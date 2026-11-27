#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

typedef char *(*ottto_xpc_handler_t)(const char *request_json, pid_t peer_pid, uid_t peer_euid,
                                     void *context);
typedef char *(*ottto_signer_handler_t)(const char *request_json, uint64_t connection_id,
                                        void *context);
typedef void (*ottto_signer_closed_t)(uint64_t connection_id, void *context);

static void ottto_send_error_reply(xpc_object_t event, xpc_connection_t peer, const char *message) {
    xpc_object_t reply = xpc_dictionary_create_reply(event);
    if (reply == NULL) {
        reply = xpc_dictionary_create(NULL, NULL, 0);
    }
    xpc_dictionary_set_string(reply, "error", message);
    xpc_connection_send_message(peer, reply);
    xpc_release(reply);
}

int ottto_xpc_serve(const char *mach_service, ottto_xpc_handler_t handler, void *context) {
    if (mach_service == NULL || handler == NULL) {
        return 2;
    }

    dispatch_queue_t queue = dispatch_queue_create("net.ottto.service.xpc", DISPATCH_QUEUE_CONCURRENT);
    xpc_connection_t listener = xpc_connection_create_mach_service(
        mach_service,
        queue,
        XPC_CONNECTION_MACH_SERVICE_LISTENER
    );
    if (listener == NULL) {
        return 1;
    }

    uid_t daemon_euid = geteuid();

    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) {
            return;
        }

        xpc_connection_t peer_connection = (xpc_connection_t)peer;

        // Connection-level peer gate: a Mach service accepts connections from
        // any process that can look up the service name, with no built-in
        // credential check. Reject (cancel without resuming) any peer whose
        // effective uid differs from the daemon's, so the Mach service is at
        // least as restrictive as the 0600 unix socket. xpc_connection_get_euid
        // reports the peer's EUID at connection time and is a supported API.
        uid_t peer_euid = xpc_connection_get_euid(peer_connection);
        if (peer_euid != daemon_euid) {
            xpc_connection_cancel(peer_connection);
            return;
        }

        xpc_connection_set_event_handler(peer_connection, ^(xpc_object_t event) {
            if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) {
                return;
            }

            const char *request_json = xpc_dictionary_get_string(event, "request");
            if (request_json == NULL) {
                ottto_send_error_reply(event, peer_connection, "missing request");
                return;
            }

            pid_t peer_pid = xpc_connection_get_pid(peer_connection);
            // Re-read the EUID alongside the PID and thread it into the Rust
            // handler so the control layer can re-assert the uid match as
            // defense in depth even though the listener already gated on it.
            uid_t message_peer_euid = xpc_connection_get_euid(peer_connection);
            char *response_json =
                handler(request_json, peer_pid, message_peer_euid, context);
            if (response_json == NULL) {
                ottto_send_error_reply(event, peer_connection, "request handler failed");
                return;
            }

            xpc_object_t reply = xpc_dictionary_create_reply(event);
            if (reply == NULL) {
                reply = xpc_dictionary_create(NULL, NULL, 0);
            }
            xpc_dictionary_set_string(reply, "response", response_json);
            xpc_connection_send_message(peer_connection, reply);
            xpc_release(reply);
            free(response_json);
        });

        xpc_connection_resume(peer_connection);
    });

    xpc_connection_resume(listener);
    dispatch_main();
    return 0;
}

// The Mac app's signer channel: a second Mach listener, separate from the
// control listener above, that only the release Ottto app can talk to.
//
// Every peer must run as this user and satisfy `peer_requirement` (the
// release app's identifier and Developer ID team). libxpc then checks that
// requirement on every message it delivers from the peer; a message from any
// other code is never handed to `handler`, and the connection fails instead.
// Each accepted connection gets an id, so the service can tie queued work and
// prepared requests to the one connection that took them; `closed` runs when
// that connection errors or is cancelled.
//
// It does not call dispatch_main(): the control listener's dispatch_main()
// serves this queue too. Returns 0 when the listener is resumed and nonzero
// when it could not be set up, and never touches the control listener, so a
// failure here leaves the control channel serving.
int ottto_xpc_start_signer(const char *mach_service, const char *peer_requirement,
                           ottto_signer_handler_t handler, ottto_signer_closed_t closed,
                           void *context) {
    if (mach_service == NULL || peer_requirement == NULL || handler == NULL || closed == NULL) {
        return 2;
    }
    if (__builtin_available(macOS 12.0, *)) {
        // xpc_connection_set_peer_code_signing_requirement exists.
    } else {
        return 3;
    }

    // Owned for the life of the process, like the listener.
    char *requirement = strdup(peer_requirement);
    if (requirement == NULL) {
        return 4;
    }

    dispatch_queue_t queue =
        dispatch_queue_create("net.ottto.service.signer", DISPATCH_QUEUE_CONCURRENT);
    if (queue == NULL) {
        free(requirement);
        return 5;
    }
    xpc_connection_t listener = xpc_connection_create_mach_service(
        mach_service,
        queue,
        XPC_CONNECTION_MACH_SERVICE_LISTENER
    );
    if (listener == NULL) {
        free(requirement);
        return 1;
    }

    uid_t daemon_euid = geteuid();
    static _Atomic uint64_t next_connection_id = 1;

    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) {
            return;
        }
        xpc_connection_t peer_connection = (xpc_connection_t)peer;

        if (xpc_connection_get_euid(peer_connection) != daemon_euid) {
            xpc_connection_cancel(peer_connection);
            return;
        }
        int rc = 1;
        if (__builtin_available(macOS 12.0, *)) {
            rc = xpc_connection_set_peer_code_signing_requirement(peer_connection, requirement);
        }
        if (rc != 0) {
            // Never resumed: nothing from this peer reaches the service.
            xpc_connection_cancel(peer_connection);
            return;
        }

        uint64_t connection_id = atomic_fetch_add(&next_connection_id, 1);
        xpc_connection_set_event_handler(peer_connection, ^(xpc_object_t event) {
            if (xpc_get_type(event) == XPC_TYPE_ERROR) {
                // Interrupted, invalid or a failed code-signing check: the
                // connection and everything it took are gone.
                closed(connection_id, context);
                xpc_connection_cancel(peer_connection);
                return;
            }
            if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) {
                return;
            }

            const char *request_json = xpc_dictionary_get_string(event, "request");
            if (request_json == NULL) {
                ottto_send_error_reply(event, peer_connection, "missing request");
                return;
            }
            char *response_json = handler(request_json, connection_id, context);
            if (response_json == NULL) {
                ottto_send_error_reply(event, peer_connection, "request handler failed");
                return;
            }

            xpc_object_t reply = xpc_dictionary_create_reply(event);
            if (reply == NULL) {
                reply = xpc_dictionary_create(NULL, NULL, 0);
            }
            xpc_dictionary_set_string(reply, "response", response_json);
            xpc_connection_send_message(peer_connection, reply);
            xpc_release(reply);
            free(response_json);
        });

        xpc_connection_resume(peer_connection);
    });

    xpc_connection_resume(listener);
    return 0;
}
