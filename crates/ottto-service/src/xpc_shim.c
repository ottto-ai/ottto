#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

typedef char *(*ottto_xpc_handler_t)(const char *request_json, pid_t peer_pid, uid_t peer_euid,
                                     void *context);

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
