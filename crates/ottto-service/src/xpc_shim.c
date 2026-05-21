#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <xpc/xpc.h>

typedef char *(*ottto_xpc_handler_t)(const char *request_json, pid_t peer_pid, void *context);

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

    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) {
            return;
        }

        xpc_connection_t peer_connection = (xpc_connection_t)peer;
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
            char *response_json = handler(request_json, peer_pid, context);
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
