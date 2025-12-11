#include "rest.h"
#include <cJSON.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int
send_json(struct mg_connection *conn, cJSON *json_obj)
{
    char *json_str = cJSON_PrintUnformatted(json_obj);
    size_t json_str_len = strlen(json_str);

    /* Send HTTP message header (+1 for \n) */
    mg_send_http_ok(conn, "application/json; charset=utf-8", json_str_len + 1);

    /* Send HTTP message content */
    mg_write(conn, json_str, json_str_len);

    /* Add a newline. This is not required, but the result is more
    * human-readable in a debugger. */
    mg_write(conn, "\n", 1);

    /* Free string allocated by cJSON_Print* */
    cJSON_free(json_str);

    return (int)json_str_len;
}

// -- Request Handlers

//Handler for the POST /change/qos
static int
rest_change_qos_handler(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *ri = mg_get_request_info(conn);

    (void)cbdata;

    /* According to method */
    if (0 == strcmp(ri->request_method, "POST")) {
        return rest_post_change_qos(conn, "change", "qos");
    }
    /* this is not a POST request */
    mg_send_http_error(
        conn, 405, "Only GET, PUT, POST, DELETE and PATCH method supported");
    return 405;

}

// Handler for the GET /plugins/streams
static int
rest_plugins_streams_count_handler(struct mg_connection *conn, void *cbdata)
{
    const struct mg_request_info *ri = mg_get_request_info(conn);

    (void)cbdata;

    /* According to method */
    if (0 == strcmp(ri->request_method, "GET")) {
        return rest_get_plugins_streams_count(conn, "plugins", "streams");
    }
    /* this is not a GET request */
    mg_send_http_error(
        conn, 405, "Only GET, PUT, POST, DELETE and PATCH method supported");
    return 405;
}

// Function to register all the endpoints
int rest_register_endpoints(struct mg_context *ctx) {
    if (!ctx) return 0;
    mg_set_request_handler(ctx, PLUGIN_STREAMS_URI, rest_plugins_streams_count_handler, 0);
    mg_set_request_handler(ctx, CHANGE_QOS_URI, rest_change_qos_handler, 0);
    return 1;
}
