#ifndef REST_H
#define REST_H

// External dependencies
#include <cJSON.h>
#include <civetweb.h>

#define PLUGIN_STREAMS_URI "/plugins/streams"
#define CHANGE_QOS_URI "/change/qos"

int rest_register_endpoints(struct mg_context *ctx);

// Functions defined in nsnd.c and used by rest.c
int rest_get_plugins_streams_count(struct mg_connection *conn, const char *p1, const char *p2);
int rest_post_change_qos(struct mg_connection *conn, const char *p1, const char *p2);

// Used by nsnd.c
int send_json(struct mg_connection *conn, cJSON *json_obj);

#endif // REST_H