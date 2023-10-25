#ifndef LUNAR_H
#define LUNAR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "uthash.h"

#include "../../lib/proto_trp.h"

#include <insane/insane.h>

typedef size_t (*lunar_data_cb)(void *data, void *args);

static inline uint32_t one_at_a_time_hash(const char *key, size_t length) {
    size_t   i    = 0;
    uint32_t hash = 0;
    while (i != length) {
        hash += key[i++];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

#define TRANSPORT_UDP 0x0
#define TRANSPORT_TRP 0x1

static nsn_stream_t stream;
static int          transport = TRANSPORT_UDP;

struct topic {
    char        *name;
    nsn_sink_t   sink;
    nsn_source_t source;

    nsn_rel_sink_t   *rel_sink;
    nsn_rel_source_t *rel_source;

    UT_hash_handle hh;
};

static struct topic *topics = NULL;

int lunar_init(const char *trsp) {

    if (strcmp(trsp, "udp") == 0)
        transport = TRANSPORT_UDP;
    else if (strcmp(trsp, "trp") == 0)
        transport = TRANSPORT_TRP;
    else {
        printf("Unknown transport type '%s', use 'udp' or 'trp'\n", trsp);
    }

    nsn_init();

    nsn_options_t opts = {
        .datapath = datapath_fast, .consumption = consumption_high, .determinism = determinism_no};

    stream = nsn_create_stream(&opts);
}

static struct topic *add_new_topic(const char *topic, int kind) {
    uint32_t id = one_at_a_time_hash(topic, strlen(topic));

    struct topic *new_topic = malloc(sizeof(struct topic));
    size_t        len       = strlen(topic);
    new_topic->name         = malloc(len);
    strncpy(new_topic->name, topic, len);

    switch (kind) {
    case TRANSPORT_UDP:
        new_topic->source = nsn_create_source(&stream, id);
        new_topic->sink   = nsn_create_sink(&stream, id, NULL);
        break;

    case TRANSPORT_TRP:
        new_topic->rel_source = nsn_create_rel_source(&stream, id);
        new_topic->rel_sink   = nsn_create_rel_sink(&stream, id);

    default:
        break;
    }

    HASH_ADD_STR(topics, name, new_topic);

    return new_topic;
}

int _lunar_pub_trp(const char *topic, lunar_data_cb datacb, void *args, struct topic *t) {
    nsn_buffer_t buf = nsn_get_buffer_reliable(t->rel_source, 0, NSN_BLOCKING);
    buf.len          = datacb(buf.data, args);
    nsn_emit_data_reliable(t->rel_source, buf);

    return 0;
}

int _lunar_pub_udp(const char *topic, lunar_data_cb datacb, void *args, struct topic *t) {
    nsn_buffer_t buf = nsn_get_buffer(t->source, 0, NSN_BLOCKING);
    buf.len          = datacb(buf.data, args);
    nsn_emit_data(t->source, &buf);

    return 0;
}

int lunar_pub(const char *topic, lunar_data_cb datacb, void *args) {

    struct topic *t;
    HASH_FIND_STR(topics, topic, t);

    if (!t)
        t = add_new_topic(topic, transport);

    switch (transport) {
    case TRANSPORT_UDP:
        _lunar_pub_udp(topic, datacb, args, t);
        break;
    case TRANSPORT_TRP:
        _lunar_pub_trp(topic, datacb, args, t);
        break;
    }

    return 0;
}

int _lunar_sub_trp(const char *topic, lunar_data_cb datacb, void *args, struct topic *t) {
    nsn_buffer_t buf = nsn_consume_data_reliable(t->rel_sink, NSN_BLOCKING);
    datacb(buf.data, args);
    nsn_release_data(t->rel_sink->sink, &buf);

    return 0;
}

int _lunar_sub_udp(const char *topic, lunar_data_cb datacb, void *args, struct topic *t) {
    nsn_buffer_t buf = nsn_consume_data(t->sink, NSN_BLOCKING);
    datacb(buf.data, args);
    nsn_release_data(t->sink, &buf);

    return 0;
}

int lunar_sub(const char *topic, lunar_data_cb datacb, void *args) {
    struct topic *t;
    HASH_FIND_STR(topics, topic, t);

    if (!t) {
        t = add_new_topic(topic, transport);
    }

    switch (transport) {
    case TRANSPORT_UDP:
        _lunar_sub_udp(topic, datacb, args, t);
        break;
    case TRANSPORT_TRP:
        _lunar_sub_trp(topic, datacb, args, t);
        break;
    }

    return 0;
}

int lunar_close() {
    struct topic *t, *tmp;
    HASH_ITER(hh, topics, t, tmp) {
        HASH_DEL(topics, t);
        free(t->name);
        free(t);
    }

    nsn_close();
}

#endif // LUNAR_H