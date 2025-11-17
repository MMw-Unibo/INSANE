#ifndef LUNAR_H
#define LUNAR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "uthash.h"

//#include "../../lib/proto_trp.h"

#include <nsn/nsn.h>

#define MAX_BUF_SIZE 1440

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

static nsn_stream_t stream;

struct topic {
    char        *name;
    nsn_sink_t   sink;
    nsn_source_t source;
    UT_hash_handle hh;
};

static struct topic *topics = NULL;

int lunar_init() {

    if (nsn_init() < 0) {
        fprintf(stderr, "nsn_init() failed\n");
        return -1;
    }

    nsn_options_t opts = {
        .datapath = NSN_QOS_DATAPATH_DEFAULT, .consumption = NSN_QOS_CONSUMPTION_POLL, .determinism = NSN_QOS_DETERMINISM_DEFAULT,
        .reliability = NSN_QOS_RELIABILITY_UNRELIABLE};

    stream = nsn_create_stream(opts);
    if (stream == NSN_INVALID_STREAM_HANDLE) {
        fprintf(stderr, "nsn_create_stream() failed\n");
        return -2;
    }

    return 0;
}

static struct topic *add_new_topic(const char *topic, const char *role) {
    uint32_t id = one_at_a_time_hash(topic, strlen(topic));
    struct topic *new_topic = malloc(sizeof(struct topic));
    size_t        len       = strlen(topic);
    new_topic->name         = malloc(len);
    strncpy(new_topic->name, topic, len);

    if(strcmp(role, "pub") == 0){
        new_topic->source = nsn_create_source(stream, id);
    }
    else if(strcmp(role, "sub") == 0){
        new_topic->sink   = nsn_create_sink(stream, id, NULL);
    }
    else{
        new_topic->source = nsn_create_source(stream, id);
        new_topic->sink   = nsn_create_sink(stream, id, NULL);
    }
    
    HASH_ADD_STR(topics, name, new_topic);

    return new_topic;
}

int _lunar_pub(lunar_data_cb datacb, void *args, struct topic *t) {
    char buffer[MAX_BUF_SIZE];   // temporary buffer
    size_t size = datacb(buffer, args); 
    nsn_buffer_t *buf = nsn_get_buffer(size, NSN_BLOCKING);
    buf->len = datacb(buf->data, args);
    nsn_emit_data(t->source, buf);
    return 0;
}

int lunar_pub(const char *role, const char *topic, lunar_data_cb datacb, void *args) {

    struct topic *t;
    HASH_FIND_STR(topics, topic, t);

    if (!t){
        t = add_new_topic(topic, role);
    }
    _lunar_pub(datacb, args, t);

    return 0;
}

int _lunar_sub(lunar_data_cb datacb, void *args, struct topic *t) {
    nsn_buffer_t *buf = nsn_consume_data(t->sink, NSN_BLOCKING);
    datacb(buf->data, args);
    nsn_release_data(buf);

    return 0;
}

int lunar_sub(const char *role, const char *topic, lunar_data_cb datacb, void *args) {
    struct topic *t;
    HASH_FIND_STR(topics, topic, t);

    if (!t) {
        t = add_new_topic(topic, role);
    }

    _lunar_sub(datacb, args, t);

    return 0;
}

int lunar_destroy_sink(const char *topic) {
    struct topic *t;
    HASH_FIND_STR(topics, topic, t);
    if(t && t->sink != NSN_INVALID_SNK){
        nsn_destroy_sink(t->sink);
    }
    return 0;
}

int lunar_destroy_source(const char *topic) {
    struct topic *t;
    HASH_FIND_STR(topics, topic, t);
    if(t && t->source != NSN_INVALID_SRC){
        nsn_destroy_source(t->source);
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

    /* Destroy NSN stream if open */
    nsn_destroy_stream(stream);

    nsn_close();
    return 0;
}

#endif // LUNAR_H