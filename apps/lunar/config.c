#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static struct config config;
struct config *conf;

// struct llevel {
//     const char *lname;
//     int log_level;
// }

// static const struct llevel lmap[] = {
//     { "DEBUG", DEBUG }
// }

static void 
add_config_value(const char *key, const char *val)
{
    size_t klen = strlen(key);
    size_t vlen = strlen(val);

    if (strncmp("insane_id", key, klen) == 0) {
        config.insane_id = atoi(val);
    };
}

static inline void
strip_spaces(char **str)
{
    if (!*str) return;
    while (isspace(**str) && **str) 
        ++(*str);
}

static inline void
unpack_bytes(char **str, char *dst)
{
    if (!str || !dst) return;
    while (!isspace(**str) && **str)
        *dst++ = *(*str)++;
}

int 
config_load(const char *path)
{
    assert(path);
    FILE *fd = fopen(path, "r");
    if (!fd) {
        fprintf(stderr, "cannot open config file '%s': %s\n", path,
                strerror(errno));
        return -1;
    }

    char line[0xff], key[0xff], val[0xff];
    int nb_lines = 0;
    char *pline, *pkey, *pval;
    while (fgets(line, 0xff, fd) != NULL) {
        memset(key, 0x00, sizeof(key));
        memset(val, 0x00, sizeof(val));

        nb_lines++;

        // Remove comments
        if (line[0] == '#') continue;

        // Remove blank lines
        pline = line;
        strip_spaces(&pline);
        if (*pline == '\0') continue;

        pkey = key;
        unpack_bytes(&pline, pkey);

        strip_spaces(&pline);
        if (line[0] == '\0') {
            continue;
        }

        pval = val;
        unpack_bytes(&pline, pval);

        add_config_value(key, val);
    }

    return 1;
}

void 
config_set_default()
{
    conf = &config;

    conf->version = VERSION;
    conf->insane_id = DEFAULT_INSANE_ID;
    conf->run = 0;
}

void
config_print()
{
    printf("Lunar MQTT v%s is starting\n", config.version);
    printf("Network settings:\n");
    printf("\tINSANE ID: %d\n", config.insane_id);
}