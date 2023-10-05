#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "server.h"
#include "config.h"

int main(int argc, char **argv)
{   
    char *confpath = "lmqtt.conf";

    int opt;
    config_set_default();
    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
            case 'c':
                confpath = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-c conf]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (config_load(confpath) < 0)
        exit(EXIT_FAILURE);

    config_print();

    start_server(conf->insane_id);

    return 0;
}
