#ifndef LUNAR_MQTT_CONFIG_H
#define LUNAR_MQTT_CONFIG_H

#define VERSION                "0.0.1"
// #define DEFAULT_LOG_LEVEL      DEBUG
// #define 
#define DEFAULT_INSANE_ID       1

struct config 
{
    const char *version;
    int run;
    int log_level;
    int insane_id;
};

extern struct config *conf;

void config_set_default();
void config_print();
int config_load(const char *);

#endif // LUNAR_MQTT_CONFIG_H