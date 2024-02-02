#ifndef NSN_CONFIG_H
#define NSN_CONFIG_H

#include "nsn_types.h"
#include "nsn_string.h"
#include "nsn_os.h"

enum nsn_config_opt_type {
    NsnConfigOptType_String,
    NsnConfigOptType_Number,
    NsnConfigOptType_Boolean,
};

typedef struct nsn_cfg_opt nsn_cfg_opt_t;
struct nsn_cfg_opt
{
    string_t     key;
    u32         type;
    union {
        string_t     string;
        f64         number;
        bool        boolean;
    };

    list_head_t   list;
};


typedef struct nsn_cfg_sec nsn_cfg_sec_t;
struct nsn_cfg_sec
{
    string_t                 name;
    nsn_cfg_sec_t    *parent;

    list_head_t   sub_sections;
    list_head_t   opts;
    list_head_t   list;
};

typedef struct nsn_cfg nsn_cfg_t;
struct nsn_cfg
{
    list_head_t  sections;
};

nsn_cfg_t *nsn_load_config(mem_arena_t *arena, string_t path);

int nsn_config_get_int(nsn_cfg_t *config, string_t section, string_t key, int *out_value);

#endif // NSN_CONFIG_H