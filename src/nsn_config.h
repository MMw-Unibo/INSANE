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
        string_t    string;
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

// Load the config file
nsn_cfg_t*
nsn_load_config(mem_arena_t *arena, string_t path);

// Get single options from the config
int 
nsn_config_get_int(nsn_cfg_t *config, string_t section, string_t key, int *out_value);
int 
nsn_config_get_string(nsn_cfg_t *cfg, string_t sec, string_t key, string_t* out_value);

// Get list of options from the config
int 
nsn_config_get_param_list(nsn_cfg_t *cfg, string_t sec, list_head_t* out_value, mem_arena_t* arena);
int
nsn_config_free_param_list(list_head_t* head, mem_arena_t* arena);

// Get single options from the list
int 
nsn_config_get_int_from_list(list_head_t* head, string_t key, int *out_value);
int 
nsn_config_get_string_from_list(list_head_t* head, string_t key, string_t* out_value);

#endif // NSN_CONFIG_H