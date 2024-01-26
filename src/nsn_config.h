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

typedef struct nsn_config_opt nsn_config_opt;
struct nsn_config_opt
{
    string8     key;
    u32         type;
    union {
        string8     string;
        f64         number;
        bool        boolean;
    };

    list_head   list;
};


typedef struct nsn_config_section nsn_config_section;
struct nsn_config_section
{
    string8             name;
    nsn_config_section *parent;

    list_head   sub_sections;
    list_head   opts;
    list_head   list;
};

typedef struct nsn_config nsn_config;
struct nsn_config 
{
    list_head   sections;
};

nsn_config *nsn_load_config(nsn_arena *arena, string8 path);

#endif // NSN_CONFIG_H