#include "nsn_config.h"

nsn_cfg_t *
nsn_load_config(mem_arena_t *arena, string_t path)
{
    nsn_cfg_t *config = mem_arena_push_struct(arena, nsn_cfg_t);
    list_init(&config->sections);
    
    nsn_file_t config_file = nsn_os_file_open(path, NsnFileFlag_Read);
    if (!nsn_file_valid(config_file)) {
        return NULL;
    } 
    
    string_t config_file_content = nsn_os_read_entire_file(arena, config_file);
    
    string_t delimiters[] = { str_lit("\n"), str_lit("\r") };
    string_list_t lines   = str_split(arena, config_file_content, delimiters, array_count(delimiters));

    usize current_line = 0;
    nsn_cfg_sec_t *current_section = NULL;
    for (string_node_t *node = lines.head; node; node = node->next) {
        string_t line = str_trim(node->string);

        if (str_starts_with(line, str_lit("#"))) continue; 
        else if (line.len == 0)                    continue;
        else if (str_starts_with(line, str_lit("["))) {    // new section
            string_t delims[]             = { str_lit("["), str_lit("]"), str_lit(".") };
            string_list_t sections_string = str_split(arena, line, delims, array_count(delims));                

            // TODO(garbu): if count > 2 then error, we currently only support one level of sub-sections
            if (sections_string.count > 2) {
                log_warn("invalid section at %ld: %.*s\n", current_line, (int)line.len, line.data);
                continue;
            }

            nsn_cfg_sec_t *new_section = mem_arena_push_struct(arena, nsn_cfg_sec_t);
            new_section->name               = sections_string.head->string;
            list_init(&new_section->opts);
            list_init(&new_section->sub_sections);       
            list_add_tail(&config->sections, &new_section->list);

            current_section = new_section;

            if (sections_string.count == 2) {
                nsn_cfg_sec_t *sub_section = mem_arena_push_struct(arena, nsn_cfg_sec_t);
                sub_section->name               = sections_string.head->next->string;
                list_init(&sub_section->opts);
                list_add_tail(&new_section->sub_sections, &sub_section->list);
                sub_section->parent             = new_section;

                current_section = sub_section;
            }
        } else if (char_is_alpha(line.data[0]) && str_contains(line, str_lit("="))) { // new option
            nsn_cfg_opt_t *new_opt  = mem_arena_push_struct(arena, nsn_cfg_opt_t);
            usize index_of_first_equal = str_index_of_first(line, str_lit("="));
            new_opt->key               = str_substring(line, 0, index_of_first_equal);
            new_opt->key               = str_trim(new_opt->key);
            string_t value             = str_substring(line, index_of_first_equal + 1, line.len);
            value = str_trim(value);
            if (str_starts_with(value, str_lit("\"")) && str_ends_with(value, str_lit("\""))) {
                new_opt->string = str_substring(value, 1, value.len - 1);
                new_opt->type   = NsnConfigOptType_String;
            } else if (char_is_alpha(value.data[0])) {
                string_t true_values[]  = { str_lit("true"), str_lit("yes"), str_lit("on") };
                string_t false_values[] = { str_lit("false"), str_lit("no"), str_lit("off") };

                if (str_match_one_of(value, true_values, array_count(true_values))) {
                    new_opt->type = NsnConfigOptType_Boolean;
                    new_opt->boolean = true;
                } else if (str_match_one_of(value, false_values, array_count(false_values))) {
                    new_opt->type = NsnConfigOptType_Boolean;
                    new_opt->boolean = false;
                } else {
                    log_error("invalid option at %ld: %.*s\n", current_line, (int)line.len, line.data);
                    continue;
                }
            } else if (char_is_digit(value.data[0])) {
                new_opt->type   = NsnConfigOptType_Number;
                new_opt->number = f64_from_str(value);
            } else {
                log_error("invalid option at %ld: %.*s\n", current_line, (int)line.len, line.data);
                continue;
            }

            list_add_tail(&current_section->opts, &new_opt->list);
        } else {
            log_error("invalid line at %ld: %.*s\n", current_line, (int)line.len, line.data);
            continue;
        }

        current_line += 1;
    }

    return config;
}

// -----------------------------------------------------------------------------
nsn_cfg_opt_t *
nsn_config_get_opt(mem_arena_t *arena, nsn_cfg_t *cfg, string_t sec, string_t key)
{
    string_t delims[]      = { str_lit(".") };
    string_list_t sections = str_split(arena, sec, delims, array_count(delims));
    string_t section_name, sub_section_name;

    nsn_cfg_opt_t *res = NULL;

    if (sections.count == 1) {
        section_name = sections.head->string;
        nsn_cfg_sec_t *section = NULL;
        list_for_each_entry(section, &cfg->sections, list) {
            if (str_eq(section->name, section_name)) {
                list_for_each_entry(res, &section->opts, list) {
                    if (str_eq(res->key, key)) {
                        return res;
                    }
                }
            }
        }
    } else if (sections.count == 2) {
        section_name     = sections.head->string;
        sub_section_name = sections.head->next->string;

        nsn_cfg_sec_t *section = NULL;
        list_for_each_entry(section, &cfg->sections, list) {
            if (str_eq(section->name, section_name)) {
                nsn_cfg_sec_t *sub_section = NULL;
                list_for_each_entry(sub_section, &section->sub_sections, list) {
                    if (str_eq(sub_section->name, sub_section_name)) {
                        list_for_each_entry(res, &sub_section->opts, list) {
                            if (str_eq(res->key, key)) {
                                return res;
                            }
                        }
                    }
                }
            }
        }
    }

    return NULL;
}

list_head_t *
nsn_config_get_opt_list(mem_arena_t *arena, nsn_cfg_t *cfg, string_t sec) {
    string_t delims[]      = { str_lit(".") };
    string_list_t sections = str_split(arena, sec, delims, array_count(delims));
    string_t section_name, sub_section_name;

    if (sections.count == 1) {
        section_name = sections.head->string;
        nsn_cfg_sec_t *section = NULL;
        list_for_each_entry(section, &cfg->sections, list) {
            if (str_eq(section->name, section_name)) {
                return &section->opts;
            }
        }
    } else if (sections.count == 2) {
        section_name     = sections.head->string;
        sub_section_name = sections.head->next->string;

        nsn_cfg_sec_t *section = NULL;
        list_for_each_entry(section, &cfg->sections, list) {
            if (str_eq(section->name, section_name)) {
                nsn_cfg_sec_t *sub_section = NULL;
                list_for_each_entry(sub_section, &section->sub_sections, list) {
                    if (str_eq(sub_section->name, sub_section_name)) {
                        return &sub_section->opts;
                    }
                }
            }
        }
    }

    return NULL;    
}

int 
nsn_config_get_int(nsn_cfg_t *cfg, string_t sec, string_t key, int *out_value)
{
    temp_mem_arena_t scratch = nsn_thread_scratch_begin(NULL, 0);

    nsn_cfg_opt_t *opt = nsn_config_get_opt(scratch.arena, cfg, sec, key);
    if (!opt) {
        return -1;
    }

    if (opt->type != NsnConfigOptType_Number) {
        return -1;
    }

    log_debug("found option %.*s.%.*s = %d\n", (int)sec.len, sec.data, (int)key.len, key.data, (int)opt->number);

    *out_value = (int)opt->number;
    nsn_thread_scratch_end(scratch);
    return 0;
}

int 
nsn_config_get_string(nsn_cfg_t *cfg, string_t sec, string_t key, string_t* out_value)
{
    temp_mem_arena_t scratch = nsn_thread_scratch_begin(NULL, 0);

    nsn_cfg_opt_t *opt = nsn_config_get_opt(scratch.arena, cfg, sec, key);
    if (!opt) {
        log_warn("invalid option: %s\n", to_cstr(key));
        return -1;
    }

    if (opt->type != NsnConfigOptType_String) {
        log_warn("invalid option type\n");
        return -1;
    }

    log_debug("found option %.*s.%.*s = %.*s\n", (int)sec.len, sec.data, (int)key.len, key.data, (int)opt->string.len, opt->string.data);

    memcpy(out_value->data, opt->string.data, opt->string.len);
    out_value->len = opt->string.len;

    nsn_thread_scratch_end(scratch);
    return 0;
}

int 
nsn_config_get_param_list(nsn_cfg_t *cfg, string_t sec, list_head_t* out_value, mem_arena_t* arena)
{
    temp_mem_arena_t scratch = nsn_thread_scratch_begin(NULL, 0);

    list_head_t* opt_list = nsn_config_get_opt_list(scratch.arena, cfg, sec);
    if (!opt_list) {
        log_warn("invalid option: %s\n", to_cstr(sec));
        return -1;
    }

    // Copy each element to the output list
    nsn_cfg_opt_t *opt = NULL;
    list_for_each_entry(opt, opt_list, list) {
        nsn_cfg_opt_t *new_opt = mem_arena_push_struct(arena, nsn_cfg_opt_t);
        memcpy(new_opt, opt, sizeof(nsn_cfg_opt_t));
        list_add_tail(out_value, &new_opt->list);
    }

    return 0;
}

int
nsn_config_free_param_list(list_head_t* head, mem_arena_t* arena)
{
    list_head_t *element, *tmp;
    list_for_each_safe(element, tmp, head) {
        mem_arena_pop(arena, sizeof(nsn_cfg_opt_t));
        list_del(element);
    }

    if (!list_empty(head)) {
        log_warn("failed to free all list elements\n");
        return -1;
    }

    return 0;
}

// Get all the options with a certain name in all the subsections of a given section
int 
nsn_config_get_string_list_from_subsections(mem_arena_t* arena, nsn_cfg_t *cfg, string_t sec, string_t key, list_head_t* out_value) {
    temp_mem_arena_t scratch = nsn_thread_scratch_begin(NULL, 0);
    nsn_cfg_sec_t *section = NULL;
    nsn_cfg_sec_t *sub_section = NULL;
    u16 sec_count = 0;
    char sec_name[256];
    
    // For each section we have in the config
    list_for_each_entry(section, &cfg->sections, list) {
        if (str_eq(sec, section->name) && section->list.next != NULL) {
            bzero(sec_name, 256);
            sub_section = list_first_entry(&section->sub_sections, nsn_cfg_sec_t, list);           
            sprintf(sec_name, "%.*s.%.*s", (int)section->name.len, section->name.data, 
                                            (int)sub_section->name.len, sub_section->name.data);
            nsn_cfg_opt_t *cur_opt = nsn_config_get_opt(scratch.arena, cfg, str_cstr(sec_name), key);
            if (!cur_opt) {
                log_warn("invalid option: %s for section %s\n", to_cstr(key), sec_name);
                continue;
            }
            if (cur_opt->type != NsnConfigOptType_String) {
               log_warn("invalid option type\n");
               continue;
            }

            // Allocate a new option from the caller's arena
            nsn_cfg_opt_t *new_opt = mem_arena_push_struct(arena, nsn_cfg_opt_t);
            memcpy(new_opt, cur_opt, sizeof(nsn_cfg_opt_t));
            list_add_tail(out_value, &new_opt->list);
        
            sec_count++;
        }
    }

    nsn_thread_scratch_end(scratch);
    return sec_count;
}

int 
nsn_config_get_int_from_list(list_head_t* head, string_t key, int *out_value)
{  
    if(list_empty(head)) {
        log_warn("empty list\n");
        return -1;
    }

    temp_mem_arena_t scratch = nsn_thread_scratch_begin(NULL, 0);

    nsn_cfg_opt_t *opt = NULL;
    list_for_each_entry(opt, head, list) {
        if (str_eq(opt->key, key)) {
            break;
        }
    }

    if (!opt) {
        log_warn("invalid option: %s\n", to_cstr(key));
        return -1;
    }

    if (opt->type != NsnConfigOptType_Number) {
        return -1;
    }

    *out_value = (int)opt->number;
    nsn_thread_scratch_end(scratch);
    return 0;
}

int 
nsn_config_get_string_from_list(list_head_t* head, string_t key, string_t* out_value) {
    
    if(list_empty(head)) {
        log_warn("empty list\n");
        return -1;
    }

    temp_mem_arena_t scratch = nsn_thread_scratch_begin(NULL, 0);

    nsn_cfg_opt_t *opt = NULL;
    list_for_each_entry(opt, head, list) {
        if (str_eq(opt->key, key)) {
            break;
        }
    }
   
    if (!opt) {
        log_warn("invalid option: %s\n", to_cstr(key));
        return -1;
    }

    log_debug("found option %.*s = %.*s\n", (int)key.len, key.data, (int)opt->string.len, opt->string.data);

    if (opt->type != NsnConfigOptType_String) {
        log_warn("invalid option type\n");
        return -1;
    }

    memcpy(out_value->data, opt->string.data, opt->string.len);
    out_value->len = opt->string.len;

    nsn_thread_scratch_end(scratch);
    return 0;
}
