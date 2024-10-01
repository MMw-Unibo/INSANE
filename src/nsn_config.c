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
        return -1;
    }

    if (opt->type != NsnConfigOptType_String) {
        return -1;
    }

    log_debug("found option %.*s.%.*s = %.*s\n", (int)sec.len, sec.data, (int)key.len, key.data, (int)opt->string.len, opt->string.data);

    *out_value = opt->string;
    nsn_thread_scratch_end(scratch);
    return 0;
}