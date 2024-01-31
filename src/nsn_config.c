#include "nsn_config.h"

nsn_config_t *
nsn_load_config(mem_arena_t *arena, string_t path)
{
    nsn_config_t *config = mem_arena_push_struct(arena, nsn_config_t);
    config->sections     = list_head_init(config->sections);

    nsn_file_t config_file = nsn_os_file_open(path, NsnFileFlag_Read);
    if (!nsn_file_valid(config_file)) {
        return NULL;
    } 
    
    string_t config_file_content = nsn_os_read_entire_file(arena, config_file);
    
    string_t delimiters[] = { str8_lit("\n"), str8_lit("\r") };
    string_list_t lines   = str8_split(arena, config_file_content, delimiters, array_count(delimiters));

    usize current_line = 0;
    nsn_config_section_t *current_section = NULL;
    for (string_node_t *node = lines.head; node; node = node->next) {
        string_t line = str8_trim(node->string);

        if (str8_starts_with(line, str8_lit("#"))) continue; 
        else if (line.len == 0)                    continue;
        else if (str8_starts_with(line, str8_lit("["))) {    // new section
            string_t delims[]             = { str8_lit("["), str8_lit("]"), str8_lit(".") };
            string_list_t sections_string = str8_split(arena, line, delims, array_count(delims));                

            // TODO(garbu): if count > 2 then error, we currently only support one level of sub-sections
            if (sections_string.count > 2) {
                log_warn("invalid section at %ld: %.*s\n", current_line, (int)line.len, line.data);
                continue;
            }

            nsn_config_section_t *new_section = mem_arena_push_struct(arena, nsn_config_section_t);
            new_section->name               = sections_string.head->string;
            new_section->opts               = list_head_init(new_section->opts);
            new_section->sub_sections       = list_head_init(new_section->sub_sections);
            list_add_tail(&config->sections, &new_section->list);

            current_section = new_section;

            if (sections_string.count == 2) {
                nsn_config_section_t *sub_section = mem_arena_push_struct(arena, nsn_config_section_t);
                sub_section->name               = sections_string.head->next->string;
                sub_section->opts               = list_head_init(sub_section->opts);
                list_add_tail(&new_section->sub_sections, &sub_section->list);
                sub_section->parent             = new_section;

                current_section = sub_section;
            }
        } else if (char_is_alpha(line.data[0]) && str8_contains(line, str8_lit("="))) { // new option
            nsn_config_opt_t *new_opt  = mem_arena_push_struct(arena, nsn_config_opt_t);
            usize index_of_first_equal = str8_index_of_first(line, str8_lit("="));
            new_opt->key               = substring8(line, 0, index_of_first_equal);
            new_opt->key               = str8_trim(new_opt->key);
            string_t value             = substring8(line, index_of_first_equal + 1, line.len);
            value = str8_trim(value);
            if (str8_starts_with(value, str8_lit("\"")) && str8_ends_with(value, str8_lit("\""))) {
                new_opt->string = substring8(value, 1, value.len - 1);
                new_opt->type   = NsnConfigOptType_String;
            } else if (char_is_alpha(value.data[0])) {
                string_t true_values[]  = { str8_lit("true"), str8_lit("yes"), str8_lit("on") };
                string_t false_values[] = { str8_lit("false"), str8_lit("no"), str8_lit("off") };

                if (str8_match_one_of(value, true_values, array_count(true_values))) {
                    new_opt->type = NsnConfigOptType_Boolean;
                    new_opt->boolean = true;
                } else if (str8_match_one_of(value, false_values, array_count(false_values))) {
                    new_opt->type = NsnConfigOptType_Boolean;
                    new_opt->boolean = false;
                } else {
                    log_error("invalid option at %ld: %.*s\n", current_line, (int)line.len, line.data);
                    continue;
                }
            } else if (char_is_digit(value.data[0])) {
                new_opt->type   = NsnConfigOptType_Number;
                new_opt->number = f64_from_str8(value);
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