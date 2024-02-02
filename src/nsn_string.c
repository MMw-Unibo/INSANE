#include "nsn_string.h"

// --- Helpers -----------------------------------------------------------------
usize 
calc_cstr_len(char *cstr)
{
    usize len = 0;
    while (*cstr++) len++;
    return len;
}

int 
str_contains(string_t string, string_t match)
{
    if (match.len > string.len) return -1;

    int occurence = 0;
    for (usize i = 0; i < string.len; i++) {
        if (string.data[i] == match.data[0]) {
            bool match_found = true;
            for (usize j = 0; j < match.len; j++) {
                if (string.data[i + j] != match.data[j]) {
                    match_found = false;
                    break;
                }
            }

            if (match_found) {
                occurence += 1;
                i += match.len - 1;
            }
        }
    }

    return occurence;
}

usize 
str_index_of_first(string_t string, string_t match)
{
    if (match.len > string.len) return -1;

    for (usize i = 0; i < string.len; i++) {
        if (string.data[i] == match.data[0]) {
            bool match_found = true;
            for (usize j = 0; j < match.len; j++) {
                if (string.data[i + j] != match.data[j]) {
                    match_found = false;
                    break;
                }
            }

            if (match_found) return i;
        }
    }

    return -1;
}

string_t 
str_trim_start(string_t string)
{
    usize offset = 0;
    while (char_is_whitespace(string.data[offset])) offset++;
    return str_substring(string, offset, string.len);
}

string_t 
str_trim_end(string_t string)
{
    usize offset = string.len - 1;
    while (char_is_whitespace(string.data[offset])) offset--;
    return str_substring(string, 0, offset + 1);
}

string_t 
str_trim(string_t string)
{
    return str_trim_start(str_trim_end(string));
}

// --- Numbers
f64 
f64_from_str(string_t value)
{
    char str[64] = {0};
    usize len    = value.len;
    if (len > sizeof(str) - 1) len = sizeof(str) - 1;
    memory_copy(str, value.data, len);
    str[len] = '\0';
    return atof(str);
}

// --- Constructors ------------------------------------------------------------
string_t 
make_string(char *cstr, usize len)
{
    string_t str = {0};
    str.data = (u8 *)cstr;
    str.len  = len;
    return str;
}

string_t 
str_substring(string_t string, usize start, usize end)
{
    usize min = start;
    usize max = end;
    if (min > string.len) min = string.len;
    if (max > string.len) max = string.len;
    if (min > max) {
        usize tmp = min;
        min = max;
        max = tmp;
    }

    string_t sub = {0};
    sub.data = string.data + min;
    sub.len  = max - min;
    return sub;
}

string_list_t 
str_split(mem_arena_t *arena, string_t string, string_t *delimiters, usize delimiter_count)
{
    string_list_t list  = {0};
    string_node_t *node = NULL;
    string_t sub        = {0};
    usize start            = 0;
    usize end              = 0;

    for (usize i = 0; i < string.len; i++) {
        for (usize j = 0; j < delimiter_count; j++) {
            if (string.data[i] == delimiters[j].data[0]) {
                end = i;
                if (start != end) {
                    sub          = str_substring(string, start, end);
                    node         = mem_arena_push_struct(arena, string_node_t);
                    node->string = sub;
                    str_list_push_node(&list, node);
                }
                
                start = i + 1;
            }
        }
    }

    if (start < string.len) {
        sub          = str_substring(string, start, string.len);
        node         = mem_arena_push_struct(arena, string_node_t);
        node->string = sub;
        str_list_push_node(&list, node);
    }

    return list;
}


// --- Comparisons -------------------------------------------------------------
bool
str_eq(string_t string, string_t match)
{
    if (string.len != match.len) return false;
    for (usize i = 0; i < string.len; i++) {
        if (string.data[i] != match.data[i]) return false;
    }

    return true;
}

bool 
str_match_one_of(string_t string, string_t *matches, usize match_count)
{
    for (usize i = 0; i < match_count; i++) {
        if (str_eq(string, matches[i])) return true;
    }

    return false;
}


bool 
str_starts_with(string_t string, string_t prefix)
{
    if (prefix.len > string.len) return false;
    for (usize i = 0; i < prefix.len; i++) {
        if (string.data[i] != prefix.data[i]) return false;
    }

    return true;
}

bool 
str_ends_with(string_t string, string_t suffix)
{
    if (suffix.len > string.len) return false;
    for (usize i = 0; i < suffix.len; i++) {
        if (string.data[string.len - suffix.len + i] != suffix.data[i]) return false;
    }

    return true;
}

// --- String Collections ------------------------------------------------------

void
str_list_push_node(string_list_t *list, string_node_t *node)
{
    nsn_list_push(list->head, list->tail, node);
    list->count += 1;
    list->size  += node->string.len;
}

void 
str_list_push(mem_arena_t *arena, string_list_t *list, string_t string)
{
    string_node_t *node = mem_arena_push_struct(arena, string_node_t);
    node->string = string;
    str_list_push_node(list, node);
}