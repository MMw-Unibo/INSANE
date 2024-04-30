#ifndef NSN_STRING_H
#define NSN_STRING_H

#include "nsn_memory.h"
#include "nsn_types.h"

// --- Basic String Types ------------------------------------------------------
typedef struct string string_t;
struct string
{
    u8    *data;
    usize  len;
};

// --- String Collections ------------------------------------------------------
typedef struct string_node string_node_t;
struct string_node
{
    string_node_t *next;
    string_t       string;
};

typedef struct string_list string_list_t;
struct string_list
{
    string_node_t   *head;
    string_node_t   *tail;
    usize            count;
    usize            size;
};

enum string_match_flag
{
    NsnStringMatchFlag_CaseInsensitive  = 1 << 0,
    NsnStringMatchFlag_RightSideSloppy  = 1 << 1,
    NsnStringMatchFlag_SlashInsensitive = 1 << 2,
    NsnStringMatchFlag_FindLast         = 1 << 3,
    NsnStringMatchFlag_KeepEmpties      = 1 << 4,
};

// --- Char Functions ----------------------------------------------------------
static inline bool char_is_whitespace(char c)       { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
static inline bool char_is_digit(char c)            { return c >= '0' && c <= '9'; }
static inline bool char_is_alpha_upper(char c)      { return c >= 'A' && c <= 'Z'; }
static inline bool char_is_alpha_lower(char c)      { return c >= 'a' && c <= 'z'; }
static inline bool char_is_alpha(char c)            { return char_is_alpha_upper(c) || char_is_alpha_lower(c); }
static inline bool char_is_alphanumeric(char c)     { return char_is_alpha(c) || char_is_digit(c); }
static inline bool char_is_upper(char c)            { return char_is_alpha_upper(c) || char_is_digit(c); }
static inline bool char_is_lower(char c)            { return char_is_alpha_lower(c) || char_is_digit(c); }

// --- String Functions --------------------------------------------------------

// --- Helpers -----------------------------------------------------------------
usize calc_cstr_len(char *cstr);

int   str_contains(string_t string, string_t match);
usize str_index_of_first(string_t string, string_t match);

string_t str_trim_start(string_t string);
string_t str_trim_end(string_t string);
string_t str_trim(string_t string);

f64 f64_from_str(string_t value);

// --- Comparisons -------------------------------------------------------------
bool cstr_eq(char *cstr, string_t match);
bool str_eq(string_t string, string_t match);
bool str_match_one_of(string_t string, string_t *matches, usize match_count);
bool str_starts_with(string_t string, string_t prefix);
bool str_ends_with(string_t string, string_t suffix);

// --- Constructors ------------------------------------------------------------
#define str_fmt             "%.*s"
#define str_varg(string)    (int)(string).len, (string).data

string_t make_string(const char *cstr, usize len);
#define str_cstr(cstr)     make_string(cstr, calc_cstr_len(cstr))
#define str_lit(cstr)      make_string(cstr, sizeof(cstr) - 1)
#define str_lit_compound(cstr) (string_t){ .data = (u8 *)cstr, .len = sizeof(cstr) - 1 }
#define to_cstr(string)     ((char *)(string).data)

string_t str_substring(string_t string, usize start, usize end);
#define str_prefix(string, pre_size)   str_substring(string, 0, pre_size)

string_list_t str_split(mem_arena_t *arena, string_t string, string_t *delimiters, usize delimiter_count);

// --- String Collections ------------------------------------------------------
void str_list_push(mem_arena_t *arena, string_list_t *list, string_t string);
void str_list_push_node(string_list_t *list, string_node_t *node);

#endif // NSN_STRING_H
