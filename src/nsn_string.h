#ifndef NSN_STRING_H
#define NSN_STRING_H

#include "nsn_arena.h"
#include "nsn_types.h"

// --- Basic String Types ------------------------------------------------------
typedef struct string8 string8;
struct string8 
{
    u8    *data;
    usize  len;
};

// --- String Collections ------------------------------------------------------
typedef struct string8_node string8_node;
struct string8_node
{
    string8_node *next;
    string8       string;
};

typedef struct string8_list string8_list;
struct string8_list
{
    string8_node *head;
    string8_node *tail;
    usize             count;
    usize             size;
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

int   str8_contains(string8 string, string8 match);
usize str8_index_of_first(string8 string, string8 match);

string8 str8_trim_start(string8 string);
string8 str8_trim_end(string8 string);
string8 str8_trim(string8 string);

f64 f64_from_str8(string8 value);

// --- Comparisons -------------------------------------------------------------
bool str8_match(string8 string, string8 match);
bool str8_match_one_of(string8 string, string8 *matches, usize match_count);
bool str8_starts_with(string8 string, string8 prefix);
bool str8_ends_with(string8 string, string8 suffix);

// --- Constructors ------------------------------------------------------------
#define str8_fmt         "%.*s"
#define str8_arg(string) (int)(string).len, (string).data

string8 str8(char *cstr, usize len);
#define str8_cstr(cstr) str8(cstr, calc_cstr_len(cstr))
#define str8_lit(cstr)  str8(cstr, sizeof(cstr) - 1)

string8 substring8(string8 string, usize start, usize end);
#define str8_prefix(string, pre_size)   substring8(string, 0, pre_size)

string8_list str8_split(nsn_arena *arena, string8 string, string8 *delimiters, usize delimiter_count);

// --- String Collections ------------------------------------------------------
void str8_list_push(nsn_arena *arena, string8_list *list, string8 string);
void str8_list_push_node(string8_list *list, string8_node *node);


#endif // NSN_STRING_H
