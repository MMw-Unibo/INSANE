#ifndef INSANE_LIST_H
#define INSANE_LIST_H

#include <stdbool.h>
#include <stddef.h>

//--------------------------------------------------------------------------------------------------
//    LIST HEAD
//--------------------------------------------------------------------------------------------------
typedef struct list_head {
    struct list_head *next;
    struct list_head *prev;
} list_head_t;

//--------------------------------------------------------------------------------------------------
#define LIST_HEAD_INIT(name)                                                                       \
    {                                                                                              \
        &(name), &(name)                                                                           \
    }

#define NSN_LIST_HEAD(name) list_head_t name = LIST_HEAD_INIT(name)

//--------------------------------------------------------------------------------------------------
static inline void list__init(list_head_t *head) {
    head->prev = head->next = head;
}

//--------------------------------------------------------------------------------------------------
static inline bool list__is_empty(const list_head_t *head) {
    return head->next == head;
}

//--------------------------------------------------------------------------------------------------
static inline void list__add(list_head_t *head, list_head_t *n) {
    head->next->prev = n;
    n->next          = head->next;
    n->prev          = head;
    head->next       = n;
}

//--------------------------------------------------------------------------------------------------
static inline void list__add_tail(list_head_t *head, list_head_t *n) {
    head->prev->next = n;
    n->prev          = head->prev;
    n->next          = head;
    head->prev       = n;
}

//--------------------------------------------------------------------------------------------------
static inline void list__del(list_head_t *elem) {
    list_head_t *prev = elem->prev;
    list_head_t *next = elem->next;

    prev->next = next;
    next->prev = prev;
}

// clang-format off
//--------------------------------------------------------------------------------------------------
#ifndef container_of
#define container_of(ptr, type, member)                                                            \
    ((type *)((char *)(ptr)-offsetof(type, member)))
#endif

//--------------------------------------------------------------------------------------------------
#define list_entry(ptr, type, member)                                                              \
    container_of(ptr, type, member)

//--------------------------------------------------------------------------------------------------
#define list_first_entry(ptr, type, member)                                                        \
    list_entry((ptr)->next, type, member)

//--------------------------------------------------------------------------------------------------
#define list_last_entry(ptr, type, member)                                                         \
    list_entry((ptr)->prev, type, member)

//--------------------------------------------------------------------------------------------------
#define list_for_each(pos, head)                                                                   \
    for (pos = (head)->next; pos != (head); pos = pos->next)

//--------------------------------------------------------------------------------------------------
#define list_for_each_safe(pos, p, head)                                                           \
    for (pos = (head)->next, p = pos->next; pos != (head); pos = p, p = pos->next)

//--------------------------------------------------------------------------------------------------
#define list_entry_is_head(pos, head, member)                                                      \
    (&pos->member == (head))

//--------------------------------------------------------------------------------------------------
#define list_next_entry(pos, member)                                                               \
    list_entry((pos)->member.next, typeof(*(pos)), member

//--------------------------------------------------------------------------------------------------
#define list_for_each_entry(pos, head, member)                                                     \
    for (pos = list_first_entry(head, typeof(*pos), member);                                       \
         !list_entry_is_head(pos, head, member);                                                   \
         pos = list_next_entry(pos, member))

// clang-format on

#endif // INSANE_LIST_H