/* Copyright (C) Xingxing Ke
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _KE_DLIST_H
#define _KE_DLIST_H

#include "ke/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_dlist_node {
    struct ke_dlist_node *next;
    struct ke_dlist_node *prev;
};

struct ke_dlist {
    struct ke_dlist_node *head;
    struct ke_dlist_node *tail;
    int len;
};

/* help macros */
#define KE_DLIST_T(name) struct ke_dlist (name)
#define KE_DLIST_FRONT(list) ((list)->head)
#define KE_DLIST_TAIL(list) ((list)->tail)
#define KE_DLIST_PREV(node) ((node)->prev)
#define KE_DLIST_NEXT(node) ((node)->next)
#define KE_DLIST_LEN(list) ((list)->len)

/* init a double link list */
#define KE_DLIST_INIT(list)                 \
    do {                                    \
        (list)->head = (list)->tail = NULL; \
        (list)->len = 0;                    \
    } while (0)

/* add node at front of list */
#define KE_DLIST_ADD_FRONT(list, node)      \
    do {                                    \
        (node)->next = (list)->head;        \
        (node)->prev = NULL;                \
        if ((list)->head)                   \
            (list)->head->prev = (node);    \
        (list)->head = (node);              \
        if ((list)->len++ == 0)             \
            (list)->tail = (node);          \
    } while (0)

/* add node at the back of list */
#define KE_DLIST_ADD_BACK(list, node)       \
    do {                                    \
        (node)->next = NULL;                \
        (node)->prev = (list)->tail;        \
        if ((list)->tail)                   \
            (list)->tail->next = (node);    \
        (list)->tail = (node);              \
        if ((list)->len++ == 0)             \
            (list)->head = (node);          \
    } while (0)

/* remove the head */
#define KE_DLIST_DEL_FRONT(list)                \
    do {                                        \
        if ((list)->len > 0) {                  \
            (list)->head = (list)->head->next;  \
            if ((list)->head)                   \
                (list)->head->prev = NULL;      \
            if (--(list)->len == 0)             \
                (list)->tail = NULL;            \
        }                                       \
    } while (0)

/* remove the tail */
#define KE_DLIST_DEL_BACK(list)                 \
    do {                                        \
        if ((list)->len > 0) {                  \
            (list)->tail = (list)->tail->prev;  \
            if ((list)->tail)                   \
                (list)->tail->next = NULL;      \
            if (--(list)->len == 0)             \
                (list)->head = NULL;            \
        }                                       \
    } while (0)

#define KE_DLIST_INSERT_BACK(l, old, new)   \
    do {                                    \
        (new)->next = (old)->next;          \
        if ((new)->next)                    \
            (new)->next->prev = (new);      \
        (old)->next = (new);                \
        (new)->prev = (old);                \
        if ((old) == (l)->tail)             \
            (l)->tail = (new);              \
        (l)->len++;                         \
    } while (0)

#define KE_DLIST_INSERT_FRONT(l, old, new)  \
    do {                                    \
        (new)->next = (old);                \
        if ((old)->prev)                    \
            (old)->prev->next = (new);      \
        (new)->prev = (old)->prev;          \
        (old)->prev = (new);                \
        if ((old) == (l)->head)             \
            (l)->head = (new);              \
        (l)->len++;                         \
    } while (0)

/* search node with:
 * int func(struct ke_dlist_node *node, void *data)
 * func return 1 indicate matched, else 0
 */
#define KE_DLIST_SEARCH(pp, list, func, data)                        \
    do {                                                             \
        struct ke_dlist_node *_curr_;                                \
        for (_curr_ = (list)->head; _curr_; _curr_ = _curr_->next) { \
            if (func(_curr_, (data))) {                              \
                *(pp) = _curr_;                                      \
                break;                                               \
            }                                                        \
        }                                                            \
    } while (0)

/* remove a node from list */
#define KE_DLIST_REMOVE(list, node)                  \
    do {                                             \
        struct ke_dlist_node *_prev_ = (node)->prev; \
        struct ke_dlist_node *_next_ = (node)->next; \
        if (_prev_)                                  \
            _prev_->next = _next_;                   \
        if (_next_)                                  \
            _next_->prev = _prev_;                   \
        if ((list)->head == (node))                  \
            (list)->head = _next_;                   \
        if ((list)->tail == (node))                  \
            (list)->tail = _prev_;                   \
        (list)->len--;                               \
    } while (0)

/* remove node if matched with:
 * int func(struct ke_dlist_node *node, void *data)
 * func return 1 indicate matched, else 0
 */
#define KE_DLIST_REMOVE_IF(list, func, data)          \
    do {                                              \
        struct ke_dlist_node *_target_ = NULL;        \
        KE_DLIST_SEARCH(&_target_, list, func, data); \
        if (_target_)                                 \
            KE_DLIST_REMOVE(list, _target_);          \
    } while (0)

 /* remove node if matched with:
  * int f1(struct ke_dlist_node *node, void *d1)
  * and then call f2 to clear target node data:
  * void f2(struct ke_dlist_node *node, void *d2)
  * f1 return 1 indicate matched, else 0
  */
#define KE_DLIST_REMOVE_IF2(list, f1, d1, f2, d2)    \
    do {                                             \
        struct ke_dlist_node *_target_ = NULL;       \
        KE_DLIST_SEARCH(&_target_, list, f1, d1);    \
        if (_target_) {                              \
            KE_DLIST_REMOVE(list, _target_);         \
            f2(_target_, d2);                        \
        }                                            \
    } while (0)

/* foreach the list with:
 * func(struct ke_dlist_node *node, void *data)
 */
#define KE_DLIST_FOREACH(list, func, data)               \
    do {                                                 \
        struct ke_dlist_node *_n_;                       \
        for (_n_ = (list)->head; _n_; _n_ = _n_->next) { \
            func(_n_, data);                             \
        }                                                \
    } while (0)

 /* foreach the list with:
  * int func(struct ke_dlist_node *node, void *data)
  * func return non-zero to break foreach
  */
#define KE_DLIST_FOREACH_IF(list, func, data)            \
    do {                                                 \
        struct ke_dlist_node *_n_;                       \
        for (_n_ = (list)->head; _n_; _n_ = _n_->next) { \
            if (func(_n_, data))                         \
                break;                                   \
        }                                                \
    } while (0)

#define KE_DLIST_CLEAR(list, clearfunc, data) \
    while (KE_DLIST_LEN(list) > 0) {          \
        struct ke_dlist_node *_n_;            \
        _n_ = KE_DLIST_FRONT(list);           \
        KE_DLIST_DEL_FRONT(list);             \
        clearfunc(_n_, data);                 \
    }                                        

#ifdef __cplusplus
}
#endif

#endif
