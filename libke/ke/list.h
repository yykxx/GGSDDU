/* Copyright (C) 2012 Xingxing Ke
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

#ifndef _KE_LIST_H
#define _KE_LIST_H

#include "ke/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_list_node {
    struct ke_list_node *next;
};

struct ke_list {
    struct ke_list_node *head;
    int len;
};

/* help macros */
#define KE_LIST_T(name)          struct ke_list (name)
#define KE_LIST_FRONT(list)      ((list)->head)
#define KE_LIST_LEN(list)        ((list)->len)
#define KE_LIST_NEXT(node)       ((node)->next)

/* init single link list */
#define KE_LIST_INIT(list)              \
    do {                                \
        (list)->head = NULL;            \
        (list)->len = 0;                \
    } while (0)

/* add a node at the front of list */
#define KE_LIST_ADD_FRONT(list, node)   \
    do {                                \
        struct ke_list_node **_head_;   \
        _head_ = &(list)->head;         \
        (node)->next = *_head_;         \
        *_head_ = (node);               \
        (list)->len++;                  \
    } while (0)

/* delete the head node */
#define KE_LIST_DEL_FRONT(list)                 \
    do {                                        \
        if ((list)->len > 0) {                  \
            (list)->head = (list)->head->next;  \
            (list)->len--;                      \
        }                                       \
    } while (0)

/* remove a node from list
 * O(n)
 */
#define KE_LIST_REMOVE(list, node)                                  \
    do {                                                            \
        struct ke_list_node **_pp_;                                 \
        for (_pp_ = &(list)->head; *_pp_; _pp_ = &(*_pp_)->next) {  \
            if ((node) == *_pp_) {                                  \
                *_pp_ = (node)->next;                               \
                (list)->len--;                                      \
                break;                                              \
            }                                                       \
        }                                                           \
    } while (0)

#define KE_LIST_REMOVE_AFTER(list, node)            \
    do {                                            \
        if ((list)->len > 0) {                      \
            if ((node)->next)                       \
                (node)->next = (node)->next->next;  \
            if (--(list)->len == 0)                 \
                (list)->head = NULL;                \
        }                                           \
    } while (0)

/* remove a node from list if matched with:
 * int func(struct ke_list_node *node, void *data)
 * func return 1 indicate matched, else return 0
 * O(n)
 */
#define KE_LIST_REMOVE_IF(list, func, data)                         \
    do {                                                            \
        struct ke_list_node **_pp_;                                 \
        for (_pp_ = &(list)->head; *_pp_; _pp_ = &(*_pp_)->next) {  \
            if (func(*_pp_, data)) {                                \
                *_pp_ = (*_pp_)->next;                              \
                (list)->len--;                                      \
                break;                                              \
            }                                                       \
        }                                                           \
    } while (0)

 /* remove node if matched with:
  * int f1(struct ke_dlist_node *node, void *d1)
  * and then call result node with:
  * void f2(struct ke_dlist_node *node, void *d2)
  * f1 return 1 indicate matched, else 0
  */
#define KE_LIST_REMOVE_IF2(list, f1, d1, f2, d2)                    \
    do {                                                            \
        struct ke_list_node **_pp_;                                 \
        for (_pp_ = &(list)->head; *_pp_; _pp_ = &(*_pp_)->next) {  \
            if (f1(*_pp_, d1)) {                                    \
                struct ke_list_node *_n_ = *_pp_;                   \
                *_pp_ = (*_pp_)->next;                              \
                (list)->len--;                                      \
                f2(_n_, d2);                                        \
                break;                                              \
            }                                                       \
        }                                                           \
    } while (0)

/* foreach the list with:
 * func(struct ke_list_node *node, void *data) 
 */
#define KE_LIST_FOREACH(list, func, data)                   \
    do {                                                    \
        struct ke_list_node *_n_;                           \
        for (_n_ = (list)->head; _n_; _n_ = _n_->next) {    \
            func(_n_, data);                                \
        }                                                   \
    } while (0)

/* search node with:
 * int func(struct ke_list_node *node, void *data)
 * func return 1 indicate matced, else return 0
 */
#define KE_LIST_SEARCH(pp, list, func, data)                \
    do {                                                    \
        struct ke_list_node *_n_;                           \
        for (_n_ = (list)->head; _n_; _n_ = _n_->next) {    \
            if (func(_n_, data)) {                          \
                *pp = _n_;                                  \
                break;                                      \
            }                                               \
        }                                                   \
    } while (0)

 /* foreach the list with:
* int func(struct ke_list_node *node, void *data)
* func return non-zero to break foreach
*/
#define KE_LIST_FOREACH_IF(list, func, data)                \
    do {                                                    \
        struct ke_list_node *_n_;                           \
        for (_n_ = (list)->head; _n_; _n_ = _n_->next) {    \
            if (func(_n_, data))                            \
                break;                                      \
        }                                                   \
    } while (0)

#define KE_LIST_CLEAR(list, clearfunc, data)                \
    while (KE_LIST_LEN(list) > 0) {                         \
        struct ke_dlist_node *_n_;                          \
        _n_ = KE_LIST_FRONT(list);                          \
        KE_LIST_DEL_FRONT(list);                            \
        clearfunc(_n_, data);                               \
    }                                        

#ifdef __cplusplus
}
#endif

#endif
