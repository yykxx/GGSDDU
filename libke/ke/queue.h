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

#ifndef _KE_QUEUE_H
#define _KE_QUEUE_H

#include "ke/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_queue_node {
    struct ke_queue_node *next;
};

struct ke_queue {
    struct ke_queue_node *head;
    struct ke_queue_node *tail;
    int len;
};

#define KE_QUEUE_INIT(q)              \
    do {                              \
        (q)->head = (q)->tail = NULL; \
        (q)->len = 0;                 \
    } while (0)

#define KE_QUEUE_PUSH(q, n)           \
    do {                              \
        (n)->next = NULL;             \
        if ((q)->tail)                \
            (q)->tail->next = n;      \
        (q)->tail = n;                \
        if ((q)->len++ == 0)          \
            (q)->head = n;            \
    } while (0)

#define KE_QUEUE_POP(q)                  \
    do {                                 \
        if ((q)->len > 0) {              \
            (q)->head = (q)->head->next; \
            if (--(q)->len == 0)         \
                (q)->tail = NULL;        \
        }                                \
    } while (0)

#define KE_QUEUE_REM(q, n)                                      \
    do {                                                        \
        struct ke_queue_node **_pp_;                            \
        for (_pp_ = &(q)->head; *_pp_; _pp_ = &(*_pp_)->next) { \
            if ((n) == *_pp_) {                                 \
                *_pp_ = (n)->next;                              \
                if (--(q)->len == 0)                            \
                    (q)->tail = NULL;                           \
                break;                                          \
            }                                                   \
        }                                                       \
    } while (0)

#define KE_QUEUE_FRONT(q) ((q)->head)
#define KE_QUEUE_END(q) ((q)->tail)
#define KE_QUEUE_LEN(q) ((q)->len)

#define KE_QUEUE_FOREACH(q, f, d)                     \
    do {                                              \
        struct ke_queue_node *_n_;                    \
        for (_n_ = (q)->head; _n_; _n_ = _n_->next) { \
            f(_n_, d);                                \
        }                                             \
    } while (0)

#define KE_QUEUE_FOREACH_IF(q, f, d)                  \
    do {                                              \
        struct ke_queue_node *_n_;                    \
        for (_n_ = (q)->head; _n_; _n_ = _n_->next) { \
            if (f(_n_, d)) break;                     \
        }                                             \
    } while (0)

#define KE_QUEUE_CLEAR(q, f, d)        \
    do {                               \
        while (KE_QUEUE_LEN(q) > 0) {  \
            struct ke_queue_node *_n_; \
            _n_ = KE_QUEUE_FRONT(q);   \
            KE_QUEUE_POP(q);           \
            f(_n_, d);                 \
        }                              \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
