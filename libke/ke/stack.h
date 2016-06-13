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

#ifndef _KE_STACKE_H
#define _KE_STACKE_H

#include "ke/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_stack_node {
    struct ke_stack_node *next;
};

struct ke_stack {
    struct ke_stack_node *top;
    int len;
};

#define KE_STACK_INIT(s) \
    do {                 \
        (s)->top = NULL; \
        (s)->len = 0;    \
    } while (0)

#define KE_STACK_TOP(s) ((s)->top)
#define KE_STACK_LEN(s) ((s)->len)

#define KE_STACK_PUSH(s, node)        \
    do {                              \
        struct ke_stack_node **_top_; \
        _top_ = &((s)->top);          \
        (node)->next = *_top_;        \
        *_top_ = (node);              \
        (s)->len++;                   \
    } while (0)

#define KE_STACK_POP(s)               \
    do {                              \
        struct ke_stack_node **_top_; \
        if ((s)->len > 0)    {        \
            _top_ = &((s)->top);      \
            *_top_ = (*_top_)->next;  \
            (s)->len--;               \
        }                             \
    } while (0)

#define KE_STACK_FOREACH(s, func, data)              \
    do {                                             \
        struct ke_stack_node *_n_;                   \
        for (_n_ = (s)->top; _n_; _n_ = _n_->next) { \
            func(_n_, data);                         \
        }                                            \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
