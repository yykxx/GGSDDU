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

#ifndef _KE_SPLAY_TREE_H_
#define _KE_SPLAY_TREE_H_

#include "ke/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_splay_node {
    struct ke_splay_node *left;
    struct ke_splay_node *right;
};

struct ke_splay {
    struct ke_splay_node *root;
    ke_stat_t (*keycmp)(void *, void *);
    int len;
};

/* init splay tree
 * @splay [in] -- splay tree to init
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_splay_init(struct ke_splay *splay,
                        ke_stat_t (*keycmp)(void *, void *));

/* insert node into splay tree
 * @splay [in] -- splay tree to init
 * @node [in] -- node to insert
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_splay_insert(struct ke_splay *splay, struct ke_splay_node *node);

/* delete node from splay tree which matched data 
 * @pp [out] -- hold the node which has removed
 * @splay [in] -- splay tree
 * @search_keycmp [in] -- search key compare function
 * @data [in] -- as the second argument to search_keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_splay_delete(struct ke_splay_node **pp,
                          struct ke_splay *splay, 
                          ke_stat_t (*search_keycmp)(void *, void *),
                          void *data);

/* search from splay tree
 * @pp [out] -- hold node
 * @splay [in] -- splay tree
 * @search_keycmp [in] -- search key compare function
 * @data [in] -- as the second argument to search_keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_splay_search(struct ke_splay_node **pp,
                          struct ke_splay *splay,
                          ke_stat_t (*search_keycmp)(void *, void *),
                          void *data);

#ifdef __cplusplus
}
#endif

#endif
