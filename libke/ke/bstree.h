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

#ifndef _KE_BSTREE_H
#define _KE_BSTREE_H

#include "ke/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_bstree_node {
    struct ke_bstree_node *left;
    struct ke_bstree_node *right;
    struct ke_bstree_node *parent;
};

struct ke_bstree {
    struct ke_bstree_node *root;
    ke_stat_t (*keycmp)(void *, void *);
    int len;
};

/* init binary sort tree 
 * @tree [in] -- tree
 * @keycmp [in] -- key compare function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_init(struct ke_bstree *tree,
                         ke_stat_t (*keycmp)(void *, void *));

/* insert data
 * @tree [in] -- target tree
 * @node [in] -- node to insert
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_insert(struct ke_bstree *tree, struct ke_bstree_node *node);

/* delete node matched data
 * @tree [in] -- target tree
 * @search_keycmp [in] -- key compare function for searching
 * @data [in] -- data to delete, as the second argument for search_keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_delete(struct ke_bstree *tree, 
                           ke_stat_t (*search_keycmp)(void *, void *),
                           void *data);

/* delete node, this is faster than ke_bstree_delete
 * but first must get data node address
 * @tree [in] -- target tree
 * @curr [in] -- node to delete
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_delete2(struct ke_bstree *tree,
                            struct ke_bstree_node *curr);

/* search the tree to find the one eq to data with keycmp compare fuction
 * @pp [out_opt] -- hold result if not NULL
 * @tree [in] -- target tree
 * @search_keycmp [in] -- key compare function for searching
 * @data [in] -- data to delete, as the second argument for search_keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_search(struct ke_bstree_node **pp,
                           struct ke_bstree *tree, 
                           ke_stat_t (*search_keycmp)(void *, void *),
                           void *data);

/* get the first node data
 * @pp [out] -- hold element
 * @tree [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_first(struct ke_bstree_node **pp, struct ke_bstree *tree);

/* get the last node data
 * @pp [out] -- hold element
 * @tree [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_last(struct ke_bstree_node **pp, struct ke_bstree *tree);

/* get next node
 * @pp [out] -- hold next node
 * @tree [in] -- target tree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_next(struct ke_bstree_node **pp, struct ke_bstree *tree,
                         struct ke_bstree_node *curr);

/* get previous node
 * @pp [out] -- hold next node
 * @tree [in] -- target tree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_prev(struct ke_bstree_node **pp, struct ke_bstree *tree,
                         struct ke_bstree_node *curr);

/* foreach funtion
 * @tree [in] -- target tree
 * @foreach_func [in] -- foreach function
 * @data [in_opt] -- the second argument to foreach_func
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_foreach(struct ke_bstree *tree,
                            void (*foreach_func)(void *, void *), void *data);

#ifdef __cplusplus
}
#endif

#endif
