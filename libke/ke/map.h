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

#ifndef _KE_MAP_H
#define _KE_MAP_H

#include "ke/rbtree.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_map_node {
    struct ke_rbtree_node node;
    struct ke_map *map;
    void *value;
    void *key;
};

struct ke_map {
    struct ke_rbtree tree;
    ke_stat_t (*keycmp)(void *, void *);
};

/* create Key-Value Map
 * @map [in] -- map
 * @keycmp [in] -- key compare function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_init(struct ke_map *map, ke_stat_t (*keycmp)(void *, void *));

/* insert key and value
 * @map [in] -- map
 * @node [in] -- node to insert
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_insert(struct ke_map *map, struct ke_map_node *node);

/* delete the key and it's value
 * @map [in] -- map
 * @key [in] -- key
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_delete(struct ke_map *map, void *key);

/* delete the key and it's value
 * @map [in] -- map
 * @node [in] -- node to delete
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_delete2(struct ke_map *map, struct ke_map_node *node);

/* find the key in the map
 * @ret [out] -- hold result, if not NULL
 * @map [in] -- map
 * @key [in] -- the key to find, as the second args to keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_search(struct ke_map_node **pp, struct ke_map *map, void *key);

/* foreach the map
 * @map [in] -- map
 * @foreach_func [in] -- function to call with elements
 * @data [in_opt] -- the second argsment to foreach_func
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_foreach(struct ke_map *map,
                         void (*foreach_func)(void *, void *), void *data);

/* number of elements
 * @nelem [out] -- store result
 * @map [in] -- map
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_nelem(int *nelem, struct ke_map *map);

/* get the first element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_first(struct ke_map_node **pp, struct ke_map *map);

/* get the last element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_last(struct ke_map_node **pp, struct ke_map *map);

/* get the next element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_next(struct ke_map_node **pp, struct ke_map *map,
                      struct ke_map_node *curr);

/* get the previous element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_prev(struct ke_map_node **pp, struct ke_map *map,
                      struct ke_map_node *curr);

#ifdef __cplusplus
}
#endif

#endif
