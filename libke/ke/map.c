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

#include "ke/map.h"

struct ke_map_foreach {
    void (*kmf_func)(void *, void *);
    void *kmf_args;
};

static ke_stat_t ke_map_keycmp_wrap(void *first, void *second);
static void ke_map_foreach_wrap(void *first, void *second);

/* create Key-Value Map
 * @map [in] -- map
 * @keycmp [in] -- key compare function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_init(struct ke_map *map, ke_stat_t (*keycmp)(void *, void *))
{
#ifdef KE_STRICT_CHECK
    if (!keycmp || !map)
        return (KE_STAT_INVALID_ARGS);
#endif
    map->keycmp = keycmp;
    return ke_rbtree_init(&map->tree, ke_map_keycmp_wrap);
}

/* insert key and value
 * @map [in] -- map
 * @node [in] -- node to insert
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_insert(struct ke_map *map, struct ke_map_node *node)
{
#ifdef KE_STRICT_CHECK
    if (!map || !node)
        return (KE_STAT_INVALID_ARGS);
#endif
    node->map = map;
    return ke_rbtree_insert(&map->tree, &node->node);
}

/* delete the key and it's value
 * @map [in] -- map
 * @key [in] -- key
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_delete(struct ke_map *map, void *key)
{
    ke_stat_t r;
    struct ke_map_node *node;
    
    r = ke_map_search(&node, map, key);
    if (KE_STAT_SUCCESS(r))
        r = ke_map_delete2(map, node);

    return (r);
}

/* delete the key and it's value
 * @map [in] -- map
 * @node [in] -- node to delete
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_delete2(struct ke_map *map, struct ke_map_node *node)
{
#ifdef KE_STRICT_CHECK
    if (!map || !node)
        return (KE_STAT_INVALID_ARGS);
#endif
    return ke_rbtree_delete2(&map->tree, &node->node);
}

/* find the key in the map
 * @ret [out] -- hold result, if not NULL
 * @map [in] -- map
 * @key [in] -- the key to find, as the second args to keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_search(struct ke_map_node **pp, struct ke_map *map, void *key)
{
    ke_stat_t r;
    struct ke_map_node knode;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!map || !key)
        return (KE_STAT_INVALID_ARGS);
#endif
    memset(&knode, 0, sizeof(knode));
    knode.key = key;
    knode.map = map;
    r = ke_rbtree_search(&node, &map->tree, ke_map_keycmp_wrap, &knode);
    if (pp)
        *pp = (struct ke_map_node *)node;
    return (r);
}

/* foreach the map
 * @map [in] -- map
 * @foreach_func [in] -- function to call with elements
 * @data [in_opt] -- the second argsment to foreach_func
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_foreach(struct ke_map *map,
                         void (*foreach_func)(void *, void *), void *data)
{
    struct ke_map_foreach args = { foreach_func, data };

#ifdef KE_STRICT_CHECK
    if (!map || !foreach_func)
        return (KE_STAT_INVALID_ARGS);
#endif
    return ke_rbtree_foreach(&map->tree, ke_map_foreach_wrap, &args);
}

/* number of elements
 * @nelem [out] -- store result
 * @map [in] -- map
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_nelem(int *nelem, struct ke_map *map)
{
#ifdef KE_STRICT_CHECK
    if (!map || !nelem)    
        return (KE_STAT_INVALID_ARGS);
#endif
    *nelem = map->tree.len;
    return (KE_STAT_OK);
}

/* get the first element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_first(struct ke_map_node **pp, struct ke_map *map)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!map || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_first(&node, &map->tree);
    *pp = (struct ke_map_node *)node;
    return (r);
}

/* get the last element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_last(struct ke_map_node **pp, struct ke_map *map)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!map || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_last(&node, &map->tree);
    *pp = (struct ke_map_node *)node;
    return (r);
}

/* get the next element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_next(struct ke_map_node **pp, struct ke_map *map,
                      struct ke_map_node *curr)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!map || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_next(&node, &map->tree, &curr->node);
    *pp = (struct ke_map_node *)node;
    return (r);
}

/* get the previous element
 * @pp [out] -- hold element
 * @map [in] -- the target trree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_map_prev(struct ke_map_node **pp, struct ke_map *map,
                      struct ke_map_node *curr)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!map || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_prev(&node, &map->tree, &curr->node);
    *pp = (struct ke_map_node *)node;
    return (r);
}

ke_stat_t ke_map_keycmp_wrap(void *first, void *second)
{
    struct ke_map_node *a1 = (struct ke_map_node *)first;
    struct ke_map_node *a2 = (struct ke_map_node *)second;
    return a1->map->keycmp(a1->key, a2->key);
}

void ke_map_foreach_wrap(void *first, void *second)
{
    struct ke_map_node *a1 = (struct ke_map_node *)first;
    struct ke_map_foreach *foreach_args = (struct ke_map_foreach *)second;
    foreach_args->kmf_func(a1, foreach_args->kmf_args);
}
