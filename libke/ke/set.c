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

#include "ke/set.h"

/* create a set
 * @set [out] -- hold result, NULL if error
 * @keycmp [in] -- key compare function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_init(struct ke_set *set, ke_stat_t (*keycmp)(void *, void *))
{
#ifdef KE_STRICT_CHECK
    if (!set)
        return (KE_STAT_INVALID_ARGS);
#endif
    /* create red black tree */
    return ke_rbtree_init(&set->tree, keycmp);
}

/* insert data into set
 * @set [in] -- set
 * @node [in] -- data to insert
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_insert(struct ke_set *set, struct ke_set_node *node)
{
#ifdef KE_STRICT_CHECK
    if (!set || !node)
        return (KE_STAT_INVALID_ARGS);
#endif
    return ke_rbtree_insert(&set->tree, &node->node);
}

/* delete item
 * @set [in] -- set
 * @search_keycmp [in] -- key compare for searching
 * @data [in] -- as second args to keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_delete(struct ke_set *set, 
                        ke_stat_t (*search_keycmp)(void *, void *),
                        void *data)
{
    ke_stat_t r;
    struct ke_set_node *node;
    
    r = ke_set_search(&node, set, search_keycmp, data);
    if (KE_STAT_SUCCESS(r))
        r = ke_set_delete2(set, node);

    return (r);
}

/* delete item, faster than ke_set_delete
 * @set [in] -- set
 * @node [in] -- node to delete
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_delete2(struct ke_set *set, struct ke_set_node *node)
{
#ifdef KE_STRICT_CHECK
    if (!set)
        return (KE_STAT_INVALID_ARGS);
#endif
    return ke_rbtree_delete2(&set->tree, &node->node);
}

/* find the key in the set
 * @pp [out] -- hold result
 * @set [in] -- set
 * @search_keycmp [in] -- key compare for searching
 * @data [in] -- the key to find
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_search(struct ke_set_node **pp, struct ke_set *set,
                        ke_stat_t (*search_keycmp)(void *, void *), void *data)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!set || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_search(&node, &set->tree, search_keycmp, data);
    *pp = (struct ke_set_node *)node;
    return (r);
}

/* foreach the set
 * @set [in] -- set
 * @foreach_func [in] -- function called with every value in the set
 * @data [in_opt] -- the second argsment to foreach_func
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_foreach(struct ke_set *set,
                         void (*foreach_func)(void *, void *), void *data)
{
#ifdef KE_STRICT_CHECK
    if (!set)
        return (KE_STAT_INVALID_ARGS);
#endif
    return ke_rbtree_foreach(&set->tree, foreach_func, data);
}

/* number of elements
 * @nelem [out] -- store result
 * @set [in] -- set
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_nelem(int *nelem, struct ke_set *set)
{
#ifdef KE_STRICT_CHECK
    if (!set || !nelem)
        return (KE_STAT_INVALID_ARGS);
#endif
    *nelem = set->tree.len;
    return (KE_STAT_OK);
}

/* get the first element
 * @pp [out] -- hold element
 * @set [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_first(struct ke_set_node **pp, struct ke_set *set)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!set || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_first(&node, &set->tree);
    *pp = (struct ke_set_node *)node;
    return (r);
}

/* get the last element
 * @pp [out] -- hold element
 * @set [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_last(struct ke_set_node **pp, struct ke_set *set)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!set || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_last(&node, &set->tree);
    *pp = (struct ke_set_node *)node;
    return (r);
}

/* get the next element
 * @pp [out] -- hold element
 * @set [in] -- the target trree
 * @curr [in] -- the prev one
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_next(struct ke_set_node **pp, struct ke_set *set,
                      struct ke_set_node *curr)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!set || !pp || !curr)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_next(&node, &set->tree, &curr->node);
    *pp = (struct ke_set_node *)node;
    return (r);
}

/* get the previous element
 * @pp [out] -- hold element
 * @set [in] -- the target trree
 * @curr [in] -- the prev one
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_set_prev(struct ke_set_node **pp, struct ke_set *set,
                      struct ke_set_node *curr)
{
    ke_stat_t r;
    struct ke_rbtree_node *node = NULL;

#ifdef KE_STRICT_CHECK
    if (!set || !pp || !curr)
        return (KE_STAT_INVALID_ARGS);
#endif
    r = ke_rbtree_prev(&node, &set->tree, &curr->node);
    *pp = (struct ke_set_node *)node;
    return (r);
}

