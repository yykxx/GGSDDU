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

#include "ke/bstree.h"

static struct ke_bstree_node *ke_bstree_walk_next(struct ke_bstree_node *node);
static struct ke_bstree_node *ke_bstree_walk_prev(struct ke_bstree_node *node);
static void ke_bstree_walk_data(struct ke_bstree_node *node,
                                void *data, void (*func)(void *, void *));
static void ke_bstree_mid_insert(struct ke_bstree *tree,
                                 struct ke_bstree_node *node);

/* create binary sort tree 
 * @tree [in] -- tree
 * @keycmp [in] -- key compare function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_init(struct ke_bstree *tree,
                         ke_stat_t (*keycmp)(void *, void *))
{
#ifdef KE_STRICT_CHECK
    if (!tree || !keycmp)
        return (KE_STAT_INVALID_ARGS);
#endif
    tree->keycmp = keycmp;
    tree->len = 0;
    tree->root = NULL;
    return (KE_STAT_OK);
}

/* insert data
 * @tree [in] -- target tree
 * @node [in] -- node to insert
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_insert(struct ke_bstree *tree, struct ke_bstree_node *node)
{
#ifdef KE_STRICT_CHECK
    if (!tree || !node)
        return (KE_STAT_INVALID_ARGS);
#endif
    ke_bstree_mid_insert(tree, node);
    tree->len++;
    return (KE_STAT_OK);
}

/* delete node matched data
 * @tree [in] -- target tree
 * @search_keycmp [in] -- key compare function for searching
 * @data [in] -- data to delete, as the second argument for search_keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_delete(struct ke_bstree *tree, 
                           ke_stat_t (*search_keycmp)(void *, void *),
                           void *data)
{
    ke_stat_t stat;
    struct ke_bstree_node *node;

    stat = ke_bstree_search(&node, tree, search_keycmp, data);
    if (KE_STAT_SUCCESS(stat))
        stat = ke_bstree_delete2(tree, node);

    return (stat);
}

/* delete node, this is faster than ke_bstree_delete
 * but first must get data node address
 * @tree [in] -- target tree
 * @curr [in] -- node to delete
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_delete2(struct ke_bstree *tree, struct ke_bstree_node *curr)
{
    /* how to remove a node from binary sort tree
     * when the node has at most one child
     * just remove it and set the child to be the child of node's parent
     *
     * when the node has has two children
     * replace the node with node's successor
     */
    struct ke_bstree_node *target = curr;
    struct ke_bstree_node *child, *node;

#ifdef KE_STRICT_CHECK
    if (!tree || !target)
        return (KE_STAT_INVALID_ARGS);
#endif

    /* when target has two children, then set node to be successor */
    if (!target->left || !target->right) {
        node = target;
    } else {
        ke_stat_t stat = ke_bstree_next(&node, tree, curr);
        if (KE_STAT_FAILED(stat))
            return (KE_STAT_ERROR);
    }

    /* at here, node may be target or successor
     * target: one child or no children
     * successor: no children
     * so, node has most one child, we get one child of node, this may be null
     * is the same as: 
     * 
     * child = NULL;
     * if (node->left)
     *     child = node->left;
     * if (node->right)
     *     child = node->right;
     */
    if (node->left)
        child = node->left;
    else
        child = node->right;

    /* when the node has a child, move it to be the child of node's parent
     * and set correct parent, then the node will be removed
     */
    if (child)
        child->parent = node->parent;

    if (node->parent) {
        if (node == node->parent->left)
            node->parent->left = child;    /* this may be null */
        else
            node->parent->right = child;    /* this may be null */
    } else {
        /* when node is the root node */
        tree->root = child;
    }

    /* node is removed, if it's not the target,
     * move the node to the new location
     */
    if (node != target) {
        /* node is the target's successor, move to new location
         * set the target's children to successor
         * the successor has no children before
         */
        node->left = target->left;
        if (target->left)
            target->left->parent = node;

        node->right = target->right;
        if (target->right)
            target->right->parent = node;

        /* set successor's parent to target's parent */
        node->parent = target->parent;
        if (target->parent) {
            if (target == target->parent->left)
                target->parent->left = node;
            else
                target->parent->right = node;
        } else {
            tree->root = node;
        }
    }

    tree->len--;
    return (KE_STAT_OK);
}

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
                           void *data)
{
    struct ke_bstree_node *node, *ret = NULL;
    ke_stat_t stat = KE_STAT_INVALID_ARGS;
    
#ifdef KE_STRICT_CHECK
    if (!tree || !search_keycmp)
        return (stat);
#endif
    node = tree->root;
    while (node) {
        ke_stat_t stat = search_keycmp(node, data);
        if (KE_STAT_EQUAL & stat) {
            ret = node;
            break;
        }

        if (stat & KE_STAT_SMALLER)
            node = node->right;    /* node < data */
        else if (stat & KE_STAT_BIGGER)
            node = node->left;    /* node > data */
        else
            /* never reach here */
            assert(0);
    }

    stat = ret ? KE_STAT_OK : KE_STAT_MISS_ELEMT;
    if (pp)
        *pp = ret;

    return (stat);
}

/* get the first node data
 * @pp [out] -- hold element
 * @tree [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_first(struct ke_bstree_node **pp, struct ke_bstree *tree)
{
    struct ke_bstree_node *first;

#ifdef KE_STRICT_CHECK
    if (!tree || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    for (first = tree->root;
         first && (first->left); first = first->left) { /* none */ }
    *pp = first;

    return (first ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* get the last node data
 * @pp [out] -- hold element
 * @tree [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_last(struct ke_bstree_node **pp, struct ke_bstree *tree)
{
    struct ke_bstree_node *last;

#ifdef KE_STRICT_CHECK
    if (!tree || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    for (last = tree->root;
         last && (last->right); last = last->right) { /* none */ }
    *pp = last;

    return (last ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* get next node
 * @pp [out] -- hold next node
 * @tree [in] -- target tree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_next(struct ke_bstree_node **pp,
                         struct ke_bstree *tree,
                         struct ke_bstree_node *curr)
{
#ifdef KE_STRICT_CHECK
    if (!curr || !tree || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    *pp = ke_bstree_walk_next(curr);
    return (*pp ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* get previous node
 * @pp [out] -- hold next node
 * @tree [in] -- target tree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_prev(struct ke_bstree_node **pp,
                         struct ke_bstree *tree,
                         struct ke_bstree_node *curr)
{
#ifdef KE_STRICT_CHECK
    if (!curr || !tree || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    *pp = ke_bstree_walk_prev(curr);
    return (*pp ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* foreach funtion
 * @tree [in] -- target tree
 * @foreach_func [in] -- foreach function
 * @data [in_opt] -- the second argument to foreach_func
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bstree_foreach(struct ke_bstree *tree,
                            void (*foreach_func)(void *, void *), void *data)
{
    struct ke_bstree_node *first;

#ifdef KE_STRICT_CHECK
    if (!foreach_func || !tree)
        return (KE_STAT_INVALID_ARGS);
#endif
    for (first = tree->root;
         first && (first->left); first = first->left) { /* none */ }
    ke_bstree_walk_data(first, data, foreach_func);
    return (KE_STAT_OK);
}

void ke_bstree_mid_insert(struct ke_bstree *tree, struct ke_bstree_node *node)
{
    ke_stat_t stat;
    struct ke_bstree_node *p = NULL;
    struct ke_bstree_node *tmp = tree->root;
    ke_stat_t (*keycmp)(void *, void *) = tree->keycmp;

    node->parent = node->left = node->right = NULL;

    /* find the location */
    while (tmp) {
        p = tmp;
        stat = keycmp(node, tmp);
        if (KE_STAT_SMALLER & stat)
            tmp = tmp->left;
        else if (KE_STAT_NSMALLER & stat)
            tmp = tmp->right;
        else
            /* never reach here */
            assert(0);
    }

    if (p) {
        node->parent = p;
        if (KE_STAT_SMALLER == stat)
            p->left = node;
        else
            p->right = node;
    } else {
        tree->root = node;
    }
}

struct ke_bstree_node *ke_bstree_walk_next(struct ke_bstree_node *node)
{
    struct ke_bstree_node *ret = NULL;

    if (!node)
        return (NULL);

    if (node->right) {
        node = node->right;
        while (node) {
            ret = node;
            node = node->left;
        }
    } else {
        struct ke_bstree_node *parent = node->parent;
        while (parent && parent->right == node) {
            node = parent;
            parent = parent->parent;
        }
        ret = parent;
    }

    return (ret);
}

struct ke_bstree_node *ke_bstree_walk_prev(struct ke_bstree_node *node)
{
    struct ke_bstree_node *ret = NULL;

    if (!node)
        return (NULL);

    if (node->left) {
        node = node->left;
        while (node) {
            ret = node;
            node = node->right;
        }
    } else {
        struct ke_bstree_node *parent = node->parent;
        while (parent && parent->left == node) {
            node = parent;
            parent = parent->parent;
        }
        ret = parent;
    }

    return (ret);
}

void ke_bstree_walk_data(struct ke_bstree_node *node, void *data,
                         void (*func)(void *, void *))
{
    while (node) {
        func(node, data);
        node = ke_bstree_walk_next(node);
    }
}
