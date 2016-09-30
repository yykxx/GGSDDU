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

#include "ke/rbtree.h"

#define KE_RBTREE_IS_RED(n) ((n)->color == KE_RED)

#define KE_RBTREE_IS_BLACK(n) ((n)->color == KE_BLACK)

#define KE_RBTREE_PARENT(n) ((n)->parent)

#define KE_RBTREE_LEFT(n) ((n)->left)

#define KE_RBTREE_RIGHT(n) ((n)->right)

#define KE_RBTREE_ROOT(n) ((n)->root)

#define KE_RBTREE_IS_LEFT(c, p) (KE_RBTREE_LEFT(p) == (c))

#define KE_RBTREE_IS_RIGHT(c, p) (KE_RBTREE_RIGHT(p) == (c))

static struct ke_rbtree_node *
ke_rbtree_borther(const struct ke_rbtree_node *node,
                  const struct ke_rbtree_node *parent);

static struct ke_rbtree_node *
ke_rbtree_uncle(const struct ke_rbtree_node *node,
                const struct ke_rbtree_node *parent);

static void
ke_rbtree_left_rotate(struct ke_rbtree *tree,
                      struct ke_rbtree_node *node);

static void
ke_rbtree_right_rotate(struct ke_rbtree *tree,
                       struct ke_rbtree_node *node);

static struct ke_rbtree_node *
ke_rbtree_walk_next(struct ke_rbtree_node *node);

static struct ke_rbtree_node *
ke_rbtree_walk_prev(struct ke_rbtree_node *node);

static void
ke_rbtree_walk_data(struct ke_rbtree_node *node, void *data,
                    void (*func)(void *, void *));

static void
ke_rbtree_insert_fixup(struct ke_rbtree *tree,
                       struct ke_rbtree_node *node);

static void
ke_rbtree_mid_insert(struct ke_rbtree *tree,
                     struct ke_rbtree_node *node);

static void
ke_rbtree_delete_fixup(struct ke_rbtree *tree,
                       struct ke_rbtree_node *node,
                       struct ke_rbtree_node *parent);

/* init binary sort tree 
 * @tree [in] -- tree
 * @keycmp [in] -- key compare function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_init(struct ke_rbtree *tree,
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
ke_stat_t ke_rbtree_insert(struct ke_rbtree *tree, struct ke_rbtree_node *node)
{
#ifdef KE_STRICT_CHECK
    if (!tree || !node)
        return (KE_STAT_INVALID_ARGS);
#endif
    ke_rbtree_mid_insert(tree, node);
    tree->len++;
    node->color = KE_RED;
    ke_rbtree_insert_fixup(tree, node);
    return (KE_STAT_OK);
}

/* delete node matched data
 * @tree [in] -- target tree
 * @search_keycmp [in] -- key compare function for searching
 * @data [in] -- data to delete, as the second argument to search_keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_delete(struct ke_rbtree *tree, 
                           ke_stat_t (*search_keycmp)(void *, void *),
                           void *data)
{
    ke_stat_t stat;
    struct ke_rbtree_node *node;

    stat = ke_rbtree_search(&node, tree, search_keycmp, data);
    if (KE_STAT_SUCCESS(stat))
        stat = ke_rbtree_delete2(tree, node);

    return (stat);
}

/* delete node, this is faster than ke_rbtree_delete
 * but first must get data node address
 * @tree [in] -- target tree
 * @curr [in] -- node to delete
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_delete2(struct ke_rbtree *tree, struct ke_rbtree_node *curr)
{
    int color;
    struct ke_rbtree_node *child, *node, *parent;
    struct ke_rbtree_node *target = curr;

#ifdef KE_STRICT_CHECK
    if (!tree || !target)
        return (KE_STAT_INVALID_ARGS);
#endif
    /* when target has two children, then set node to be successor */
    if (!target->left || !target->right) {
        node = target;
    } else {
        if (KE_STAT_FAILED(ke_rbtree_next(&node, tree, target)))
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
    color = node->color;
    parent = KE_RBTREE_PARENT(node);
    if (node->left)
        child = node->left;
    else
        child = node->right;

    /* when the node has a child, move it to be the child of node's parent
     * and set correct parent, then the node will be removed
     */
    if (child)
        child->parent = parent;

    if (parent) {
        if (node == parent->left)
            parent->left = child;    /* this may be null */
        else
            parent->right = child;    /* this may be null */
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
        
        node->color = target->color;

        /* set successor's parent to target's parent */
        node->parent = target->parent;
        if (target->parent) {
            if (target == target->parent->left)
                target->parent->left = node;
            else
                target->parent->right = node;
        } else 
            tree->root = node;

        if (parent == target)
            parent = node;
    }

    if (color == KE_BLACK)
        ke_rbtree_delete_fixup(tree, child, parent);

    tree->len--;
    return (KE_STAT_OK);
}

/* search the tree to find the one eq to data with keycmp compare fuction
 * @pp [out_opt] -- hold result if not NULL
 * @tree [in] -- target tree
 * @search_keycmp [in] -- key compare function for searching
 * @data [in] -- as the second argument to search_keycmp
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_search(struct ke_rbtree_node **pp,
                           struct ke_rbtree *tree, 
                           ke_stat_t (*search_keycmp)(void *, void *),
                           void *data)
{
    struct ke_rbtree_node *node, *ret = NULL;
    
#ifdef KE_STRICT_CHECK
    if (!tree || !search_keycmp)
        return (KE_STAT_INVALID_ARGS);
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

    if (pp)
        *pp = ret;

    return (ret ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* get the first node data
 * @pp [out] -- hold element
 * @tree [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_first(struct ke_rbtree_node **pp, struct ke_rbtree *tree)
{
    struct ke_rbtree_node *first;
    
#ifdef KE_STRICT_CHECK
    if (!tree || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    for (first = tree->root;
         first && (first->left); first = first->left) { /* none */ }
    *pp = first;

    return (first ? KE_STAT_OK : KE_STAT_ERROR);
}

/* get the last node data
 * @pp [out] -- hold element
 * @tree [in] -- the target trree
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_last(struct ke_rbtree_node **pp, struct ke_rbtree *tree)
{
    struct ke_rbtree_node *last;

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
ke_stat_t ke_rbtree_next(struct ke_rbtree_node **pp,
                         struct ke_rbtree *tree, struct ke_rbtree_node *curr)
{
#ifdef KE_STRICT_CHECK
    if (!pp || !tree || !curr)
        return (KE_STAT_INVALID_ARGS);
#endif
    *pp = ke_rbtree_walk_next(curr);
    return (*pp ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* get previous node
 * @pp [out] -- hold next node
 * @tree [in] -- target tree
 * @curr [in] -- current node
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_prev(struct ke_rbtree_node **pp, struct ke_rbtree *tree,
                         struct ke_rbtree_node *curr)
{
#ifdef KE_STRICT_CHECK
    if (!curr || !tree || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif
    *pp = ke_rbtree_walk_prev(curr);
    return (*pp ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* foreach funtion
 * @tree [in] -- target tree
 * @foreach_func [in] -- foreach function
 * @data [in_opt] -- the second argument to foreach_func
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_rbtree_foreach(struct ke_rbtree *tree,
                            void (*foreach_func)(void *, void *), void *data)
{
    struct ke_rbtree_node *first;

#ifdef KE_STRICT_CHECK
    if (!foreach_func || !tree)
        return (KE_STAT_INVALID_ARGS);
#endif
    for (first = tree->root;
         first && (first->left); first = first->left) { /* none */ }
    ke_rbtree_walk_data(first, data, foreach_func);

    return (KE_STAT_OK);
}

struct ke_rbtree_node *
ke_rbtree_borther(const struct ke_rbtree_node *node,
                  const struct ke_rbtree_node *parent)
{
    if (!parent)
        return (NULL);

    if (KE_RBTREE_IS_LEFT(node, parent))
        return (KE_RBTREE_RIGHT(parent));

    return (KE_RBTREE_LEFT(parent));
}

struct ke_rbtree_node *
ke_rbtree_uncle(const struct ke_rbtree_node *node,
                const struct ke_rbtree_node *parent)
{
    if (!parent)
        return (NULL);

    return ke_rbtree_borther(parent, parent->parent);
}

void ke_rbtree_left_rotate(struct ke_rbtree *tree, struct ke_rbtree_node *node)
{
    struct ke_rbtree_node *parent = KE_RBTREE_PARENT(node);
    struct ke_rbtree_node *right = KE_RBTREE_RIGHT(node);
    KE_RBTREE_RIGHT(node) = KE_RBTREE_LEFT(right);
    if (KE_RBTREE_RIGHT(node))
        KE_RBTREE_PARENT(KE_RBTREE_RIGHT(node)) = node;

    KE_RBTREE_PARENT(right) = parent;
    if (!parent)
        KE_RBTREE_ROOT(tree) = right;
    else if (KE_RBTREE_IS_LEFT(node, parent))
        KE_RBTREE_LEFT(parent) = right;
    else
        KE_RBTREE_RIGHT(parent) = right;

    KE_RBTREE_LEFT(right) = node;
    KE_RBTREE_PARENT(node) = right;
}

void ke_rbtree_right_rotate(struct ke_rbtree *tree, struct ke_rbtree_node *node)
{
    struct ke_rbtree_node *parent = KE_RBTREE_PARENT(node);
    struct ke_rbtree_node *left = KE_RBTREE_LEFT(node);

    KE_RBTREE_LEFT(node) = KE_RBTREE_RIGHT(left);
    if (KE_RBTREE_LEFT(node))
        KE_RBTREE_PARENT(KE_RBTREE_LEFT(node)) = node;

    KE_RBTREE_PARENT(left) = parent;
    if (!parent)
        KE_RBTREE_ROOT(tree) = left;
    else if (KE_RBTREE_IS_LEFT(node, parent))
        KE_RBTREE_LEFT(parent) = left;
    else
        KE_RBTREE_RIGHT(parent) = left;

    KE_RBTREE_RIGHT(left) = node;
    KE_RBTREE_PARENT(node) = left;
}

struct ke_rbtree_node *ke_rbtree_walk_next(struct ke_rbtree_node *node)
{
    struct ke_rbtree_node *ret = NULL;

    if (!node)
        return (NULL);

    if (node->right) {
        node = node->right;
        while (node) {
            ret = node;
            node = node->left;
        }
    } else {
        struct ke_rbtree_node *parent = node->parent;
        while (parent && parent->right == node) {
            node = parent;
            parent = parent->parent;
        }
        ret = parent;
    }

    return (ret);
}

struct ke_rbtree_node *ke_rbtree_walk_prev(struct ke_rbtree_node *node)
{
    struct ke_rbtree_node *ret = NULL;

    if (!node)
        return (NULL);

    if (node->left) {
        node = node->left;
        while (node) {
            ret = node;
            node = node->right;
        }
    } else {
        struct ke_rbtree_node *parent = node->parent;
        while (parent && parent->left == node) {
            node = parent;
            parent = parent->parent;
        }
        ret = parent;
    }

    return (ret);
}

void ke_rbtree_walk_data(struct ke_rbtree_node *node,
                         void *data, void (*func)(void *, void *))
{
    while (node) {
        func(node, data);
        node = ke_rbtree_walk_next(node);
    }
}

void ke_rbtree_mid_insert(struct ke_rbtree *tree, struct ke_rbtree_node *node)
{
    ke_stat_t stat;
    struct ke_rbtree_node *p = NULL;
    struct ke_rbtree_node *tmp = tree->root;
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

void ke_rbtree_insert_fixup(struct ke_rbtree *tree, struct ke_rbtree_node *node)
{
    struct ke_rbtree_node *parent, *gparent, *uncle, *tmp;

#define __KE_SWAP_VALUE(x, y, t)    \
    do {    \
        (t) = (x);    \
        (x) = (y);    \
        (y) = (t);    \
    } while (0)    \

    while ((parent = KE_RBTREE_PARENT(node)) && KE_RBTREE_IS_RED(parent)) {
        uncle = ke_rbtree_uncle(node, parent);
        gparent = KE_RBTREE_PARENT(parent);

        if (uncle && KE_RBTREE_IS_RED(uncle)) {
            uncle->color = parent->color = KE_BLACK;
            gparent->color = KE_RED;
            node = gparent;
            continue;
        }

        if (KE_RBTREE_IS_LEFT(parent, gparent)) {
            if (KE_RBTREE_IS_RIGHT(node, parent)) {
                ke_rbtree_left_rotate(tree, parent);
                __KE_SWAP_VALUE(node, parent, tmp);
            }

            parent->color = KE_BLACK;
            gparent->color = KE_RED;
            ke_rbtree_right_rotate(tree, gparent);

        } else {
            if (KE_RBTREE_IS_LEFT(node, parent)) {
                ke_rbtree_right_rotate(tree, parent);
                __KE_SWAP_VALUE(node, parent, tmp);
            }

            parent->color = KE_BLACK;
            gparent->color = KE_RED;
            ke_rbtree_left_rotate(tree, gparent);
        }
    }

    tree->root->color = KE_BLACK;
}

void ke_rbtree_delete_fixup(struct ke_rbtree *tree,
                            struct ke_rbtree_node *node,
                            struct ke_rbtree_node *parent)
{
    struct ke_rbtree_node *left, *right, *borther;

    while (node != tree->root && (!node || KE_RBTREE_IS_BLACK(node))) {
        borther = ke_rbtree_borther(node, parent);

        if (KE_RBTREE_IS_LEFT(node, parent)) {
            if (KE_RBTREE_IS_RED(borther)) {
                borther->color = KE_BLACK;
                parent->color = KE_RED;
                ke_rbtree_left_rotate(tree, parent);
                borther = KE_RBTREE_RIGHT(parent);
            }

            left = KE_RBTREE_LEFT(borther);
            right = KE_RBTREE_RIGHT(borther);

            if ((!left || KE_RBTREE_IS_BLACK(left)) && 
                (!right || KE_RBTREE_IS_BLACK(right))) {
                borther->color = KE_RED;
                node = parent;
                parent = KE_RBTREE_PARENT(node);

            } else {
                if (!right || KE_RBTREE_IS_BLACK(right)) {
                    KE_RBTREE_LEFT(borther)->color = KE_BLACK;
                    borther->color = KE_RED;
                    ke_rbtree_right_rotate(tree, borther);
                    borther = KE_RBTREE_RIGHT(parent);
                }

                borther->color = parent->color;
                parent->color = KE_BLACK;
                KE_RBTREE_RIGHT(borther)->color = KE_BLACK;
                ke_rbtree_left_rotate(tree, parent);
                node = tree->root;
                break;
            }

        } else {
            if (KE_RBTREE_IS_RED(borther)) {
                borther->color = KE_BLACK;
                parent->color = KE_RED;
                ke_rbtree_right_rotate(tree, parent);
                borther = KE_RBTREE_LEFT(parent);
            }

            left = KE_RBTREE_LEFT(borther);
            right = KE_RBTREE_RIGHT(borther);

            if ((!left || KE_RBTREE_IS_BLACK(left)) && 
                (!right || KE_RBTREE_IS_BLACK(right))) {
                borther->color = KE_RED;
                node = parent;
                parent = KE_RBTREE_PARENT(node);

            } else {
                if (!left || KE_RBTREE_IS_BLACK(left)) {
                    KE_RBTREE_RIGHT(borther)->color = KE_BLACK;
                    borther->color = KE_RED;
                    ke_rbtree_left_rotate(tree, borther);
                    borther = KE_RBTREE_LEFT(parent);
                }

                borther->color = parent->color;
                parent->color = KE_BLACK;
                KE_RBTREE_LEFT(borther)->color = KE_BLACK;
                ke_rbtree_right_rotate(tree, parent);
                node = tree->root;
                break;
            }
        }

        parent = KE_RBTREE_PARENT(node);
    }

    if (node)
        node->color = KE_BLACK;
}
