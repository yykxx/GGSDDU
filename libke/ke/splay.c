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

#include "ke/splay.h"

static struct ke_splay_node *
ke_splay_play(struct ke_splay_node *x,
              ke_stat_t (*keycmp)(void *, void *), void *data)
{
    struct ke_splay_node n, *l, *r;

    n.left = n.right = NULL;
    l = r = &n;

    for (;;) {
        ke_stat_t stat;
        struct ke_splay_node *y;
        
        stat = keycmp(x, data);
        if (KE_STAT_SMALLER & stat) {
            if (!x->right)
                break;

            stat = keycmp(x->right, data);
            if (KE_STAT_SMALLER & stat) {
                /* rotate left */
                y = x->right;
                x->right = y->left;
                y->left = x;
                x = y;

                if (!x->right)
                    break;
            }

            /* the smaller link in l tree */
            l->right = x;
            l = x;
            x = x->right;
        } else if (KE_STAT_BIGGER & stat) {
            if (!x->left)
                break;

            stat = keycmp(x->left, data);
            if (KE_STAT_BIGGER & stat) {
                /* rotate right */
                y = x->left;
                x->left = y->right;
                y->right = x;
                x = y;

                if (!x->left)
                    break;
            }
            
            /* the bigger link in r tree */
            r->left = x;
            r = x;
            x = x->left;
        } else {
            break;
        }
    }
    /* relink the root */
    l->right = x->left;
    r->left = x->right;
    x->left = n.right;
    x->right = n.left;

    return (x);
}

static struct ke_splay_node *
ke_splay_remove_root(struct ke_splay_node *root,
                     ke_stat_t (*keycmp)(void *, void *))
{
    struct ke_splay_node *left, *right, *max, *min;

    left = root->left;
    right = root->right;

    for (max = left; max && max->right; max = max->right);
    if (max) {
        root = ke_splay_play(left, keycmp, max);
        /* root has no right child */
        root->right = right;
    } else {
        /* if root has no left child */
        for (min = right; min && min->left; min = min->left);
        if (min) {
            root = ke_splay_play(right, keycmp, min);
            /* root has no left child */
            root->left = left;
        } else {
            /* root is the only element */
            root = NULL;
        }
    }

    return (root);
}

/* init splay tree
 * @splay [in] -- splay tree to init
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_splay_init(struct ke_splay *splay,
                        ke_stat_t (*keycmp)(void *, void *))
{
#ifdef KE_STRICT_CHECK
    if (!splay)
        return (KE_STAT_INVALID_ARGS);
#endif
    splay->keycmp = keycmp;
    splay->len = 0;
    splay->root = NULL;
    return (KE_STAT_OK);
}

/* insert node into splay tree
 * @splay [in] -- splay tree to init
 * @node [in] -- node to insert
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_splay_insert(struct ke_splay *splay, struct ke_splay_node *node)
{
#ifdef KE_STRICT_CHECK
    if (!splay || !node)
        return (KE_STAT_INVALID_ARGS);
#endif
    node->left = node->right = NULL;
    if (splay->root) {
        struct ke_splay_node *x;
        ke_stat_t stat;

        x = ke_splay_play(splay->root, splay->keycmp, node);
        stat = splay->keycmp(x, node);
        if (KE_STAT_NSMALLER & stat) {
            node->left = x->left;
            node->right = x;
            x->left = NULL;
        } else if (KE_STAT_SMALLER & stat) {
            node->right = x->right;
            node->left = x;
            x->right = NULL;
        } else {
            /* never reach here */
            assert(0);
        }
    }
    
    splay->root = node;
    splay->len++;
    return (KE_STAT_OK);
}

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
                          void *data)
{
    ke_stat_t stat = ke_splay_search(pp, splay, search_keycmp, data);
    if (KE_STAT_SUCCESS(stat)) {
        splay->root = ke_splay_remove_root(*pp, splay->keycmp);
        splay->len--;
    }

    return (stat);
}

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
                          void *data)
{
    struct ke_splay_node *curr;
    ke_stat_t stat = KE_STAT_INVALID_ARGS;

#ifdef KE_STRICT_CHECK
    if (!splay || !search_keycmp || !data || !pp)
        return (stat);
#endif
    curr = ke_splay_play(splay->root, search_keycmp, data);
    stat = search_keycmp(curr, data);
    if (KE_STAT_EQUAL & stat) {
        *pp = curr;
        stat = KE_STAT_OK;
    } else {
        stat = KE_STAT_MISS_ELEMT;
    }

    splay->root = curr;
    return (stat);
}
