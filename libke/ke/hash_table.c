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

#include "ke/hash_table.h"

/* init hash link table 
 * @hash [in_out] -- hash to init
 * @bucket_size [in] -- size of bucket 
 * @alloc [in] -- memory allocator
 * @hash_func [in] -- hash function
 * @keyoff [in] -- offset of key in data node
 * @match [in] -- function to compare key
 *     return 1 indicate data is matched
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_hash_link_table_init(struct ke_hash_link_table *hash,
                                  int bucket_size, void *(*alloc)(size_t),
                                  int (*hash_func)(void *), int keyoff,
                                  ke_stat_t (*match)(void *, void *))
{
    size_t size;

#ifdef KE_STRICT_CHECK
    if (!alloc || !hash_func || !match)
        return (KE_STAT_INVALID_ARGS);
#endif

    size = bucket_size * sizeof(struct ke_dlist);
    hash->bucket = (struct ke_dlist *)alloc(size);
    if (hash->bucket) {
        int i;

        hash->total_num = 0;
        hash->size = bucket_size;
        hash->hash = hash_func;
        hash->match = match;
        hash->keyoff = keyoff;

        for (i = 0; i < bucket_size; i++)
            KE_DLIST_INIT(&hash->bucket[i]);

        return (KE_STAT_OK);
    }
    return (KE_STAT_MEMALLOC_ERROR);
}

/* destroy hash link table 
 * @hash [in] -- hash to destroy
 * @mfree [in] -- memory free function
 * @node_destroy [in] -- destroy node
 * @data [in] -- pass to node_destroy as the second argument
 */
void ke_hash_link_table_destroy(struct ke_hash_link_table *hash,
                                void (*mfree)(void *),
                                void (*node_destroy)(void *, void *),
                                void *data)
{
    int i;

    if (node_destroy) {
        for (i = 0; i < hash->size; i++)
            KE_DLIST_CLEAR(&hash->bucket[i], node_destroy, data);
    }

    hash->total_num = 0;
    mfree(hash->bucket);
}

/* insert a new node into hash link table 
 * @hash [in] -- target hash
 * @node [in] -- new node
 */
ke_stat_t ke_hash_link_table_insert(struct ke_hash_link_table *hash,
                                    struct ke_hash_link_table_node *node)
{
    int n, mod;
    void *key;

#ifdef KE_STRICT_CHECK
    if (!hash)
        return (KE_STAT_INVALID_ARGS);
#endif
    
    key = (char *)node + hash->keyoff;
    n = hash->hash(key);
    mod = n % hash->size;

    if (mod < 0)
        return (KE_STAT_OUTBOUND);

    KE_DLIST_ADD_FRONT(&hash->bucket[mod], &node->node);
    hash->total_num++;
    return (KE_STAT_OK);
}

/* remove a node from hash link table 
 * @hash [in] -- target hash
 * @node [in] -- node to remove
 */
ke_stat_t ke_hash_link_table_rem(struct ke_hash_link_table *hash,
                                 struct ke_hash_link_table_node *node)
{
    int n, mod;
    void *key;

#ifdef KE_STRICT_CHECK
    if (!hash)
        return (KE_STAT_INVALID_ARGS);
#endif
    
    key = (char *)node + hash->keyoff;
    n = hash->hash(key);
    mod = n % hash->size;

    if (mod < 0)
        return (KE_STAT_OUTBOUND);

    KE_DLIST_REMOVE(&hash->bucket[mod], &node->node);
    hash->total_num--;
    return (KE_STAT_OK);
}

/* find a node from hash link table 
 * @pp [out] -- result
 * @hash [in] -- target hash
 * @key [in] -- pass to match function as the second argument
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_hash_link_table_get(struct ke_hash_link_table_node **pp,
                                 struct ke_hash_link_table *hash, void *key)
{
    struct ke_dlist_node *node;
    int n, mod;

#ifdef KE_STRICT_CHECK
    if (!hash || !pp)
        return (KE_STAT_INVALID_ARGS);
#endif

    if (hash->total_num == 0)
        return (KE_STAT_MISS_ELEMT);
    
    n = hash->hash(key);
    mod = n % hash->size;

    if (mod < 0)
        return (KE_STAT_OUTBOUND);

    *pp = NULL;
    for (node = KE_DLIST_FRONT(&hash->bucket[mod]); node;
         node = KE_DLIST_NEXT(node))
    {
        if (hash->match((char *)node + hash->keyoff, key) == KE_STAT_EQUAL) {
            *pp = (struct ke_hash_link_table_node *)node;
            break;
        }
    }

    return (*pp ? KE_STAT_OK : KE_STAT_MISS_ELEMT);
}

/* get the total number of hash elements 
 * @len [out] -- result
 * @bucket [in] -- which bucket to fetch, -1 indicate all of them
 * @hash [in] -- hash table
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_hash_link_table_elem_num(unsigned *len, int bucket,
                                      struct ke_hash_link_table *hash)
{
#ifdef KE_STRICT_CHECK
    if (!len || !hash)
        return (KE_STAT_INVALID_ARGS);
#endif
    if (bucket == -1) {
        *len = hash->total_num;
    } else {
        if (bucket < 0 || bucket > hash->size)
            return (KE_STAT_OUTBOUND);
        *len = KE_DLIST_LEN(&hash->bucket[bucket]);
    }
    return (KE_STAT_OK);
}

/* foreach 
 * @hash [in] -- target hash
 * @bucket [in] -- which bucket to foreach, -1 indicate all of them
 * @data [in] -- pass to func as the second argument 
 * @func [in] -- foreach function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_hash_link_table_foreach(struct ke_hash_link_table *hash,
                                     int bucket, 
                                     void (*func)(void *, void *),
                                     void *data)
{
#ifdef KE_STRICT_CHECK
    if (!func || !hash)
        return (KE_STAT_INVALID_ARGS);
#endif
    if (bucket == -1) {
        int i;
        for (i = 0; i < hash->size; i++)
            KE_DLIST_FOREACH(&hash->bucket[i], func, data);
    } else {
        if (bucket < 0 || bucket > hash->size)
            return (KE_STAT_OUTBOUND);
        KE_DLIST_FOREACH(&hash->bucket[bucket], func, data);
    }
    return (KE_STAT_OK);
}

/* clear 
 * @hash [in] -- target hash
 * @bucket [in] -- which bucket to foreach, -1 indicate all of them
 * @data [in] -- pass to func as the second argument 
 * @func [in] -- foreach function
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_hash_link_table_clear(struct ke_hash_link_table *hash,
                                   int bucket, 
                                   void (*func)(void *, void *),
                                   void *data)
{
#ifdef KE_STRICT_CHECK
    if (!hash)
        return (KE_STAT_INVALID_ARGS);
#endif
    if (bucket == -1) {
        int i;
        for (i = 0; i < hash->size; i++)
            KE_DLIST_CLEAR(&hash->bucket[i], func, data);
        hash->total_num = 0;
    } else {
        if (bucket < 0 || bucket > hash->size)
            return (KE_STAT_OUTBOUND);
        hash->total_num -= KE_DLIST_LEN(&hash->bucket[bucket]);
        if (func) {
            KE_DLIST_CLEAR(&hash->bucket[bucket], func, data);
        } else {
            KE_DLIST_INIT(&hash->bucket[bucket]);
        }
    }
    return (KE_STAT_OK);
}
