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

#ifndef _KE_HASH_TABLE_H
#define _KE_HASH_TABLE_H

#include "ke/dlist.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_hash_link_table_node {
    struct ke_dlist_node node;
};

struct ke_hash_link_table {
    unsigned total_num;
    struct ke_dlist *bucket;
    int size;
    int keyoff;
    int (*hash)(void *);
    ke_stat_t (*match)(void *, void *);
};

#define ke_hash_link_table_bucket_get(t, k) ((k) % (t)->size)
#define ke_hash_link_table_bucket_get2(t, kv) (((t)->hash(kv)) % (t)->size)

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
                                  ke_stat_t (*match)(void *, void *));

/* destroy hash link table 
 * @hash [in] -- hash to destroy
 * @mfree [in] -- memory free function
 * @node_destroy [in] -- destroy node
 * @data [in] -- pass to node_destroy as the second argument
 */
void ke_hash_link_table_destroy(struct ke_hash_link_table *hash,
                                void (*mfree)(void *),
                                void (*node_destroy)(void *, void *),
                                void *data);

/* insert a new node into hash link table 
 * @hash [in] -- target hash
 * @node [in] -- new node
 */
ke_stat_t ke_hash_link_table_insert(struct ke_hash_link_table *hash,
                                    struct ke_hash_link_table_node *node);

/* remove a node from hash link table 
 * @hash [in] -- target hash
 * @node [in] -- node to remove
 */
ke_stat_t ke_hash_link_table_rem(struct ke_hash_link_table *hash,
                                 struct ke_hash_link_table_node *node);

/* find a node from hash link table 
 * @pp [out] -- result
 * @hash [in] -- target hash
 * @key [in] -- pass to match function as the second argument
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_hash_link_table_get(struct ke_hash_link_table_node **pp,
                                 struct ke_hash_link_table *hash, void *key);

/* get the total number of hash elements 
 * @len [out] -- result
 * @bucket [in] -- which bucket to fetch, -1 indicate all of them
 * @hash [in] -- hash table
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_hash_link_table_elem_num(unsigned *len, int bucket,
                                      struct ke_hash_link_table *hash);

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
                                     void *data);

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
                                   void *data);

#ifdef __cplusplus
}
#endif

#endif
