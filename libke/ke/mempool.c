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

#include "ke/mempool.h"

struct ke_memnode {
    struct ke_list_node node;
    char buf[0];
};

/* init memory pool, all the memory will be free when we destroy the pool
 * @pool -- the pool
 * @blk_sz -- init block size
 * @alloc -- memory allocate function
 * @mfree -- memory free function
 */
void ke_mempool_init(struct ke_mempool *pool, size_t blk_sz,
                     void *(*alloc)(size_t), void (*mfree)(void *))
{
    KE_LIST_INIT(&pool->blk_list);
    memset(&pool->onoff, 0, sizeof(pool->onoff));
    pool->curr = NULL;
    pool->curr_free = 0;
    pool->init_blksz = blk_sz;
    pool->alloctor = alloc;
    pool->mfree = mfree;
}

/* destory memory pool and free all the blocks
 * @pool -- the correct pool
 */
void ke_mempool_destroy(struct ke_mempool *pool)
{
    void *blk;
    struct ke_list_node *node;

    while (KE_LIST_LEN(&pool->blk_list) > 0) {
        node = KE_LIST_FRONT(&pool->blk_list);
        KE_LIST_DEL_FRONT(&pool->blk_list);
        blk = (char *)node - offsetof(struct ke_memnode, node);
        pool->mfree(blk);
    }

    memset(pool, 0, sizeof(struct ke_mempool));
}

/* allocate
 * @pool -- the correct pool
 * @objsz -- object size
 * return NULL on error
 */
void *ke_mempool_alloc(struct ke_mempool *pool, size_t objsz)
{
    char *data;
    
    if (!pool->curr) {
        struct ke_memnode *node;
        size_t blksz, m;

        blksz = pool->init_blksz + sizeof(struct ke_memnode);
        blksz = blksz >= objsz ? blksz : objsz;
        
        m = blksz % sizeof(void *);
        if (m != 0)
            blksz += sizeof(void *) - m;

        node = (struct ke_memnode *)pool->alloctor(blksz);
        if (!node)
            return (NULL);

        pool->curr = node->buf;
        pool->curr_free = blksz - sizeof(struct ke_memnode);
        KE_LIST_ADD_FRONT(&pool->blk_list, &node->node);
    }

    if (objsz > pool->curr_free) {
        size_t m, blksz;
        struct ke_memnode *node;
        
        blksz = pool->init_blksz;
        while (blksz < objsz)
            blksz += pool->init_blksz;

        blksz += sizeof(struct ke_memnode);
        m = blksz % sizeof(void *);
        if (m != 0)
            blksz += sizeof(void *) - m;

        node = (struct ke_memnode *)pool->alloctor(blksz);
        if (!node)
            return (NULL);

        pool->curr = node->buf;
        pool->curr_free = blksz - sizeof(struct ke_memnode);
        KE_LIST_ADD_FRONT(&pool->blk_list, &node->node);
    }

    data = pool->curr;
    pool->curr += objsz;
    pool->curr_free -= objsz;

    if (pool->onoff.zero_memory)
        memset(data, 0, objsz);

    return (data);
}

/* allocate and clear to zero 
 * @pool -- the correct pool
 * @objn -- the number of object 
 * @objsz -- object size
 * return NULL on error
 */
void *ke_mempool_calloc(struct ke_mempool *pool, size_t objn, size_t objsz)
{
    size_t tsz = objn * objsz;
    void *data = ke_mempool_alloc(pool, tsz);
    if (data && !pool->onoff.zero_memory)
        memset(data, 0, tsz);
    return (data);
}
