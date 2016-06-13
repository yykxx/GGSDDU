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

#ifndef _KE_MEMPOOL_H
#define _KE_MEMPOOL_H

#include "ke/list.h"

#ifdef __cplusplus
extern "C" {
#endif
    
struct ke_mempool {
    struct ke_list blk_list;
    void *(*alloctor)(size_t);
    void (*mfree)(void *);
    char *curr;
    size_t curr_free;
    size_t init_blksz;

    struct {
        uint8_t zero_memory:1;
    } onoff;
};

/* init memory pool, all the memory will be free when we destroy the pool
 * @pool -- the pool
 * @blk_sz -- init block size
 * @alloc -- memory allocate function
 * @mfree -- memory free function
 */
void ke_mempool_init(struct ke_mempool *pool, size_t blk_sz,
                     void *(*alloc)(size_t), void (*mfree)(void *));

/* enable zero memory */
#define ke_mempool_enable(p, z) (p)->onoff.zero_memory = z;

/* destory memory pool and free all the blocks
 * @pool -- the correct pool
 */
void ke_mempool_destroy(struct ke_mempool *pool);

/* allocate
 * @pool -- the correct pool
 * @objsz -- object size
 * return NULL on error
 */
void *ke_mempool_alloc(struct ke_mempool *pool, size_t objsz);

/* allocate and clear to zero 
 * @pool -- the correct pool
 * @objn -- the number of object 
 * @objsz -- object size
 * return NULL on error
 */
void *ke_mempool_calloc(struct ke_mempool *pool, size_t objn, size_t objsz);

#define ke_mempool_talloc(T, p) (T *)ke_mempool_alloc(p, sizeof(T))

#ifdef __cplusplus
}
#endif
    
#endif

