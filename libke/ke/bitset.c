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

#include "ke/bitset.h"

/* create a bitset object, init the bit buffer with init_size,
 * the bit buffer will increase dynamic
 * @bitset [in] -- bitset
 * @init_size [in] -- initial byte size of bit buffer, 8bit per byte
 * @mallocator [in] -- function which use to allocate
 *                     bitset object and buffer of bits
 * @mfree [in] -- function which use to free data allocate by @mallocator
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bitset_init(struct ke_bitset *bitset, size_t init_size,
                         void *(*mallocator)(size_t), void (*mfree)(void *))
{
    char *buf;

#ifdef KE_STRICT_CHECK
    if (!bitset)
        return (KE_STAT_INVALID_ARGS);
#endif
    if (!mallocator && !mfree) {
        mallocator = malloc;
        mfree = free;
    }
    if (!mallocator || !mfree)
        return (KE_STAT_INVALID_ARGS);

    buf = (char *)mallocator(init_size);
    if (!buf)
        return (KE_STAT_MEMALLOC_ERROR);

    bitset->used = bitset->nbits = 0;
    bitset->factor = KE_BS_DEF_FACTOR;
    bitset->size = init_size;
    bitset->malloc = mallocator;
    bitset->mfree = mfree;
    bitset->buf = buf;
    return (KE_STAT_OK);
}

/* destroy a bitset object
 * @bitset [in] -- the one to close
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bitset_close(struct ke_bitset *bitset)
{
#ifdef KE_STRICT_CHECK
    if (!bitset || !bitset->mfree)
        return (KE_STAT_INVALID_ARGS);
#endif
    
    bitset->mfree(bitset->buf);
    memset(bitset, 0, sizeof(struct ke_bitset));
    return (KE_STAT_OK);
}

/* test the nth bit 
 * @bitset [in] -- target bitset
 * @nbit [in] -- target bit [1...n]
 * return value check with KE_BIT_IS_UNSET or KE_BIT_IS_SET
 */
ke_stat_t ke_bitset_test(struct ke_bitset *bitset, size_t nbit)
{
    size_t mod, n;

#ifdef KE_STRICT_CHECK
    if (!bitset)
        return (KE_STAT_INVALID_ARGS);
#endif

    if (nbit == 0)
        return (KE_STAT_INVALID_ARGS);

    n = nbit / 8;
    if (n > bitset->used)
        return (KE_STAT_UNSET);

    /* [0...7] [8...15] 8th bits is locate in the first bit */
    mod = nbit % 8;
    if (mod == 0)
        n -= 1;

    if (bitset->buf[n] & (1 << mod))
        return (KE_STAT_SET);

    return (KE_STAT_UNSET);
}

/* set the nth bit
 * @bitset [in_out] -- target bitset, pointer to bitset handle, 
 * this handle may be changed when the bit buffer is too small
 * @nbit [in] -- target bit [1...n]
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bitset_set(struct ke_bitset *bitset, size_t nbit)
{
    size_t mod, n;

#ifdef KE_STRICT_CHECK
    if (!bitset)
        return (KE_STAT_INVALID_ARGS);
#endif

    if (nbit == 0)
        return (KE_STAT_INVALID_ARGS);

    n = nbit / 8;
    if (n >= bitset->size) {
        /* realloc memory */
        char *newbuf;
        size_t sn = bitset->size;

        while (sn <= n)
            sn += (size_t)((bitset->size * (bitset->factor + 1)));
        
        newbuf = (char *)bitset->malloc(sn);
        if (!newbuf)
            return (KE_STAT_MEMALLOC_ERROR);

        memset(newbuf + bitset->size, 0, sn - bitset->size);
        memcpy(newbuf, bitset->buf, bitset->used);

        bitset->mfree(bitset->buf);
        bitset->buf = newbuf;
        bitset->size = sn;
    }

    if (bitset->nbits < nbit)
        bitset->nbits = nbit;

    /* [0...7] [8...15] 8th bits is locate in the first bit */
    mod = nbit % 8;
    if (mod == 0)
        n -= 1;

    if (n + 1 > bitset->used)
        bitset->used = n + 1;
    
    bitset->buf[n] = bitset->buf[n] | (1 << mod);
    return (KE_STAT_OK);
}

/* clear the nth bit
 * @bitset [in] -- target bitset
 * @nbit [in] -- target bit [1...n]
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bitset_clear(struct ke_bitset *bitset, size_t nbit)
{
    size_t mod, n;

#ifdef KE_STRICT_CHECK
    if (!bitset)
        return (KE_STAT_INVALID_ARGS);
#endif

    if (nbit == 0)
        return (KE_STAT_INVALID_ARGS);

    n = nbit / 8;
    if (n > bitset->size)
        return (KE_STAT_OUTBOUND);

    /* [0...7] [8...15] 8th bits is locate in the first bit */
    mod = nbit % 8;
    if (mod == 0)
        n -= 1;

    bitset->buf[n] &= (~(1 << mod));
    return (KE_STAT_OK);
}
