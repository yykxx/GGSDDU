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

#ifndef _KE_BITSET_H
#define _KE_BITSET_H

#include "ke/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* macro implemetion */

struct ke_bitset_def {
    /* we do not check the size at runtime
     * user must be make sure the buffer is big enough
     * or you can check whether the buffer is out of range or not
     * by KE_BITSET_CHECK_RANGE
     */
    size_t size;
    char *buf;
};

#define KE_BYTE_WIDE        8
#define KE_BITSET_T(name)    struct ke_bitset_def (name);

/* init bitset buffer */
#define KE_BITSET_INIT_BUF(it, bitbuf, nbit) \
    do {                                     \
        (it).buf = bitbuf;                   \
        (it).size = nbit;                    \
    } while (0)

#define KE_BITSET_CHECK_RANGE(it, nbit) (((nbit) / KE_BYTE_WIDE) <= (it).size)

/* test bit, n = [1...n] */
#define KE_BITSET_TEST(it, nbit, ret)         \
    do {                                      \
        size_t _mod_ = (nbit) % KE_BYTE_WIDE; \
        size_t _n_ = (nbit) / KE_BYTE_WIDE;   \
        assert(nbit > 0);                     \
        if (_mod_ == 0) --_n_;                \
        ret = (it).buf[_n_] & (1 << _mod_);   \
    } while (0)

/* set bit, n = [1...n] */
#define KE_BITSET_SET(it, nbit)                       \
    do {                                              \
        size_t _mod_ = (nbit) % KE_BYTE_WIDE;         \
        size_t _n_ = (nbit) / KE_BYTE_WIDE;           \
        assert(nbit > 0);                             \
        if (_mod_ == 0) --_n_;                        \
        (it).buf[_n_] = (it).buf[_n_] | (1 << _mod_); \
    } while (0)

/* clear nbitth bit, n = [1...n] */
#define KE_BITSET_CLEAR(it, nbit)                        \
    do {                                                 \
        size_t _mod_ = (nbit) % KE_BYTE_WIDE;            \
        size_t _n_ = (nbit) / KE_BYTE_WIDE;              \
        assert(nbit > 0);                                \
        if (_mod_ == 0) --_n_;                           \
        (it).buf[_n_] = (it).buf[_n_] & (~(1 << _mod_)); \
    } while (0)

/* function implemetion */

#define KE_BS_DEF_FACTOR    0.25

struct ke_bitset {
    size_t nbits;
    size_t size;
    size_t used;
    void *(*malloc)(size_t);
    void (*mfree)(void *);
    float factor;
    char *buf;
};

#define KE_BIT_IS_SET(stat) (((stat) & KE_STAT_SET) == KE_STAT_SET)
#define KE_BIT_IS_UNSET(stat) (((stat) & KE_STAT_UNSET) == KE_STAT_UNSET)

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
                         void *(*mallocator)(size_t), void (*mfree)(void *));

/* destroy a bitset object
 * @bitset [in] -- the one to close
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bitset_close(struct ke_bitset *bitset);

/* test the nth bit 
 * @bitset [in] -- target bitset
 * @nbit [in] -- target bit [1...n]
 * return value check with KE_BIT_IS_UNSET or KE_BIT_IS_SET
 */
ke_stat_t ke_bitset_test(struct ke_bitset *bitset, size_t nbit);

/* set the nth bit
 * @bitset [in] -- target bitset
 * @nbit [in] -- target bit [1...n]
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bitset_set(struct ke_bitset *bitset, size_t nbit);

/* clear the nth bit
 * @bitset [in] -- target bitset
 * @nbit [in] -- target bit [1...n]
 * return value check with KE_STAT_SUCCESS or KE_STAT_FAILED
 */
ke_stat_t ke_bitset_clear(struct ke_bitset *bitset, size_t nbit);

#ifdef __cplusplus
}
#endif

#endif
