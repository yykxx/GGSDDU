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


#ifndef _KE_DEFS_H
#define _KE_DEFS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int ke_stat_t;

#define KE_STAT_OK             0
/* bitset is set */
#define KE_STAT_SET            0x00000001
/* bitset is unset */
#define KE_STAT_UNSET          0x00000002

#define KE_STAT_ERROR          0x80000000
#define KE_STAT_INVALID_ARGS   0x80000001
#define KE_STAT_MISS_TYPE      0x80000002
#define KE_STAT_MISS_ELEMT     0x80000004
#define KE_STAT_MEMALLOC_ERROR 0x80000008
#define KE_STAT_NOBUFS         0x80000010
#define KE_STAT_OUTBOUND       0x80000020

#define KE_STAT_EQUAL          0x00000001
#define KE_STAT_NEQUAL         0x00000002
#define KE_STAT_BIGGER         0x00000004
#define KE_STAT_SMALLER        0x00000008
#define KE_STAT_NBIGGER        (KE_STAT_EQUAL | KE_STAT_SMALLER)
#define KE_STAT_NSMALLER       (KE_STAT_EQUAL | KE_STAT_BIGGER)

#define KE_STAT_SUCCESS(ret)   (KE_STAT_OK == (ret))
#define KE_STAT_FAILED(ret)    ((KE_STAT_ERROR & (ret)) == KE_STAT_ERROR)

#ifdef __cplusplus
}
#endif

#endif
