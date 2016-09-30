/* Copyright (C) 2012 Xingxing Ke 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this lst of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this lst of conditions and the following disclaimer in the
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

#ifndef _KE_LOOKASIDE_LIST_H
#define _KE_LOOKASIDE_LIST_H

#include "ke/list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ke_lookaside_list {
    /* use to alloc memory when there is no object in lst */
    void *(*alloc)(size_t);

    /* use to free memory when the number of object in
     * lst larger than high level
     */
    void (*free)(void *);

    /* size in bytes per object */
    size_t obj_sz;

    /* the max number of object in lst */
    int32_t high_level;

    /* node cookie, use to verify valid object */
    uint16_t cookie;

    /* on/off */
    struct {
        uint8_t zero_memory : 1;
    } onoff;

    /* object lst */
    struct ke_list lst;

#ifndef NO_COLLECT_MISC_FLAG
    /* misc */
    struct {
        /* how many times allocate */
        uint64_t alloc_times;

        /* how many times free */
        uint64_t free_times;

        /* how many times allocate from lst */
        uint64_t alloc_times_from_list;

        /* how many times free to lst */
        uint64_t free_times_to_list;

        /* how many times allocate failed */
        uint64_t alloc_failed_times;
    } misc;
#endif
};

/* init a lookaside lst, a lookaside lst is just like 
 * a memory pool with object which has the same size
 * @lst -- lst to init
 * @high_level -- high water level, the number of free objects hold in lst
 * @obj_sz -- object size in bytes
 * @cookie -- cookie of node header
 * @alloc -- memory allocator, called when there is no free object in lst
 * @mfree -- memory free function,
 *           called when the number of free objects larger than high_level
 * return void
 */
void ke_lookaside_list_init(struct ke_lookaside_list *lst,
                            int32_t high_level, size_t obj_sz, uint16_t cookie,
                            void *(*alloc)(size_t), void (*mfree)(void *));

/* enable feature 
 * @lst -- lst to enable
 * @zero_memory -- set memory to zero when allocated
 * @tag_check -- an assert check for node cookie
 */

#define ke_lookaside_list_enable(l, zero_mem)   \
    do {                                        \
        (l)->onoff.zero_memory = zero_mem;        \
    } while (0)

/* destroy a lst, this just free the objects in lst 
 * @lst -- lst to destroy
 * return void
 */
void ke_lookaside_list_destroy(struct ke_lookaside_list *lst);

/* allocate object
 * @lst -- lookaside lst 
 * return NULL if failed, else valid memory address
 */
#define ke_lookaside_list_alloc(lst) \
    ke_lookaside_list_alloc_and_init((lst), NULL, NULL)

/* allocate object and init object if it is not from cache
 * @lst -- lookaside lst 
 * @userdata -- userdata pass to func as the second args
 * return NULL if failed, else valid memory address
 */
void *ke_lookaside_list_alloc_and_init(struct ke_lookaside_list *lst,
                                       void (*func)(void *, void *),
                                       void *user_data);

/* allocate from lookaside lst and clear memory to zero
 * @lst -- lookaside lst 
 * return NULL if failed, else valid memory address
 */
void *ke_lookaside_list_calloc(struct ke_lookaside_list *lst);

/* reference an exsit object
 * @obj -- object allocated from lookaside list
 * return current refcount
 */
int ke_lookaside_list_ref(void *obj);

/* free object 
 * @lst -- lookaside lst
 * @obj -- object to free
 * return refcount, 0 -- indicate the object was freed
 */
#define ke_lookaside_list_free(l, obj) \
    ke_lookaside_list_free_and_destroy((l), (obj), NULL, NULL)

/* free object 
 * @lst -- lookaside lst
 * @obj -- object to free
 * @func -- the object will be free if the number of free objects larger than
 *          high level and then func will be called before free it
 * @userdata -- userdata pass to func as the second args
 * return refcount, 0 -- indicate the object was freed
 */
int ke_lookaside_list_free_and_destroy(struct ke_lookaside_list *lst, void *obj,
                                       void (*func)(void *, void *),
                                       void *userdata);

/* remove objects from cache
 * @lst -- lookaside lst
 * @num_to_free -- the number of objects to free
 * return the number of object which is freed
 */
int ke_lookaside_list_remove(struct ke_lookaside_list *lst, int num_to_free);

/* foreach object */    
void ke_lookaside_list_foreach(struct ke_lookaside_list *lst,
                               void (*func)(void *, void *), void *userdata);
    
/* get the number of free objects 
 * @lst -- lookaside lst
 * return the number 
 */
#define ke_lookaside_list_free_objects(l)    KE_LIST_LEN(&((l)->lst))

#ifdef __cplusplus
}
#endif
    
#endif
