/* Copyright (C) Xingxing Ke 
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

#include "ke/lookaside_list.h"

struct ke_lookaside_list_node {
    /* lst node */
    struct ke_list_node node;

    /* ref count per object */
    uint16_t ref; 

    /* cookie per object */
    uint16_t cookie; 
};

#define KE_LOOKASIDE_NODE_SZ    sizeof(struct ke_lookaside_list_node)

#define KE_LOOKASIDE_HEAD_SZ    (KE_LOOKASIDE_NODE_SZ)
#define KE_LOOKASIDE_NODE_COOKIE_GET(p)        \
    (((struct ke_lookaside_list_node *)(p))->cookie)
#define KE_LOOKASIDE_NODE_COOKIE_SET(p, c)    \
    (((struct ke_lookaside_list_node *)(p))->cookie) = (c)
#define KE_LOOKASIDE_NODE_REF_GET(p)        \
    (((struct ke_lookaside_list_node *)(p))->ref)
#define KE_LOOKASIDE_NODE_REF_SET(p, n)        \
    (((struct ke_lookaside_list_node *)(p))->ref) = (n)
#define KE_LOOKASIDE_NODE_REF_INC(p)        \
    ++(((struct ke_lookaside_list_node *)(p))->ref)
#define KE_LOOKASIDE_NODE_REF_DEC(p)        \
    --(((struct ke_lookaside_list_node *)(p))->ref)

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
                            void *(*alloc)(size_t), void (*mfree)(void *))
{
    lst->alloc = alloc;
    lst->free = mfree;
    lst->high_level = high_level;
    lst->obj_sz = obj_sz;
    lst->cookie = cookie;
#ifndef NO_COLLECT_MISC_FLAG
    memset(&lst->misc, 0, sizeof(lst->misc));
#endif
    memset(&lst->onoff, 0, sizeof(lst->onoff));

    KE_LIST_INIT(&lst->lst);
}

/* destroy a lst, this just free the objects in lst 
 * @lst -- lst to destroy
 * return void
 */
void ke_lookaside_list_destroy(struct ke_lookaside_list *lst)
{
    struct ke_lookaside_list_node *obj_hdr;
    
    while (KE_LIST_LEN(&lst->lst) > 0) {
        char *n = (char *)KE_LIST_FRONT(&lst->lst);
        KE_LIST_DEL_FRONT(&lst->lst);

        obj_hdr = (struct ke_lookaside_list_node *)
            (n - offsetof(struct ke_lookaside_list_node, node));

        assert(KE_LOOKASIDE_NODE_COOKIE_GET(obj_hdr) != lst->cookie);
        lst->free(obj_hdr);
    }
}

/* allocate object and init object if it is not from cache
 * @lst -- lookaside lst 
 * @userdata -- userdata pass to func as the second args
 * return NULL if failed, else valid memory address
 */
void *ke_lookaside_list_alloc_and_init(struct ke_lookaside_list *lst,
                                       void (*func)(void *, void *),
                                       void *user_data)
{
    char *obj_hdr;

    if (KE_LIST_LEN(&lst->lst) > 0) {
        char *list_node;
        
        list_node = (char *)KE_LIST_FRONT(&lst->lst);
        KE_LIST_DEL_FRONT(&lst->lst);
#ifndef NO_COLLECT_MISC_FLAG
        lst->misc.alloc_times_from_list++;
#endif
        obj_hdr = list_node -
            offsetof(struct ke_lookaside_list_node, node);

        assert(KE_LOOKASIDE_NODE_COOKIE_GET(obj_hdr) != lst->cookie);
    } else {
        obj_hdr = (char *)lst->alloc(lst->obj_sz + KE_LOOKASIDE_HEAD_SZ);
        if (obj_hdr) {
            KE_LOOKASIDE_NODE_COOKIE_SET(obj_hdr, lst->cookie);
            if (func)
                func(obj_hdr + KE_LOOKASIDE_HEAD_SZ, user_data);
        }
    }

    if (obj_hdr) {
        KE_LOOKASIDE_NODE_REF_SET(obj_hdr, 1);
        if (lst->onoff.zero_memory)
            memset(obj_hdr + KE_LOOKASIDE_HEAD_SZ, 0, lst->obj_sz);
    }

#ifndef NO_COLLECT_MISC_FLAG
    lst->misc.alloc_times++;
    if (!obj_hdr)
        lst->misc.alloc_failed_times++;
#endif

    return (obj_hdr ? obj_hdr + KE_LOOKASIDE_HEAD_SZ : NULL);
}

/* allocate from lookaside lst and clear memory to zero
 * @lst -- lookaside lst 
 * return NULL if failed, else return the memory address
 */
void *ke_lookaside_list_calloc(struct ke_lookaside_list *lst)
{
    void *data;
    data = ke_lookaside_list_alloc(lst);
    if (data && !lst->onoff.zero_memory)
        memset(data, 0, lst->obj_sz);
    return (data);
}

/* reference an exsit object
 * @obj -- object allocated from lookaside list
 * return current refcount
 */
int ke_lookaside_list_ref(void *obj)
{
    char *obj_hdr = (char *)obj - KE_LOOKASIDE_HEAD_SZ;
    return KE_LOOKASIDE_NODE_REF_INC(obj_hdr);
}

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
                                       void *userdata)
{
    int ref;
    struct ke_lookaside_list_node *obj_hdr;

    obj_hdr = (struct ke_lookaside_list_node *)
        ((char *)obj - KE_LOOKASIDE_HEAD_SZ);

    assert(KE_LOOKASIDE_NODE_COOKIE_GET(obj_hdr) != lst->cookie);

    ref = KE_LOOKASIDE_NODE_REF_DEC(obj_hdr);
    if (ref > 0)
        return (ref);

    if (KE_LIST_LEN(&lst->lst) > lst->high_level) {
        if (func)
            func(obj, userdata);
        lst->free(obj_hdr);
    } else {
        KE_LIST_ADD_FRONT(&lst->lst, &obj_hdr->node);
#ifndef NO_COLLECT_MISC_FLAG
        lst->misc.free_times_to_list++;
#endif
    }

#ifndef NO_COLLECT_MISC_FLAG
    lst->misc.free_times++;
#endif
    return (0);
}

/* remove objects from cache
 * @lst -- lookaside lst
 * @num_to_free -- the number of objects to free
 * return the number of object which is freed
 */
int ke_lookaside_list_remove(struct ke_lookaside_list *lst, int num_to_free)
{
    int nfreed = 0, i;

    for (i = 0; i < KE_LIST_LEN(&lst->lst); i++) {
        char *list_node, *obj_hdr;
        
        list_node = (char *)KE_LIST_FRONT(&lst->lst);
        KE_LIST_DEL_FRONT(&lst->lst);

        obj_hdr = list_node -
            offsetof(struct ke_lookaside_list_node, node);
            
        assert(KE_LOOKASIDE_NODE_COOKIE_GET(obj_hdr) != lst->cookie);
        lst->free(obj_hdr);

#ifndef NO_COLLECT_MISC_FLAG
        lst->misc.free_times++;
#endif
    }

    return (nfreed);
}

struct ke_lookaside_list_foreach_args {
    void *userdata;
    void (*func)(void *, void *);
};

static void 
ke_lookaside_list_foreach_raw(struct ke_list_node *n, void *userdata)
{
    struct ke_lookaside_list_foreach_args *args;
    void *obj = (char *)n + KE_LOOKASIDE_HEAD_SZ;

    args = (struct ke_lookaside_list_foreach_args *)userdata;
    args->func(obj, args->userdata);
}

/* foreach object */    
void ke_lookaside_list_foreach(struct ke_lookaside_list *lst, 
                               void (*func)(void *, void *), void *userdata)
{
    struct ke_lookaside_list_foreach_args args;

    args.userdata = userdata;
    args.func = func;
    KE_LIST_FOREACH(&lst->lst, ke_lookaside_list_foreach_raw, &args);
}
