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

#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

#include "ke/queue.h"
#include "ke/aio.h"

#define KE_EVENTS_MAX_COUNT 64

struct ke_aio {
    int (*before_poll)(void *);
    void *before_poll_user_data;
    void (*after_poll)(void *, int);
    void *after_poll_user_data;
    void *(*alloc)(size_t);
    void (*free)(void *);
    void *poller;
    int errcode;
    volatile int stop;
    struct ke_queue task_queue;    
    struct ke_lookaside_list fd_pool;
    struct ke_lookaside_list ioctx_pool;
    struct ke_lookaside_list close_handler_pool;
    struct ke_lookaside_list task_pool;    
};

struct ke_aio_task {
    struct ke_queue_node node;
    void (*task)(void *);
    void *user_data;
};

enum ke_aio_type {
    KAT_TCP_READ,
    KAT_TCP_WRITE,
    KAT_TCP_ACCEPT,
    KAT_TCP_CONNECT,
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    KAT_FILE_READ,
    KAT_FILE_WRITE,
#endif
};

struct ke_aio_ioctx {
    struct ke_queue_node node;
    struct ke_aio_fd *afd;
    union {
        void (*on_read_done)(void *, char *, int);
        void (*on_write_done)(void *, const char *, int);
        int (*on_accept_done)(void *, ke_native_sock_t,
                              struct sockaddr *, socklen_t);
        void (*on_conn_done)(void *, int);
    };
    void *user_data;
    union {
        char *rbuf;
        const char *wbuf;
    };
    int buflen;
    enum ke_aio_type io_type;
};

struct ke_aio_fd {
    struct ke_aio *aio;
    struct ke_dlist close_handler_lst;
    int fd;
    int events;
    struct ke_queue read_ioctx_queue;
    struct ke_queue write_ioctx_queue;    
    uint8_t refcount;
    uint8_t type : 3;
    uint8_t closed : 1;
    uint8_t connect_called : 1;
};

#define KE_AIO_SET_ERRNO(aio) (aio)->errcode = errno
#define KE_AIO_SET_ERRCODE(aio, e) (aio)->errcode = (e)

static void ke_aio_error_event_handler(struct ke_aio_ioctx *);
static void ke_aio_read_event_handler(struct ke_aio_ioctx *);
static void ke_aio_write_event_handler(struct ke_aio_ioctx *);
static void ke_aio_accept_event_handler(struct ke_aio_ioctx *);
static void ke_aio_connect_event_handler(struct ke_aio_ioctx *);
static void ke_aio_run_post_task(struct ke_aio *aio);
static int ke_aio_closefd_internal(struct ke_aio_fd *afd);

#ifdef USE_EPOLL
#include "ke/aio_epoll.c"
#else
#endif

/* create aio
 * return NULL -- error, else success
 */    
ke_aio_t ke_aio_create()
{
    return (struct ke_aio *)calloc(1, sizeof(struct ke_aio));
}

/* create aio
 * @handle -- aio handle 
 * @config -- aio config 
 * return 0 -- success, else error
 */
int ke_aio_init(ke_aio_t handle, const struct ke_aio_config *config)
{
    void *poller;
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;
    
#ifdef KE_STRICT_CHECK
    if (!config->alloc || !config->free) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    poller = ke_aio_create_poller(aio, config);
    if (!poller)
        return (-1);

    aio->alloc = config->alloc;
    aio->free = config->free;
    aio->before_poll = config->before_poll;
    aio->before_poll_user_data = config->before_poll_user_data;
    aio->after_poll = config->after_poll;
    aio->after_poll_user_data = config->after_poll_user_data;
    aio->errcode = 0;
    aio->poller = poller;

    KE_QUEUE_INIT(&aio->task_queue);

    ke_lookaside_list_init(&aio->fd_pool, config->free_fd,
                           sizeof(struct ke_aio_fd),
                           -1, config->alloc, config->free);
    
    ke_lookaside_list_init(&aio->ioctx_pool, config->free_io_ctx,
                           sizeof(struct ke_aio_ioctx),
                           -1, config->alloc, config->free);
    
    ke_lookaside_list_init(&aio->close_handler_pool,
                           config->free_close_handler,
                           sizeof(struct ke_aio_close_handler),
                           -1, config->alloc, config->free);

    ke_lookaside_list_init(&aio->task_pool, config->free_task,
                           sizeof(struct ke_aio_task),
                           -1, config->alloc, config->free);

    return (0);
}

/* close proactor
 * @handle -- aio handle
 * return 0 -- success, else error
 */
int ke_aio_close(ke_aio_t handle)
{
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;
    if (aio->poller) {
        ke_aio_close_poller(aio->poller);
        ke_lookaside_list_destroy(&aio->task_pool);
        ke_lookaside_list_destroy(&aio->close_handler_pool);
        ke_lookaside_list_destroy(&aio->ioctx_pool);
        ke_lookaside_list_destroy(&aio->fd_pool);        
    }
    free(aio);
    return (0);
}

/* create tcp fd
 * @handle -- aio handle
 * @addr -- address to bind, NULL indicate to use INADDR_ANY
 * @port -- port to bind
 * @backlog -- not call listen with this socket if backlog == -1
 * @addr_reuse --  non-zero value indicate to set SO_REUSEADDR
 * return NULL -- error, else success
 */
ke_aio_fd_t ke_aio_create_tcp_fd(ke_aio_t handle, struct in_addr *addr,
                                 int32_t port, int32_t backlog,
                                 int addr_reuse)
{
    int sock, flags;
    ke_aio_fd_t fd;    
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        KE_AIO_SET_ERRNO(aio);        
        return (KE_AIO_INVALID_FD);
    }
    
    if (port > 0 && port <= UINT16_MAX) {
        int err;
        struct sockaddr_in addrin;

        err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                         &addr_reuse, sizeof(addr_reuse));
        if (err) {
            KE_AIO_SET_ERRNO(aio);
            close(sock);
            return (KE_AIO_INVALID_FD);
        }

        addrin.sin_family = AF_INET;
        addrin.sin_port = htons(port);
        if (addr)
            addrin.sin_addr = *addr;
        else
            addrin.sin_addr.s_addr = htonl(INADDR_ANY);
        
        err = bind(sock, (struct sockaddr *)&addrin, sizeof(addrin));
        if (!err && backlog >= 0)
            err = listen(sock, backlog);

        if (err) {
            KE_AIO_SET_ERRNO(aio);
            close(sock);
            return (KE_AIO_INVALID_FD);
        }
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        KE_AIO_SET_ERRNO(aio);
        close(sock);        
        return (KE_AIO_INVALID_FD);        
    }
    
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0) {
        KE_AIO_SET_ERRNO(aio);
        close(sock);        
        return (KE_AIO_INVALID_FD);        
    }

    fd = ke_aio_assoc_tcp(handle, sock, port > 0);
    if (fd == KE_AIO_INVALID_FD)
        close(sock);

    return (fd);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* create file fd
 * @handle -- aio handle   
 * @filepath -- file path
 * @flags -- O_XXX
 * @mode -- S_XXX
 * return NULL -- error, else success
 */
ke_aio_fd_t ke_aio_create_file_fd(ke_aio_t handle, const char *filepath,
                                  int flags, mode_t mode)
{
    int file;
    ke_aio_fd_t fd;
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;

#ifdef KE_STRICT_CHECK
    if (!filepath) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (KE_AIO_INVALID_FD);
    }
#endif
    
    file = open(filepath, flags, mode);
    if (file < 0) {
        KE_AIO_SET_ERRNO(aio);
        return (KE_AIO_INVALID_FD);
    }

    flags = fcntl(file, F_GETFL, 0);
    if (flags < 0) {
        KE_AIO_SET_ERRNO(aio);
        close(file);
        return (KE_AIO_INVALID_FD);        
    }
    
    flags |= O_NONBLOCK;
    if (fcntl(file, F_SETFL, flags) < 0) {
        KE_AIO_SET_ERRNO(aio);
        close(file);        
        return (KE_AIO_INVALID_FD);        
    }

    fd = ke_aio_assoc_file(handle, file);
    if (fd == KE_AIO_INVALID_FD)
        close(file);

    return (fd);
}

#endif

static ke_aio_fd_t ke_aio_assoc_fd(ke_aio_t handle, int type,
                                   int fd, int binded)
{
    struct ke_aio *aio;
    struct ke_aio_fd *afd;

    aio = (struct ke_aio *)handle;    
#ifdef KE_STRICT_CHECK
    if (fd < 0) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (KE_AIO_INVALID_FD);
    }
#endif

    afd = ke_lookaside_list_calloc(&aio->fd_pool);
    if (afd) {
        afd->fd = fd;
        afd->type = type;
        afd->aio = aio;
        KE_DLIST_INIT(&afd->close_handler_lst);
        KE_QUEUE_INIT(&afd->read_ioctx_queue);
        KE_QUEUE_INIT(&afd->write_ioctx_queue);        
    } else {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
    }

    return (afd);
}

/* associate native socket with aio
 * @handle -- aio handle
 * @sock -- native tcp socket 
 * @binded -- is socket binded
 * return NULL -- error, else success 
 */
ke_aio_fd_t ke_aio_assoc_tcp(ke_aio_t handle, ke_native_sock_t sock,
                             int binded)
{
    return ke_aio_assoc_fd(handle, KE_AIO_FD_TCP, sock, binded);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* associate native file with aio
 * @handle -- aio handle
 * @file -- native file 
 * return NULL -- error, else success 
 */
ke_aio_fd_t ke_aio_assoc_file(ke_aio_t handle, ke_native_file_t file)
{
    return ke_aio_assoc_fd(handle, KE_AIO_FD_FILE, file, 0);
}

#endif

/* close fd 
 * @fd -- aio fd 
 * return 0 -- success, else error
 */
int ke_aio_closefd(ke_aio_fd_t fd)
{
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    if (afd->closed)
        return (0);
        
    if (afd->refcount > 0)
        afd->closed = 1;
    else
        ke_aio_closefd_internal(afd);
    
    return (0);
}

/* close fd 
 * @fd -- aio fd 
 * return 0 -- success, else error
 */
int ke_aio_closefd_internal(struct ke_aio_fd *afd)
{
#define KE_AIO_INVOKE_CLOSE_HANDLER(n, d)                       \
    {                                                           \
        struct ke_aio_close_handler *_ch;                       \
        _ch = (struct ke_aio_close_handler *)n;                 \
        _ch->handler(_ch->user_data);                           \
        ke_lookaside_list_free(&aio->close_handler_pool, _ch);  \
    }

#define KE_AIO_INVOKE_READ_CB(n, d)                                  \
    {                                                                \
        struct ke_aio_ioctx *_ioctx;                                 \
        _ioctx = (struct ke_aio_ioctx *)n;                           \
        _ioctx->on_read_done(_ioctx->user_data, _ioctx->rbuf, 0);    \
        ke_lookaside_list_free(&aio->ioctx_pool, _ioctx);            \
    }

#define KE_AIO_INVOKE_WRITE_CB(n, d)                                 \
    {                                                                \
        struct ke_aio_ioctx *_ioctx;                                 \
        _ioctx = (struct ke_aio_ioctx *)n;                           \
        _ioctx->on_write_done(_ioctx->user_data, _ioctx->wbuf, 0);   \
        ke_lookaside_list_free(&aio->ioctx_pool, _ioctx);            \
    }

    struct ke_aio *aio = afd->aio;

    KE_QUEUE_CLEAR(&afd->read_ioctx_queue, KE_AIO_INVOKE_READ_CB, NULL);
    KE_QUEUE_CLEAR(&afd->write_ioctx_queue, KE_AIO_INVOKE_WRITE_CB, NULL);    
    KE_DLIST_CLEAR(&afd->close_handler_lst, KE_AIO_INVOKE_CLOSE_HANDLER, NULL);
    close(afd->fd);
    ke_lookaside_list_free(&aio->fd_pool, afd);
    
    return (0);

#undef KE_AIO_INVOKE_READ_CB    
#undef KE_AIO_INVOKE_WRITE_CB
#undef KE_AIO_INVOKE_CLOSE_HANDLER
}

/* async tcp read
 * return 0 -- success, else error
 */
int ke_aio_tcp_read(ke_aio_fd_t fd, char *buf, int buflen, 
                    void (*on_io_done)(void *, char *, int),
                    void *user_data)
{
    struct ke_aio *aio;
    struct ke_aio_fd *afd;
    struct ke_aio_ioctx *ioctx;    

    afd = (struct ke_aio_fd *)fd;
    aio = afd->aio;

#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_TCP || !buf || buflen <= 0 || !on_io_done) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_ioctx *)ke_lookaside_list_alloc(&aio->ioctx_pool);
    if (!ioctx) {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
        return (-1);
    }

    ioctx->afd = afd;
    ioctx->on_read_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->rbuf = buf;
    ioctx->buflen = buflen;
    ioctx->io_type = KAT_TCP_READ;

    if (KE_QUEUE_LEN(&afd->read_ioctx_queue) > 0) {
        KE_QUEUE_PUSH(&afd->read_ioctx_queue, &ioctx->node);
        return (0);
    }

    KE_QUEUE_PUSH(&afd->read_ioctx_queue, &ioctx->node);
    if (ke_aio_set_read_event(ioctx)) {
        ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
        return (-1);
    }

    return (0);
}

/* async tcp write
 * return 0 -- success, else error
 */
int ke_aio_tcp_write(ke_aio_fd_t fd, const char *buf, int buflen, 
                     void (*on_io_done)(void *, const char *, int),
                     void *user_data)
{
    struct ke_aio *aio;
    struct ke_aio_fd *afd;
    struct ke_aio_ioctx *ioctx;    

    afd = (struct ke_aio_fd *)fd;
    aio = afd->aio;

#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_TCP || !buf || buflen <= 0 || !on_io_done) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_ioctx *)ke_lookaside_list_alloc(&aio->ioctx_pool);
    if (!ioctx) {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
        return (-1);
    }

    ioctx->afd = afd;
    ioctx->on_write_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->wbuf = buf;
    ioctx->buflen = buflen;
    ioctx->io_type = KAT_TCP_WRITE;

    if (KE_QUEUE_LEN(&afd->write_ioctx_queue) > 0) {
        KE_QUEUE_PUSH(&afd->write_ioctx_queue, &ioctx->node);
        return (0);
    }

    KE_QUEUE_PUSH(&afd->write_ioctx_queue, &ioctx->node);
    if (ke_aio_set_write_event(ioctx)) {
        ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
        return (-1);
    }

    return (0);
}

/* async tcp accept
 * return 0 -- success, else error
 */
int ke_aio_tcp_accept(ke_aio_fd_t fd,
                      int (*on_accept_done)(void *, ke_native_sock_t,
                                            struct sockaddr *, socklen_t),
                      void *user_data)
{
    struct ke_aio *aio;
    struct ke_aio_fd *afd;
    struct ke_aio_ioctx *ioctx;    

    afd = (struct ke_aio_fd *)fd;
    aio = afd->aio;

#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_TCP || !on_accept_done) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_ioctx *)ke_lookaside_list_alloc(&aio->ioctx_pool);
    if (!ioctx) {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
        return (-1);
    }

    ioctx->afd = afd;
    ioctx->on_accept_done = on_accept_done;
    ioctx->user_data = user_data;
    ioctx->rbuf = NULL;
    ioctx->buflen = 0;
    ioctx->io_type = KAT_TCP_ACCEPT;

    if (KE_QUEUE_LEN(&afd->read_ioctx_queue) > 0) {
        KE_QUEUE_PUSH(&afd->read_ioctx_queue, &ioctx->node);
        return (0);
    }

    KE_QUEUE_PUSH(&afd->read_ioctx_queue, &ioctx->node);
    if (ke_aio_set_accept_event(ioctx)) {
        ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
        return (-1);
    }

    return (0);
}

/* async tcp connect
 * on_conn_done(user_data, is_error)
 * return 0 -- success, else error
 */
int ke_aio_tcp_connect(ke_aio_fd_t fd,
                       struct sockaddr *addr, socklen_t addrlen, 
                       void (*on_conn_done)(void *, int),
                       void *user_data)
{
    int err;
    struct ke_aio *aio;
    struct ke_aio_fd *afd;
    struct ke_aio_ioctx *ioctx;    

    afd = (struct ke_aio_fd *)fd;
    aio = afd->aio;

#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_TCP || !on_conn_done || !addr || addrlen < 0) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    if (afd->connect_called) {
        KE_AIO_SET_ERRCODE(aio, EISCONN);
        return (-1);
    }

    err = connect(afd->fd, addr, addrlen);
    afd->connect_called = 1;
    
    if (err == -1) {
        if (errno == EISCONN || errno == 0) {
            on_conn_done(user_data, 0);
            return (0);
        }
        if (errno != EINTR && errno != EALREADY && errno != EINPROGRESS) {
            KE_AIO_SET_ERRNO(aio);
            return (-1);
        }
    }

    ioctx = (struct ke_aio_ioctx *)ke_lookaside_list_alloc(&aio->ioctx_pool);
    if (!ioctx) {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
        return (-1);
    }

    ioctx->afd = afd;
    ioctx->on_conn_done = on_conn_done;
    ioctx->user_data = user_data;
    ioctx->wbuf = NULL;
    ioctx->buflen = 0;
    ioctx->io_type = KAT_TCP_CONNECT;    

    KE_QUEUE_PUSH(&afd->write_ioctx_queue, &ioctx->node);    
    if (ke_aio_set_connect_event(ioctx)) {
        ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
        return (-1);
    }

    return (0);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* async file read
 * return 0 -- success, else error
 */
int ke_aio_file_read(ke_aio_fd_t fd, char *buf, int buflen, uint64_t off,
                     void (*on_io_done)(void *, char *, int),
                     void *user_data)
{
    struct ke_aio *aio;
    struct ke_aio_fd *afd;
    struct ke_aio_ioctx *ioctx;    

    afd = (struct ke_aio_fd *)fd;
    aio = afd->aio;

#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_FILE || !on_io_done || !buf || buflen == 0) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_ioctx *)ke_lookaside_list_alloc(&aio->ioctx_pool);
    if (!ioctx) {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
        return (-1);
    }

    ioctx->afd = afd;
    ioctx->on_read_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->rbuf = buf;
    ioctx->buflen = buflen;
    ioctx->io_type = KAT_FILE_READ;    

    if (ke_aio_submit_read(ioctx, off)) {
        ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
        return (-1);
    }

    return (0);
}

/* async file write
 * return 0 -- success, else error
 */
int ke_aio_file_write(ke_aio_fd_t fd, const char *buf, int buflen, uint64_t off,
                      void (*on_io_done)(void *, const char *, int),
                      void *user_data)
{
    struct ke_aio *aio;
    struct ke_aio_fd *afd;
    struct ke_aio_ioctx *ioctx;    

    afd = (struct ke_aio_fd *)fd;
    aio = afd->aio;

#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_FILE || !on_io_done || !buf || buflen == 0) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_ioctx *)ke_lookaside_list_alloc(&aio->ioctx_pool);
    if (!ioctx) {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
        return (-1);
    }

    ioctx->afd = afd;
    ioctx->on_write_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->wbuf = buf;
    ioctx->buflen = buflen;
    ioctx->io_type = KAT_FILE_WRITE;        

    if (ke_aio_submit_write(ioctx, off)) {
        ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
        return (-1);
    }

    return (0);
}

#endif


/* add close handler on fd
 * @fd -- valid fd
 * @user_data -- argument pass to handler
 * @handler -- handler called when fd closed
 * return 0 -- success, else error
 */
int ke_aio_add_close_handler(ke_aio_fd_t fd, void (*handler)(void *),
                             void *user_data)
{
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio = afd->aio;
    struct ke_aio_close_handler *ch;

#ifdef KE_STRICT_CHECK
    if (!handler) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    ch = (struct ke_aio_close_handler *)
        ke_lookaside_list_alloc(&aio->close_handler_pool);
    if (ch) {
        ch->handler = handler;
        ch->user_data = user_data;
        KE_DLIST_ADD_BACK(&afd->close_handler_lst, &ch->node);
    } else {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
    }

    return (ch ? 0 : -1);
}

/* remove close handler on fd
 * @fd -- valid fd
 * @user_data -- argument pass to handler
 * @handler -- handler called when fd closed
 */
void ke_aio_rem_close_handler(ke_aio_fd_t fd, void (*handler)(void *),
                              void *user_data)
{
#define KE_AIO_FIND_CLOSE_HANDLER(n, d)                        \
    (((struct ke_aio_close_handler *)n)->handler == handler \
    &&((struct ke_aio_close_handler *)n)->user_data == user_data)

#define KE_AIO_FREE_CLOSE_HANDLER(n, d) \
    ke_lookaside_list_free(&aio->close_handler_pool, n)
        
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio = afd->aio;

#ifdef KE_STRICT_CHECK
    if (!handler) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return;
    }
#endif

    KE_DLIST_REMOVE_IF2(&afd->close_handler_lst, KE_AIO_FIND_CLOSE_HANDLER,
                        NULL, KE_AIO_FREE_CLOSE_HANDLER, NULL);
    
#undef KE_AIO_FIND_CLOSE_HANDLER
#undef KE_AIO_FREE_CLOSE_HANDLER
}

/* clear close handler on fd */
void ke_aio_clear_close_handler(ke_aio_fd_t fd)
{
#define KE_AIO_FREE_CLOSE_HANDLER(n, d) \
    ke_lookaside_list_free(&aio->close_handler_pool, n)

    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio = afd->aio;    

    KE_DLIST_CLEAR(&afd->close_handler_lst, KE_AIO_FREE_CLOSE_HANDLER, NULL);
    
#undef KE_AIO_FREE_CLOSE_HANDLER
}

/* post task
 * @handle -- aio
 * @task -- the handler of task
 * @user_data -- user data pass to as the second argument
 * return 0 -- success, else error
 */
int ke_aio_post_task(ke_aio_t handle, void (*task)(void *), void *user_data)
{
    struct ke_aio_task *aio_task;
    struct ke_aio *aio;

#ifdef KE_STRICT_CHECK
    if (!task) {
        KE_AIO_SET_ERRCODE(aio, EINVAL);
        return (-1);
    }
#endif

    aio = (struct ke_aio *)handle;
    aio_task = ke_lookaside_list_alloc(&aio->task_pool);
    if (!aio_task) {
        KE_AIO_SET_ERRCODE(aio, ENOMEM);
        return (-1);
    }
    
    aio_task->task = task;
    aio_task->user_data = user_data;
    KE_QUEUE_PUSH(&aio->task_queue, &aio_task->node);
    return (0);
}

/* get native socket */
ke_native_sock_t ke_aio_get_native_socket(ke_aio_fd_t fd)
{
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_TCP) {
        KE_AIO_SET_ERRCODE(afd->aio, EINVAL);
        return (-1);
    }
#endif
    return (afd->fd);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* get native file */
ke_native_file_t ke_aio_get_native_file(ke_aio_fd_t fd)
{
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
#ifdef KE_STRICT_CHECK
    if (afd->type != KE_AIO_FD_FILE) {
        KE_AIO_SET_ERRCODE(afd->aio, EINVAL);        
        return (-1);
    }
#endif
    return (afd->fd);
}

#endif

ke_native_errno_t ke_aio_errno(ke_aio_t handle)
{
    return (((struct ke_aio *)handle)->errcode);
}

static void ke_aio_tcp_read_event_handler(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio *aio = afd->aio;
    int off = 0, err = 0;

    do {
        ssize_t len = recv(afd->fd, ioctx->rbuf + off, ioctx->buflen - off, 0);
        if (len > 0) {
            off += len;
        } else if (len < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                err = 1;
            break;
        } else {
            break;
        }
    } while (off < ioctx->buflen);

    /* report error when we read nothing and error happens */
    if (err && off == 0)
        off = -1;
    
    ioctx->on_read_done(ioctx->user_data, ioctx->rbuf, off);
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
}

static void ke_aio_tcp_write_event_handler(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio *aio = afd->aio;
    int off = 0, err = 0;

    do {
        ssize_t len = send(afd->fd, ioctx->wbuf + off, ioctx->buflen - off, 
                           MSG_NOSIGNAL);
        if (len >= 0) {
            off += len;
        } else if (len < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                err = 1;
            break;
        }
    } while (off < ioctx->buflen);

    /* report error when we read nothing and error happens */
    if (err && off == 0)
        off = -1;
    
    ioctx->on_write_done(ioctx->user_data, ioctx->rbuf, off);
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

static void ke_aio_file_read_event_handler(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio *aio = ioctx->afd->aio;
    
    ioctx->on_read_done(ioctx->user_data, ioctx->rbuf, ioctx->buflen);
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
}

static void ke_aio_file_write_event_handler(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio *aio = ioctx->afd->aio;
    
    ioctx->on_write_done(ioctx->user_data, ioctx->wbuf, ioctx->buflen);
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
}

#endif

void ke_aio_error_event_handler(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio *aio = afd->aio;

    switch (ioctx->io_type) {
    case KAT_TCP_ACCEPT:
        ioctx->on_accept_done(ioctx->user_data, -1, NULL, 0);
        break;
    case KAT_TCP_CONNECT:
        ioctx->on_conn_done(ioctx->user_data, 1);
        break;
    case KAT_TCP_READ:
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    case KAT_FILE_READ:
#endif
        ioctx->on_read_done(ioctx->user_data, ioctx->rbuf, -1);
        break;
    case KAT_TCP_WRITE:
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    case KAT_FILE_WRITE:
#endif
        ioctx->on_write_done(ioctx->user_data, ioctx->wbuf, -1);
        break;
    default:
        assert(0 && "this will not happen");
        break;
    }
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
}

void ke_aio_read_event_handler(struct ke_aio_ioctx *ioctx)
{
    switch (ioctx->io_type) {
    case KAT_TCP_READ:
        ke_aio_tcp_read_event_handler(ioctx);
        break;
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    case KAT_FILE_READ:
        ke_aio_file_read_event_handler(ioctx);
        break;
#endif
    default:
        assert(0 && "this will not happen");
        break;
    }
}

void ke_aio_write_event_handler(struct ke_aio_ioctx *ioctx)
{
    switch (ioctx->io_type) {
    case KAT_TCP_WRITE:
        ke_aio_tcp_write_event_handler(ioctx);        
        break;
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    case KAT_FILE_WRITE:
        ke_aio_file_write_event_handler(ioctx);        
        break;
#endif
    default:
        assert(0 && "this will not happen");
        break;
    }
}

void ke_aio_accept_event_handler(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio *aio = afd->aio;
    int rc = 0;

    do {
        struct sockaddr_in addr;
        socklen_t addrlen;
        int cli, err = 0;

        cli = accept(afd->fd, (struct sockaddr *)&addr, &addrlen);
        if (-1 == cli) {
            if (errno == EINTR)
                continue;
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                err = 1;
            else
                err = -1;
        }

        if (err == 0) {
            ioctx->on_accept_done(ioctx->user_data, cli,
                                  (struct sockaddr *)&addr, addrlen);
            /* callback return non-zero value indicate to continue accept */
            if (rc != 0)
                continue;
        } else if (err == -1) {
            /* unexpected error */
            KE_AIO_SET_ERRNO(aio);
            ioctx->on_accept_done(ioctx->user_data, -1, NULL, 0);
        } else if (err == 1 && rc != 0) {
            /* automatic accept, reuse ioctx */
            KE_QUEUE_PUSH(&afd->read_ioctx_queue, &ioctx->node);
            if (!ke_aio_set_accept_event(ioctx))
                return;
            /* set accept event failed, then pop and free it at the end */
            KE_QUEUE_POP(&afd->read_ioctx_queue);
        }
        
        break;
    } while (1);

    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
}

void ke_aio_connect_event_handler(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio *aio = afd->aio;
    int ecode = 0, err;
    socklen_t elen = sizeof(ecode);

    err = getsockopt(afd->fd, SOL_SOCKET, SO_ERROR, &ecode, &elen);
    if (!err) {
        if (ecode == EALREADY || ecode == EINPROGRESS) {
            /* check next time */
            ke_aio_set_connect_event(ioctx);
            return;
        }

        if (ecode == EISCONN || ecode == 0) {
            /* connected */
            ioctx->on_conn_done(ioctx->user_data, 0);
            ke_lookaside_list_free(&aio->ioctx_pool, ioctx);
            return;
        }
    }

    KE_AIO_SET_ERRNO(aio);
    ioctx->on_conn_done(ioctx->user_data, 1);
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);    
}

void ke_aio_run_post_task(struct ke_aio *aio)
{
    struct ke_aio_task *aio_task;

    while (KE_QUEUE_LEN(&aio->task_queue) > 0) {
        aio_task = (struct ke_aio_task *)KE_QUEUE_FRONT(&aio->task_queue);
        KE_QUEUE_POP(&aio->task_queue);
        aio_task->task(aio_task->user_data);
        ke_lookaside_list_free(&aio->task_pool, aio_task);
    }
}