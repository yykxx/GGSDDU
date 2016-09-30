/* Copyright (C) 2013 Xingxing Ke
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

#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <assert.h>
#include <io.h>

#define KE_AIO_IO    0
#define KE_AIO_TASK  1

struct ke_aio_ovrlp {
    OVERLAPPED ovrlp;
    union {
        void (*hook)(void *, ke_aio_fd_t, int, int);
        void (*task)(void *);
    };
    uint8_t type;
};

struct ke_aio_io_ctx {
    struct ke_aio_ovrlp ovrlp;
    union {
        void (*on_read_done)(void *, char *, int);
        void (*on_write_done)(void *, const char *, int);
    };
    void *user_data;
    union {
        WSABUF wsabuf;
        struct {
            union {
                char *rbuf;
                const char *wbuf;
            };
            int buflen;
        };
    };
};

#define ADDRLEN    (sizeof(SOCKADDR_IN) + 16)

struct ke_aio_tcp_accept_ctx {
    struct ke_aio_ovrlp ovrlp;
    int (*on_accept_done)(void *, ke_native_sock_t,
                          struct sockaddr *, socklen_t);
    void *user_data;
    BYTE addr_buf[ADDRLEN + ADDRLEN];
    SOCKET cli_sock;
};

struct ke_aio_tcp_connect_ctx {
    struct ke_aio_ovrlp ovrlp;
    void (*on_conn_done)(void *, int);
    void *user_data;
    struct sockaddr_in peer;
};

struct ke_aio {
    void *(*alloc)(size_t);
    void (*free)(void *);
    int (*before_poll)(void *);
    void (*after_poll)(void *, int);
    void *data1;
    void *data2;
    void *user_data;
    HANDLE iocp;
    struct ke_lookaside_list fd_pool;
    struct ke_lookaside_list tcp_connect_ctx_pool;
    struct ke_lookaside_list tcp_accept_ctx_pool;
    struct ke_lookaside_list io_ctx_pool;
    struct ke_lookaside_list close_handler_pool;
    struct ke_lookaside_list task_ovrlp_pool;
    volatile uint8_t shutdown;
    ke_native_errno_t errcode;
};

#define KE_AIO_WIN_MAX_POOL    9

struct ke_aio_fd {
    struct ke_dlist close_handler_lst;
    struct ke_aio *aio;
    LPFN_ACCEPTEX acceptex;
    union {
        SOCKET sock;
        HANDLE file;
    };
    uint32_t refcount;
    uint8_t type : 3;
    uint8_t closing : 1;
    uint8_t connected : 1;
    uint8_t binded : 1;
};

static struct ke_aio_fd *ke_aio_create_fd(struct ke_aio *);

static void ke_aio_closefd_inner(struct ke_aio_fd *);

static ke_aio_fd_t ke_aio_assoc_fd(ke_aio_t, ke_native_sock_t, int);

static void ke_aio_tcp_accept_done(void *, ke_aio_fd_t, int, int);

static void ke_aio_tcp_connect_done(void *, ke_aio_fd_t, int, int);

static void ke_aio_tcp_read_done(void *, ke_aio_fd_t, int, int);

static void ke_aio_tcp_write_done(void *, ke_aio_fd_t, int, int);

static void ke_aio_file_read_done(void *, ke_aio_fd_t, int, int);

static void ke_aio_file_write_done(void *, ke_aio_fd_t, int, int);

static void ke_aio_clear_close_handler_list(struct ke_aio_fd *);

static int ke_aio_accept_inner(struct ke_aio_fd *,
                               struct ke_aio_tcp_accept_ctx *); 

/* create aio
 * @config -- aio config 
 * return KE_AIO_INVALID_HANDLE -- error, else success
 */    
ke_aio_t ke_aio_create(const struct ke_aio_config *config)
{
    struct ke_aio *aio;

#ifdef KE_STRICT_CHECK
    if (!config->alloc || !config->free)
        return (KE_AIO_INVALID_HANDLE);
#endif

    aio = config->alloc(sizeof(*aio));
    if (aio == NULL)
        return (KE_AIO_INVALID_HANDLE);

    memset(aio, 0, sizeof(*aio));
    aio->alloc = config->alloc;
    aio->free = config->free;
    aio->before_poll = config->before_poll;
    aio->data1 = config->before_poll_user_data;
    aio->after_poll = config->after_poll;
    aio->data2 = config->after_poll_user_data;

    aio->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (!aio->iocp) {
        ke_aio_close(aio);
        return (-1);
    }

    ke_lookaside_list_init(&aio->fd_pool, config->free_fd,
                           sizeof(struct ke_aio_fd), 
                           -1, config->alloc, config->free);

    ke_lookaside_list_init(&aio->tcp_accept_ctx_pool,
                           config->free_accept_ctx,
                           sizeof(struct ke_aio_tcp_accept_ctx),
                           -1, config->alloc, config->free);

    ke_lookaside_list_init(&aio->tcp_connect_ctx_pool,
                           config->free_connect_ctx,
                           sizeof(struct ke_aio_tcp_connect_ctx),
                           -1, config->alloc, config->free);

    ke_lookaside_list_init(&aio->io_ctx_pool, 
                           config->free_io_ctx,
                           sizeof(struct ke_aio_io_ctx),
                           -1, config->alloc, config->free);

    ke_lookaside_list_init(&aio->close_handler_pool, 
                           config->free_close_handler,
                           sizeof(struct ke_aio_fd), 
                           -1, config->alloc, config->free);

    ke_lookaside_list_init(&aio->task_ovrlp_pool, 
                           config->free_task,
                           sizeof(struct ke_aio_ovrlp), 
                           -1, config->alloc, config->free);
    return (aio);
}

/* close aio
 * @handle -- aio will be closed
 * return 0 -- success, else error
 */
int ke_aio_close(ke_aio_t handle)
{
    struct ke_aio *aio;
    
    aio = (struct ke_aio *)handle;
#ifdef KE_STRICT_CHECK
    if (!aio || !aio->free)
        return (-1);
#endif

    if (!aio->iocp) {
        CloseHandle(aio->iocp);
        aio->iocp = NULL;
    }

    ke_lookaside_list_destroy(&aio->task_ovrlp_pool);
    ke_lookaside_list_destroy(&aio->close_handler_pool);
    ke_lookaside_list_destroy(&aio->io_ctx_pool);
    ke_lookaside_list_destroy(&aio->tcp_connect_ctx_pool);
    ke_lookaside_list_destroy(&aio->tcp_accept_ctx_pool);
    ke_lookaside_list_destroy(&aio->fd_pool);

    aio->free(aio);
    return (0);
}

/* get userdata
 * @handle -- aio handle
 * return the userdata, default NULL
 */
void *ke_aio_get_user_data(ke_aio_t handle)
{
    void *user_data = NULL;

    if (handle != KE_AIO_INVALID_HANDLE) {
        struct ke_aio *aio = (struct ke_aio *)handle;
        user_data = aio->user_data;
    }
    return (user_data);
}

/* bind userdata
 * @handle -- aio handle
 * return the old userdata
 */
void *ke_aio_set_user_data(ke_aio_t handle, void *user_data)
{
    void* old_ud = NULL;

    if (handle != KE_AIO_INVALID_HANDLE) {
        struct ke_aio *aio = (struct ke_aio *)handle;
        old_ud = aio->user_data;
        aio->user_data = user_data;
    }
    return (old_ud);
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
    int binded = 0;
    SOCKET sock;
    ke_aio_fd_t fd;

    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                      WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET)
        return (KE_AIO_INVALID_FD);

    if (port >= 0 && port <= UINT16_MAX) {
        struct sockaddr_in baddr;

        baddr.sin_family = AF_INET;
        baddr.sin_port = htons(port);
        if (addr)
            baddr.sin_addr = *addr;
        else
            baddr.sin_addr.s_addr = htonl(INADDR_ANY);

        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&addr_reuse,
                   sizeof(addr_reuse));

        if (SOCKET_ERROR == bind(sock, (SOCKADDR *)&baddr, sizeof(baddr))) {
            closesocket(sock);
            return (KE_AIO_INVALID_FD);
        }

        binded = 1;
    }

    if (backlog > 0 && SOCKET_ERROR == listen(sock, backlog)) {
        closesocket(sock);
        return (KE_AIO_INVALID_FD);
    }

    fd = ke_aio_assoc_tcp(handle, sock, binded);
    if (fd == KE_AIO_INVALID_FD)
        closesocket(sock);

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
    ke_aio_fd_t fd;
    HANDLE file_handle;
    DWORD create_flags, access_flags, attr_flags;

#ifdef KE_STRICT_CHECK
    if (!filepath)
        return (KE_AIO_INVALID_FD);
#endif

    create_flags = access_flags = 0;

    if ((flags & O_WRONLY) == O_WRONLY)
        access_flags |= GENERIC_WRITE;
    if ((flags & O_RDONLY) == O_RDONLY)
        access_flags |= GENERIC_READ;
    if ((flags & O_RDWR) == O_RDWR)
        access_flags |= GENERIC_READ | GENERIC_WRITE;

    if ((flags & O_EXCL) == O_EXCL)
        create_flags |= OPEN_EXISTING;
    else if ((flags & O_TRUNC) == O_TRUNC)
        create_flags |= TRUNCATE_EXISTING;
    else if ((flags & O_CREAT) == O_CREAT)
        create_flags |= CREATE_ALWAYS;
    else
        create_flags |= OPEN_EXISTING;

    attr_flags = FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL;

    file_handle = CreateFile(filepath, access_flags, FILE_SHARE_READ,
                             NULL, create_flags, attr_flags, NULL);
    if (file_handle == INVALID_HANDLE_VALUE)
        return (KE_AIO_INVALID_FD);

    fd = ke_aio_assoc_file(handle, file_handle);
    if (fd == KE_AIO_INVALID_FD)
        CloseHandle(file_handle);

    return (fd);
}

#endif

/* associate native socket with aio */
ke_aio_fd_t ke_aio_assoc_tcp(ke_aio_t handle, ke_native_sock_t sock, 
                             int binded)
{
    struct ke_aio_fd *afd;

    afd = (struct ke_aio_fd *)ke_aio_assoc_fd(handle, sock, KE_AIO_FD_TCP);
    if (afd)
        afd->binded = binded;
    return (afd);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* associate native file with aio */
ke_aio_fd_t ke_aio_assoc_file(ke_aio_t handle, ke_native_file_t file)
{
    return ke_aio_assoc_fd(handle, (ke_native_sock_t)file, KE_AIO_FD_FILE);
}

#endif

/* close fd 
 * @fd -- aio fd to close
 * return 0 -- success, else error
 */
int ke_aio_closefd(ke_aio_fd_t fd)
{
    struct ke_aio_fd *afd;

    afd = (struct ke_aio_fd *)fd;
    if (afd->closing)
        return (-1);
    
    /* check refcount */
    if (afd->refcount > 0)
        afd->closing = 1;
    else
        ke_aio_closefd_inner(afd);

    return (0);
}

/* async tcp read
 * return 0 -- success, else error
 */
int ke_aio_tcp_read(ke_aio_fd_t fd, char *buf, int buflen, 
                    void (*on_io_done)(void *, char *, int),
                    void *user_data)
{
    DWORD flags = 0, done = 0, rc;
    struct ke_aio_io_ctx *ioctx;
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio;

    aio = afd->aio;
#ifdef KE_STRICT_CHECK
    if (!on_io_done || !buf || buflen <= 0
        || afd->type != KE_AIO_FD_TCP) {
        aio->errcode = ERROR_INVALID_PARAMETER;
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_io_ctx *)
        ke_lookaside_list_alloc(&aio->io_ctx_pool);
    if (!ioctx) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }

    ioctx->ovrlp.hook = ke_aio_tcp_read_done;
    ioctx->ovrlp.type = KE_AIO_IO;
    ioctx->on_read_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->wsabuf.buf = buf;
    ioctx->wsabuf.len = buflen;
    memset(&ioctx->ovrlp, 0, sizeof(ioctx->ovrlp));

    afd->refcount++;
    rc = WSARecv(afd->sock, &ioctx->wsabuf, 1, &done, &flags,
                 &ioctx->ovrlp.ovrlp, NULL);
    if (rc == SOCKET_ERROR) {
        DWORD errcode = WSAGetLastError();
        if (errcode != WSA_IO_PENDING) {
            aio->errcode = errcode;
            ke_lookaside_list_free(&aio->io_ctx_pool, ioctx);
            afd->refcount--;
            return (-1);
        }
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
    DWORD done = 0, rc;
    struct ke_aio_io_ctx *ioctx;
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio;

    aio = afd->aio;
#ifdef KE_STRICT_CHECK
    if (!on_io_done || !buf || buflen <= 0
        || afd->type != KE_AIO_FD_TCP) {
        aio->errcode = ERROR_INVALID_PARAMETER;
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_io_ctx *)
        ke_lookaside_list_alloc(&aio->io_ctx_pool);
    if (!ioctx) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }

    ioctx->ovrlp.hook = ke_aio_tcp_write_done;
    ioctx->ovrlp.type = KE_AIO_IO;
    ioctx->on_write_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->wsabuf.buf = (char*)buf;
    ioctx->wsabuf.len = buflen;
    memset(&ioctx->ovrlp, 0, sizeof(ioctx->ovrlp));

    afd->refcount++;
    rc = WSASend(afd->sock, &ioctx->wsabuf, 1, &done, 0,
                 &ioctx->ovrlp.ovrlp, NULL);
    if (rc == SOCKET_ERROR) {
        DWORD errcode = WSAGetLastError();
        if (errcode != WSA_IO_PENDING) {
            aio->errcode = errcode;
            ke_lookaside_list_free(&aio->io_ctx_pool, ioctx);
            afd->refcount--;
            return (-1);
        }
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
    struct ke_aio_tcp_accept_ctx *ioctx;
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio;
    DWORD bytes;

    aio = afd->aio;
#ifdef KE_STRICT_CHECK
    if (!on_accept_done || afd->type != KE_AIO_FD_TCP) {
        aio->errcode = ERROR_INVALID_PARAMETER;
        return (-1);
    }
#endif

    if (!afd->acceptex) {
        GUID acceptex_guid = WSAID_ACCEPTEX;
        LPFN_ACCEPTEX acceptex_ptr;
        int err;

        err = WSAIoctl(afd->sock,
                       SIO_GET_EXTENSION_FUNCTION_POINTER,
                       &acceptex_guid, sizeof(acceptex_guid),
                       &acceptex_ptr, sizeof(acceptex_ptr),
                       &bytes, NULL, NULL);
        if (err == SOCKET_ERROR) {
            aio->errcode = WSAGetLastError();
            return (-1);
        }
        afd->acceptex = acceptex_ptr;
    }

    ioctx = (struct ke_aio_tcp_accept_ctx *)
        ke_lookaside_list_alloc(&aio->tcp_accept_ctx_pool);
    if (!ioctx) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }

    ioctx->ovrlp.hook = ke_aio_tcp_accept_done;
    ioctx->ovrlp.type = KE_AIO_IO;
    ioctx->on_accept_done = on_accept_done;
    ioctx->user_data = user_data;

    return ke_aio_accept_inner(afd, ioctx);
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
    GUID connectex_guid = WSAID_CONNECTEX;
    struct ke_aio_tcp_connect_ctx *ioctx;
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    LPFN_CONNECTEX connectex_ptr = NULL;
    struct ke_aio *aio;
    DWORD bytes;
    BOOL succ; 
    int err;

    aio = afd->aio;
#ifdef KE_STRICT_CHECK
    if (!addr || !on_conn_done || afd->type != KE_AIO_FD_TCP) {
        aio->errcode = ERROR_INVALID_PARAMETER;
        return (-1);
    }
#endif
    
    if (afd->connected) {
        aio->errcode = WSAEDISCON;
        return (-1);
    }

    ioctx = (struct ke_aio_tcp_connect_ctx *)
        ke_lookaside_list_alloc(&aio->tcp_connect_ctx_pool);
    if (!ioctx) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }
        
    err = WSAIoctl(afd->sock,
                   SIO_GET_EXTENSION_FUNCTION_POINTER,
                   &connectex_guid, sizeof(connectex_guid),
                   &connectex_ptr, sizeof(connectex_ptr),
                   &bytes, NULL, NULL);

    if (err == SOCKET_ERROR) {
        aio->errcode = WSAGetLastError();
        ke_lookaside_list_free(&aio->tcp_connect_ctx_pool, ioctx);
        return (-1);
    }

    ioctx->ovrlp.hook = ke_aio_tcp_connect_done;
    ioctx->ovrlp.type = KE_AIO_IO;
    ioctx->on_conn_done = on_conn_done;
    ioctx->user_data = user_data;
    memset(&ioctx->ovrlp, 0, sizeof(ioctx->ovrlp));
    memcpy(&ioctx->peer, addr, addrlen);

    if (!afd->binded) {
        SOCKADDR_IN local;

        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = htons(0);

        if (bind(afd->sock, (PSOCKADDR)&local, sizeof(local))) {
            aio->errcode = WSAGetLastError();
            ke_lookaside_list_free(&aio->tcp_connect_ctx_pool, ioctx);
            return (-1);
        }

        afd->binded = 1;
    }

    afd->refcount++;
    succ = connectex_ptr(afd->sock, (struct sockaddr *)&ioctx->peer,
                         addrlen, NULL, 0, &bytes, &ioctx->ovrlp.ovrlp);
    if (!succ) {
        aio->errcode = WSAGetLastError();
        ke_lookaside_list_free(&aio->tcp_connect_ctx_pool, ioctx);
        afd->refcount--;
        return (-1);
    }

    return (0);
}

/* async file read
 * return 0 -- success, else error
 */
int ke_aio_file_read(ke_aio_fd_t fd, char *buf, int buflen, uint64_t off,
                     void (*on_io_done)(void *, char *, int),
                     void *user_data)
{
    struct ke_aio_io_ctx *ioctx;
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio;

    aio = afd->aio;
#ifdef KE_STRICT_CHECK
    if (!on_io_done || !buf || buflen <= 0 
        || afd->type != KE_AIO_FD_FILE) {
        aio->errcode = ERROR_INVALID_PARAMETER;
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_io_ctx *)
        ke_lookaside_list_alloc(&aio->io_ctx_pool);
    if (!ioctx) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }

    ioctx->ovrlp.hook = ke_aio_file_read_done;
    ioctx->ovrlp.type = KE_AIO_IO;
    ioctx->on_read_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->rbuf = buf;
    ioctx->buflen = buflen;
    ioctx->ovrlp.ovrlp.Offset = (DWORD)off;
    ioctx->ovrlp.ovrlp.OffsetHigh = (DWORD)(off >> 32);

    afd->refcount++;
    if (!ReadFile(afd->file, buf, buflen, NULL, &ioctx->ovrlp.ovrlp)) {
        DWORD errcode = GetLastError();
        if (errcode != ERROR_IO_PENDING) {
            aio->errcode = errcode;
            ke_lookaside_list_free(&aio->io_ctx_pool, ioctx);
            afd->refcount--;
            return (-1);
        }
    }

    return (0);
}

/* async file write
 * return 0 -- success, else error
 */
int ke_aio_file_write(ke_aio_fd_t fd, const char *buf, int buflen, uint64_t off,
                      void (*on_io_done)(void *,
                                         const char *, int),
                      void *user_data)
{
    struct ke_aio_io_ctx *ioctx;
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    struct ke_aio *aio;

    aio = afd->aio;
#ifdef KE_STRICT_CHECK
    if (!on_io_done || !buf || buflen <= 0 
        || afd->type != KE_AIO_FD_FILE) {
        aio->errcode = ERROR_INVALID_PARAMETER;
        return (-1);
    }
#endif

    ioctx = (struct ke_aio_io_ctx *)
        ke_lookaside_list_alloc(&aio->io_ctx_pool);
    if (!ioctx) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }

    ioctx->ovrlp.hook = ke_aio_file_write_done;
    ioctx->ovrlp.type = KE_AIO_IO;
    ioctx->on_write_done = on_io_done;
    ioctx->user_data = user_data;
    ioctx->wbuf = buf;
    ioctx->buflen = buflen;
    ioctx->ovrlp.ovrlp.Offset = (DWORD)off;
    ioctx->ovrlp.ovrlp.OffsetHigh = (DWORD)(off >> 32);

    afd->refcount++;
    if (!WriteFile(afd->file, buf, buflen, NULL, &ioctx->ovrlp.ovrlp)) {
        DWORD errcode = GetLastError();
        if (errcode != ERROR_IO_PENDING) {
            aio->errcode = errcode;
            ke_lookaside_list_free(&aio->io_ctx_pool, ioctx);
            afd->refcount--;
            return (-1);
        }
    }

    return (0);
}

/* add close handler on fd
 * @fd -- valid fd
 * @user_data -- argument pass to handler
 * @handler -- handler called when fd closed
 * return 0 -- success, else error
 */
int ke_aio_add_close_handler(ke_aio_fd_t fd, void (*handler)(void *),
                             void *user_data)
{
    struct ke_aio *aio;
    struct ke_aio_fd *afd;
    struct ke_aio_close_handler *ch;

    afd = (struct ke_aio_fd *)fd;
    aio = afd->aio;

    ch = (struct ke_aio_close_handler *)
        ke_lookaside_list_alloc(&aio->close_handler_pool);
    if (!ch) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }

    ch->handler = handler;
    ch->user_data = user_data;
    KE_DLIST_ADD_BACK(&afd->close_handler_lst, &ch->node);
    return (0);
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

/* run loop
 * @actr -- aio 
 */
void ke_aio_run(ke_aio_t handle)
{
    DWORD timeout = (DWORD)-1;
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;

#ifdef KE_STRICT_CHECK
    if (!aio->iocp) {
        aio->errcode = ERROR_INVALID_PARAMETER;
        return;
    }
#endif

    while (!aio->shutdown) {
        BOOL succ;
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED ovrlp = NULL;
        struct ke_aio_fd *afd;
        struct ke_aio_ovrlp *pwovrlp;
        int fail_packet = 0;
        int err = KE_AIO_POLL_SUCCESS;

        if (aio->before_poll)
            timeout = aio->before_poll(aio->data1);

        if (timeout == -1)
            timeout = KE_AIO_DEFAULT_POLL_TIMEOUT;

        succ = GetQueuedCompletionStatus(aio->iocp, &bytes, &key,
                                         &ovrlp, timeout);
        if (!succ) {
            if (!ovrlp) {
                err = KE_AIO_POLL_TIMEOUT;
                /* MSDN -- ERROR_ABANDONED_WAIT_0 
                 * err = KE_AIO_POLL_FAILED;
                 */
            } else {
                fail_packet = 1;
            }
        }
        
        if (err == KE_AIO_POLL_SUCCESS && ovrlp) {
            pwovrlp = KE_MEM_TO_TYPE_PTR(struct ke_aio_ovrlp,
                                      ovrlp, ovrlp);
            
            if (pwovrlp->type == KE_AIO_IO) {
                afd = (struct ke_aio_fd *)key;
                pwovrlp->hook(pwovrlp, afd, bytes, fail_packet);
                
                afd->refcount--;
                assert(afd->refcount >= 0);

                if (afd->refcount == 0 && afd->closing)
                    ke_aio_closefd_inner(afd);
                
            } else if (pwovrlp->type == KE_AIO_TASK) {
                pwovrlp->task((void *)key);
                ke_lookaside_list_free(&aio->task_ovrlp_pool, pwovrlp);
            }
        }

        if (aio->after_poll)
            aio->after_poll(aio->data2, err);
    }
}

/* post an shutdown message
 * @handle -- aio to shutdown
 * return 0 -- success, else error
 */
int ke_aio_notify_exit(ke_aio_t handle)
{
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;
    aio->shutdown = 1;
    return PostQueuedCompletionStatus(aio->iocp, 0, 0, NULL) ? 0 : -1;
}

/* wakeup the thread which is waiting on aio
 * @handle -- aio
 * return 0 -- success, else error
 */
int ke_aio_wakeup(ke_aio_t handle)
{
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;
    return PostQueuedCompletionStatus(aio->iocp, 0, 0, NULL) ? 0 : -1;
}

/* post task 
 * @handle -- aio
 * @task -- the handler of task
 * @user_data -- user data pass to as the second argument
 * return 0 -- success, else error
 */
int ke_aio_post_task(ke_aio_t handle, void (*task)(void *), void *user_data)
{
    struct ke_aio *aio;
    struct ke_aio_ovrlp *pwovrlp;

    aio = (struct ke_aio *)handle;
    pwovrlp = (struct ke_aio_ovrlp *)
        ke_lookaside_list_alloc(&aio->task_ovrlp_pool);
    if (!pwovrlp) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (-1);
    }

    pwovrlp->task = task;
    pwovrlp->type = KE_AIO_TASK;
    if (PostQueuedCompletionStatus(aio->iocp, 0, (ULONG_PTR)user_data,
                                   &pwovrlp->ovrlp))
        return (0);

    aio->errcode = GetLastError();
    ke_lookaside_list_free(&aio->task_ovrlp_pool, pwovrlp);
    return (-1);
}

/* get native socket */
ke_native_sock_t ke_aio_get_native_socket(ke_aio_fd_t fd)
{
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    if (afd->type != KE_AIO_FD_TCP) {
        afd->aio->errcode = ERROR_INVALID_PARAMETER;
        return (INVALID_SOCKET);
    }
    return (afd->sock);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* get native file */
ke_native_file_t ke_aio_get_native_file(ke_aio_fd_t fd)
{
    struct ke_aio_fd *afd = (struct ke_aio_fd *)fd;
    if (afd->type != KE_AIO_FD_FILE) {
        afd->aio->errcode = ERROR_INVALID_PARAMETER;
        return (INVALID_HANDLE_VALUE);
    }
    return (afd->file);
}

#endif

ke_native_errno_t ke_aio_errno(ke_aio_t handle)
{
    struct ke_aio *aio = (struct ke_aio *)handle;
    return (aio->errcode);
}

struct ke_aio_fd *
ke_aio_create_fd(struct ke_aio *aio)
{
    struct ke_aio_fd *afd;

    afd = (struct ke_aio_fd *)ke_lookaside_list_calloc(&aio->fd_pool);
    if (afd) {
        afd->aio = aio;
        KE_DLIST_INIT(&afd->close_handler_lst);
        afd->type = KE_AIO_FD_UNKNOWN;
    } else {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
    }
    return (afd);
}

void ke_aio_closefd_inner(struct ke_aio_fd *afd)
{
    ke_aio_clear_close_handler_list(afd);

    switch (afd->type) {
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    case KE_AIO_FD_FILE:
        CloseHandle(afd->file);
        break;
#endif
    case KE_AIO_FD_TCP:
        closesocket(afd->sock);
        break;
    }

    ke_lookaside_list_free(&afd->aio->fd_pool, afd);
}

void ke_aio_clear_close_handler_list(struct ke_aio_fd *afd)
{
    while (KE_DLIST_LEN(&afd->close_handler_lst) > 0) {
        struct ke_aio_close_handler *closehandler;
        closehandler = KE_MEM_TO_TYPE_PTR(struct ke_aio_close_handler, node,
                                       KE_DLIST_FRONT(&afd->close_handler_lst));
        KE_DLIST_DEL_FRONT(&afd->close_handler_lst);
        closehandler->handler(closehandler->user_data);
        ke_lookaside_list_free(&afd->aio->close_handler_pool, closehandler);
    }
}

ke_aio_fd_t ke_aio_assoc_fd(ke_aio_t handle, ke_native_sock_t sock, int type)
{
    struct ke_aio_fd *afd;
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;
#ifdef KE_STRICT_CHECK
    if (sock == INVALID_SOCKET)
        return (NULL);
#endif

    afd = ke_aio_create_fd(aio);
    if (!afd) {
        aio->errcode = ERROR_NO_SYSTEM_RESOURCES;
        return (NULL);
    }

    if (aio->iocp != CreateIoCompletionPort((HANDLE)sock, aio->iocp,
                                           (ULONG_PTR)afd, 0)) {
        aio->errcode = GetLastError();
        ke_aio_closefd(afd);
        return (NULL);
    }
    
    afd->sock = sock;
    afd->type = type;
    return (afd);
}

void ke_aio_tcp_accept_done(void *user_data, ke_aio_fd_t fd, int bytes,
                            int err) 
{
    GUID get_acceptex_sockaddrs_guid = WSAID_GETACCEPTEXSOCKADDRS;
    LPFN_GETACCEPTEXSOCKADDRS get_acceptex_sockaddrs = NULL;
    struct ke_aio_tcp_accept_ctx *ioctx;
    struct ke_aio_fd *afd;
    DWORD rc;

    ioctx = (struct ke_aio_tcp_accept_ctx *)user_data;
    afd = (struct ke_aio_fd *)fd;

    err = WSAIoctl(ioctx->cli_sock, 
                   SIO_GET_EXTENSION_FUNCTION_POINTER,
                   &get_acceptex_sockaddrs_guid, 
                   sizeof(get_acceptex_sockaddrs_guid),
                   &get_acceptex_sockaddrs, 
                   sizeof(get_acceptex_sockaddrs),
                   &rc, NULL, NULL);

    if (err != SOCKET_ERROR) {
        assert(get_acceptex_sockaddrs != NULL);

        err = setsockopt(ioctx->cli_sock, SOL_SOCKET, 
                         SO_UPDATE_ACCEPT_CONTEXT, 
                         (char *)&ioctx->cli_sock, 
                         sizeof(ioctx->cli_sock));

        if (err != SOCKET_ERROR) {
            INT local_len, remote_len;
            PSOCKADDR local = NULL, remote = NULL;

            get_acceptex_sockaddrs(ioctx->addr_buf, 0, 
                                   ADDRLEN, ADDRLEN, 
                                   &local, &local_len, 
                                   &remote, &remote_len);
        }
    } 
    
    if (err == SOCKET_ERROR){
        closesocket(ioctx->cli_sock);
        err = ioctx->on_accept_done(ioctx->user_data, INVALID_SOCKET, NULL, 0);
    } else {
        err = ioctx->on_accept_done(ioctx->user_data, ioctx->cli_sock,
                                    (struct sockaddr *)&ioctx->addr_buf[0],
                                    sizeof(struct sockaddr_in));
    }

    if (err != 0) {
        /* accept automatic when err not 0 */
        if (!ke_aio_accept_inner(afd, ioctx))
            return;

        /* notify user when accept failed */
        ioctx->on_accept_done(ioctx->user_data, INVALID_SOCKET, NULL, 0);
    }

    /* free ioctx when:
     * 1, no need to accept automatic
     * 2, accept automatic failed
     */
    ke_lookaside_list_free(&afd->aio->tcp_accept_ctx_pool, ioctx);
}

void ke_aio_tcp_connect_done(void *user_data, ke_aio_fd_t fd, int bytes,
                             int err) 
{
    int seconds;
    struct ke_aio_fd *afd;
    struct ke_aio_tcp_connect_ctx *ioctx;

    afd = (struct ke_aio_fd *)fd;
    ioctx = (struct ke_aio_tcp_connect_ctx *)user_data;

    setsockopt(afd->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

    err = getsockopt(afd->sock, SOL_SOCKET, SO_CONNECT_TIME, 
                     (char *)&seconds, &bytes);

    if (err == NO_ERROR && seconds != -1)
        ioctx->on_conn_done(ioctx->user_data, 0);
    else
        ioctx->on_conn_done(ioctx->user_data, -1);

    ke_lookaside_list_free(&afd->aio->tcp_connect_ctx_pool, ioctx);
}

void ke_aio_tcp_read_done(void *user_data, ke_aio_fd_t fd, int bytes, int err) 
{
    struct ke_aio_fd *afd;
    struct ke_aio_io_ctx *ioctx;

    afd = (struct ke_aio_fd *)fd;
    ioctx = (struct ke_aio_io_ctx *)user_data;
    ioctx->on_read_done(ioctx->user_data, ioctx->wsabuf.buf,
                        err ? -1 : bytes);
    ke_lookaside_list_free(&afd->aio->io_ctx_pool, ioctx);
}

void ke_aio_tcp_write_done(void *user_data, ke_aio_fd_t fd,    int bytes, int err) 
{
    /* write(..., buf, 1024, ...)
     * ...
     * callback(..., bytes=512, err!=0)
     * ...
     * user_callback(..., -1)
     * we don't report the bytes when err is set
     * -1 indicate error
     */
    struct ke_aio_fd *afd;
    struct ke_aio_io_ctx *ioctx;

    afd = (struct ke_aio_fd *)fd;
    ioctx = (struct ke_aio_io_ctx *)user_data;
    ioctx->on_write_done(ioctx->user_data, ioctx->wsabuf.buf,
                         err ? -1 : bytes);
    ke_lookaside_list_free(&afd->aio->io_ctx_pool, ioctx);
}

void ke_aio_file_read_done(void *user_data, ke_aio_fd_t fd,    int bytes, int err) 
{
    struct ke_aio_fd *afd;
    struct ke_aio_io_ctx *ioctx;

    afd = (struct ke_aio_fd *)fd;
    ioctx = (struct ke_aio_io_ctx *)user_data;

    ioctx->on_read_done(ioctx->user_data, ioctx->rbuf,
                        err ? -1 : bytes);
    ke_lookaside_list_free(&afd->aio->io_ctx_pool, ioctx);
}

void ke_aio_file_write_done(void *user_data, ke_aio_fd_t fd,
                            int bytes, int err) 
{
    struct ke_aio_fd *afd;
    struct ke_aio_io_ctx *ioctx;

    afd = (struct ke_aio_fd *)fd;
    ioctx = (struct ke_aio_io_ctx *)user_data;

    ioctx->on_write_done(ioctx->user_data, ioctx->wbuf,
                         err ? -1 : bytes);
    ke_lookaside_list_free(&afd->aio->io_ctx_pool, ioctx);
}

int ke_aio_accept_inner(struct ke_aio_fd *afd,
                        struct ke_aio_tcp_accept_ctx *ioctx)
{
    BOOL succ;
    SOCKET sock;
    DWORD bytes;
    struct ke_aio *aio = afd->aio;

RETRY:
    memset(&ioctx->ovrlp, 0, sizeof(ioctx->ovrlp));
    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0,
                      WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        aio->errcode = WSAGetLastError();
        ke_lookaside_list_free(&aio->tcp_accept_ctx_pool, ioctx);
        return (-1);
    }

    afd->refcount++;
    ioctx->cli_sock = sock;
    succ = afd->acceptex(afd->sock, sock, ioctx->addr_buf, 0, ADDRLEN,
                         ADDRLEN, &bytes, &ioctx->ovrlp.ovrlp);
    if (!succ) {
        DWORD errcode = WSAGetLastError();
        if (errcode == WSAECONNRESET) {
            closesocket(sock);
            afd->refcount--;
            goto RETRY;
        }

        if (errcode != WSA_IO_PENDING) {
            aio->errcode = errcode;
            closesocket(sock);
            ke_lookaside_list_free(&aio->tcp_accept_ctx_pool, ioctx);
            afd->refcount--;
            return (-1);
        }
    }

    return (0);
}
