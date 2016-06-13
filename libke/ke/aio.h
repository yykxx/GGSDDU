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

#ifndef _KE_AIO_H
#define _KE_AIO_H

#include "ke/defs.h"

/* fd type */
#define KE_AIO_FD_UNKNOWN    0
#define KE_AIO_FD_TCP        1
#ifdef KE_AIO_ENABLE_REGULAR_FILE
#define KE_AIO_FD_FILE       2
#endif

/* poll state */
#define KE_AIO_POLL_SUCCESS    0
#define KE_AIO_POLL_TIMEOUT    1

#define KE_AIO_INVALID_FD   NULL

#ifdef __cplusplus
extern "C" {
#endif

typedef void *ke_aio_t;
typedef void *ke_aio_fd_t;

struct ke_aio_config {
    int32_t free_close_handler; 
    int32_t free_fd;
    int32_t free_io_ctx;
    int32_t free_task;
#if defined(_WIN32) || defined(_WIN64)
    int32_t free_accept_ctx;
    int32_t free_connect_ctx;
#else
    int32_t free_file_io_task;
#endif
    
    int (*before_poll)(void *);
    void *before_poll_user_data;
    
    void (*after_poll)(void *, int);
    void *after_poll_user_data;
    
    void *(*alloc)(size_t);
    void (*free)(void *);
};

/* create aio
 * return NULL -- error, else success
 */    
ke_aio_t ke_aio_create();

/* create aio
 * @handle -- aio handle 
 * @config -- aio config 
 * return 0 -- success, else error
 */
int ke_aio_init(ke_aio_t handle, const struct ke_aio_config* config);
    
/* close aio
 * @handle -- aio handle
 * return 0 -- success, else error
 */
int ke_aio_close(ke_aio_t handle);

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
                                 int addr_reuse);

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* create file fd
 * @handle -- aio handle   
 * @filepath -- file path
 * @flags -- O_XXX
 * @mode -- S_XXX
 * return NULL -- error, else success
 */
ke_aio_fd_t ke_aio_create_file_fd(ke_aio_t handle, const char *filepath,
                                  int flags, mode_t mode);

#endif

/* associate native tcp socket with aio
 * @handle -- aio handle
 * @sock -- native tcp socket 
 * @binded -- is socket binded
 * return NULL -- error, else success 
 */
ke_aio_fd_t ke_aio_assoc_tcp(ke_aio_t handle, ke_native_sock_t sock,
                             int binded);

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* associate native file with aio
 * @handle -- aio handle
 * @file -- native file 
 * return NULL -- error, else success 
 */
ke_aio_fd_t ke_aio_assoc_file(ke_aio_t handle, ke_native_file_t file);

#endif

/* close fd 
 * @fd -- aio fd 
 * return 0 -- success, else error
 */
int ke_aio_closefd(ke_aio_fd_t fd);

/* async tcp read
 * return 0 -- success, else error
 */
int ke_aio_tcp_read(ke_aio_fd_t fd, char *buf, int buflen, 
                    void (*on_io_done)(void *, char *, int),
                    void *user_data);

/* async tcp write
 * return 0 -- success, else error
 */
int ke_aio_tcp_write(ke_aio_fd_t fd, const char *buf, int buflen, 
                     void (*on_io_done)(void *, const char *, int),
                     void *user_data);
/* async tcp accept
 * return 0 -- success, else error
 */
int ke_aio_tcp_accept(ke_aio_fd_t fd,
                      int (*on_accept_done)(void *, ke_native_sock_t,
                                            struct sockaddr *, socklen_t),
                      void *user_data);

/* async tcp connect
 * on_conn_done(user_data, is_error)
 * return 0 -- success, else error
 */
int ke_aio_tcp_connect(ke_aio_fd_t fd,
                       struct sockaddr *addr, socklen_t addrlen, 
                       void (*on_conn_done)(void *, int),
                       void *user_data);

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* async file read
 * return 0 -- success, else error
 */
int ke_aio_file_read(ke_aio_fd_t fd, char *buf, int buflen, uint64_t off,
                     void (*on_io_done)(void *, char *, int),
                     void *user_data);
    
/* async file write
 * return 0 -- success, else error
 */
int ke_aio_file_write(ke_aio_fd_t fd, const char *buf, int buflen, uint64_t off,
                      void (*on_io_done)(void *, const char *, int),
                      void *user_data);

#endif

/* add close handler on fd
 * @fd -- valid fd
 * @user_data -- argument pass to handler
 * @handler -- handler called when fd closed
 * return 0 -- success, else error
 */
int ke_aio_add_close_handler(ke_aio_fd_t fd, void (*handler)(void *),
                             void *user_data);

/* remove close handler on fd
 * @fd -- valid fd
 * @user_data -- argument pass to handler
 * @handler -- handler called when fd closed
 */
void ke_aio_rem_close_handler(ke_aio_fd_t fd, void (*handler)(void *),
                              void *user_data);

/* clear close handler on fd */
void ke_aio_clear_close_handler(ke_aio_fd_t fd);

/* run loop
 * @actr -- aio 
 */
void ke_aio_run(ke_aio_t handle);

/* notify run loop to break
 * @handle -- aio to shutdown
 * return 0 -- success, else error
 */
int ke_aio_notify_exit(ke_aio_t handle);

/* wakeup IO thread
 * @handle -- aio
 * return 0 -- success, else error
 */
int ke_aio_wakeup(ke_aio_t handle);

/* post task
 * @handle -- aio
 * @task -- the handler of task
 * @user_data -- user data pass to as the second argument
 * return 0 -- success, else error
 */
int ke_aio_post_task(ke_aio_t handle, void (*task)(void *), void *user_data);

/* get native socket */
ke_native_sock_t ke_aio_get_native_socket(ke_aio_fd_t fd);

#ifdef KE_AIO_ENABLE_REGULAR_FILE

/* get native file */
ke_native_file_t ke_aio_get_native_file(ke_aio_fd_t fd);

#endif

ke_native_errno_t ke_aio_errno(ke_aio_t handle);

#ifdef __cplusplus
}
#endif

#endif
