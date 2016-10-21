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

#ifndef _KE_AIO_H
#define _KE_AIO_H

#include "ke/defs.h"

/* fd type */
#define KE_AIO_FD_UNKNOWN    0
#define KE_AIO_FD_TCP        1
#define KE_AIO_FD_FILE       2

/* poll state */
#define KE_AIO_POLL_SUCCESS   0
#define KE_AIO_POLL_TIMEOUT   1

#define KE_AIO_INVALID_FD     NULL

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
    
    int (*before_poll)(ke_aio_t, void *);
    void *before_poll_user_data;
    
    void (*after_poll)(ke_aio_t, void *, int);
    void *after_poll_user_data;
    
    void *(*alloc)(size_t);
    void (*free)(void *);
};

/* create aio
 * @handle [out] -- hold the result aio handle
 * @config [in] -- common configure for aio
 * return 0 -- success, else error
 */    
ke_native_errno_t 
ke_aio_create(ke_aio_t *handle, const struct ke_aio_config *config);

/* close aio
 * @handle [in] -- aio handle
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_close(ke_aio_t handle);

/* get userdata
 * @handle [in] -- aio handle
 * return the userdata, default NULL
 */
void *
ke_aio_get_user_data(ke_aio_t handle);

/* bind userdata
 * @handle [in] -- aio handle
 * @user_data [in] -- user data
 * return the old userdata
 */
void *
ke_aio_set_user_data(ke_aio_t handle, void *user_data);

/* associate native tcp socket with aio
 * @fd [out] -- hold aio tcp fd
 * @handle [in] -- aio handle
 * @sock [in] -- native tcp socket 
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_assoc_tcp(ke_aio_fd_t *fd, ke_aio_t handle, ke_native_sock_t sock);

/* associate native file with aio
 * @fd [out] -- hold aio file fd
 * @handle [in] -- aio handle
 * @file [in] -- native file 
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_assoc_file(ke_aio_fd_t *fd, ke_aio_t handle, ke_native_file_t file);

/* close fd 
 * @fd [in] -- aio fd 
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_closefd(ke_aio_fd_t fd);

/* async tcp read
 * @fd [in] -- valid aio tcp fd
 * @buf [out] -- buffer to hold data read from fd
 * @buflen [in] -- the length of buffer
 * @on_io_done [in] -- the notify callback on_io_done(user_data, buf, len)
 * @user_data [in] -- user data pass to on_io_done
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_tcp_read(ke_aio_fd_t fd, char *buf, int buflen, 
                void (*on_io_done)(void *, char *, int),
                void *user_data);

/* async tcp write
 * @fd [in] -- valid aio tcp fd
 * @buf [in] -- buffer to hold data read from fd
 * @buflen [in] -- the length of buffer
 * @on_io_done [in] -- notify callback on_io_done(user_data, buf, len)
 * @user_data [in] -- user data pass to on_io_done
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_tcp_write(ke_aio_fd_t fd, const char *buf, int buflen, 
                 void (*on_io_done)(void *, const char *, int),
                 void *user_data);

/* async tcp accept
 * @fd [in] -- valid aio tcp fd
 * @on_accept_done [in] -- notify callback 
 *    on_accept_done(user_data, client_sock, addr, addrlen)
 * @user_data -- user data pass to on_accept_done
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_tcp_accept(ke_aio_fd_t fd,
                  int (*on_accept_done)(void *, ke_native_sock_t,
                                        struct sockaddr *, socklen_t),
                  void *user_data);

/* async tcp connect
 * @fd [in] -- valid aio tcp fd
 * @addr [in] -- address of peer
 * @addrlen [in] -- length of address
 * @on_conn_done [in] -- notify callback on_conn_done(user_data, is_connected)
 * @user_data [in] -- user data pass to on_conn_done
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_tcp_connect(ke_aio_fd_t fd,
                   const struct sockaddr *addr, socklen_t addrlen,
                   void (*on_conn_done)(void *, int),
                   void *user_data);

/* async file read
 * @fd [in] -- valid aio file fd
 * @buf [out] -- buffer to hold data read from fd
 * @buflen [in] -- length of buffer
 * @off [in] -- read offset
 * @on_io_done [in] -- notify callback, on_io_done(user_data, buf, len)
 * @user_data [in] -- user data pass to on_io_done
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_file_read(ke_aio_fd_t fd, char *buf, int buflen, uint64_t off,
                 void (*on_io_done)(void *, char *, int),
                 void *user_data);
    
/* async file write
 * @fd [in] -- valid aio file fd
 * @buf [in] -- data to write
 * @buflen [in] -- length of buffer
 * @off [in] -- write offset
 * @on_io_done [in] -- notify callback, on_io_done(user_data, buf, len)
 * @user_data [in] -- user data pass to on_io_done
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_file_write(ke_aio_fd_t fd, const char *buf, int buflen, uint64_t off,
                  void (*on_io_done)(void *, const char *, int), 
                  void *user_data);

/* add close handler on fd
 * @fd [in] -- valid aio fd
 * @handler [in] -- handler called when fd closed
 * @user_data [in] -- user data pass to handler
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_add_close_handler(ke_aio_fd_t fd, void (*handler)(void *),
                         void *user_data);

/* remove close handler on fd
 * @fd [in] -- valid aio fd
 * @handler [in] -- handler called when fd closed
 * @user_data [in] -- user_data pass to handler
 * return 0 -- success, else error
 */
ke_native_errno_t 
ke_aio_rem_close_handler(ke_aio_fd_t fd, void (*handler)(void *), 
                         void *user_data);

/* clear close handler on fd 
 * @fd [in] -- valid aio fd
 */
void 
ke_aio_clear_close_handler(ke_aio_fd_t fd);

/* run loop
 * @handle [in] -- valid aio handle
 */
void 
ke_aio_run(ke_aio_t handle);

/* notify run loop to exit
 * @handle [in] -- valid aio handle
 * return 0 -- success, else error
 */
ke_native_errno_t 
ke_aio_notify_exit(ke_aio_t handle);

/* wakeup IO thread
 * @handle [in] -- valid aio handle
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_wakeup(ke_aio_t handle);

/* post task
 * @handle [in] -- valid aio handle
 * @task [in] -- the handler of task
 * @user_data [in] -- user data pass to task handler
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_post_task(ke_aio_t handle, void (*task)(void *), void *user_data);

/* get native socket 
 * @sock [out] -- hold the native socket handle
 * @fd [in] -- valid aio fd
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_get_native_socket(ke_native_sock_t *sock, ke_aio_fd_t fd);

/* get native file 
 * @file [out] -- hold the native file handle
 * @fd [in] -- valid aio fd
 * return 0 -- success, else error
 */
ke_native_errno_t
ke_aio_get_native_file(ke_native_file_t *file, ke_aio_fd_t fd);

#ifdef __cplusplus
}
#endif

#endif
