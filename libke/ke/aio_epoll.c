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

#ifdef KE_AIO_ENABLE_REGULAR_FILE
#define _GNU_SOURCE
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#endif

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/epoll.h>

#define KE_IO_EVENT_MAX_COUNT 64

struct ke_aio_epoll {
    int epoll_fd;
    int wakeup_pipe_fd[2];

#ifdef KE_AIO_ENABLE_REGULAR_FILE
    int aio_event_fd;
    aio_context_t aio_ctx;
    struct ke_lookaside_list file_io_task_pool;
#endif
};

#ifdef KE_AIO_ENABLE_REGULAR_FILE

struct ke_aio_file_io_task {
    struct ke_aio_ioctx *ioctx;
    int result_len;
};

static int io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}

static int io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}

static int io_getevents(aio_context_t ctx, long min_nr, long nr,
                        struct io_event *events, struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}

static int io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}

static int eventfd()
{
    return syscall(SYS_eventfd, 0);
}

#endif

static int ke_aio_disable_wakeup(ke_aio_t);

static void ke_aio_close_poller(void* data)
{
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    aio_context_t nullctx;
#endif
    struct ke_aio_epoll *poller;

    poller = (struct ke_aio_epoll *)data;
    if (!poller)
        return;

    if (poller->wakeup_pipe_fd[0] != -1) {
        close(poller->wakeup_pipe_fd[0]);
        poller->wakeup_pipe_fd[0] = -1;
    }

    if (poller->wakeup_pipe_fd[1] != -1) {
        close(poller->wakeup_pipe_fd[1]);
        poller->wakeup_pipe_fd[1] = -1;
    }

#ifdef KE_AIO_ENABLE_REGULAR_FILE
    memset(&nullctx, 0, sizeof(nullctx));
    if (memcmp(&poller->aio_ctx, &nullctx, sizeof(poller->aio_ctx)))
        io_destroy(poller->aio_ctx);

    if (poller->aio_event_fd != -1) {
        close(poller->aio_event_fd);
        poller->aio_event_fd = -1;
    }
#endif

    if (poller->epoll_fd != -1) {
        close(poller->epoll_fd);
        poller->epoll_fd = -1;
    }

#ifdef KE_AIO_ENABLE_REGULAR_FILE
    ke_lookaside_list_destroy(&poller->file_io_task_pool);
#endif

    free(poller);
}

static void *ke_aio_create_poller(struct ke_aio *aio,
                                  const struct ke_aio_config *config)
{
#ifdef KE_AIO_ENABLE_REGULAR_FILE
    int n = 1;
    struct epoll_event ev;
#endif
    struct ke_aio_epoll *poller;

    poller = calloc(0, sizeof(*poller));
    if (!poller) {
        KE_AIO_SET_ERRNO(aio);
        return (NULL);
    }

    poller->wakeup_pipe_fd[0] = -1;
    poller->wakeup_pipe_fd[1] = -1;
    poller->epoll_fd = -1;

#ifdef KE_AIO_ENABLE_REGULAR_FILE
    poller->aio_event_fd = -1;
    ke_lookaside_list_init(&poller->file_io_task_pool,
                           config->free_file_io_task,
                           sizeof(struct ke_aio_file_io_task), -1,
                           config->alloc, config->free);
#endif

    poller->epoll_fd = epoll_create(20480);
    if (poller->epoll_fd == -1) {
        KE_AIO_SET_ERRNO(aio);
        ke_aio_close_poller(poller);
        return (NULL);
    }

#ifdef KE_AIO_ENABLE_REGULAR_FILE
    poller->aio_event_fd = eventfd();
    if (poller->aio_event_fd == -1) {
        KE_AIO_SET_ERRNO(aio);
        ke_aio_close_poller(poller);        
        return (NULL);
    }

    if (ioctl(poller->aio_event_fd, FIONBIO, &n) == -1) {
        KE_AIO_SET_ERRNO(aio);
        ke_aio_close_poller(poller);        
        return (NULL);
    }

    if (io_setup(KE_IO_EVENT_MAX_COUNT, &poller->aio_ctx) < 0) {
        KE_AIO_SET_ERRNO(aio);
        ke_aio_close_poller(poller);
        return (NULL);
    }
#endif

    if (pipe(poller->wakeup_pipe_fd) < 0) {
        KE_AIO_SET_ERRNO(aio);
        ke_aio_close_poller(poller);        
        return (NULL);
    }

#ifdef KE_AIO_ENABLE_REGULAR_FILE
    memset(&ev, 0, sizeof(ev));    
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = &poller->aio_event_fd;

    if (epoll_ctl(poller->epoll_fd, EPOLL_CTL_ADD, poller->aio_event_fd,
                  &ev) < 0) {
        KE_AIO_SET_ERRNO(aio);
        ke_aio_close_poller(poller);
        return (NULL);
    }
#endif

    return (poller);
}

static int ke_aio_epoll_ctl(struct ke_aio_epoll *poller,
                            struct ke_aio_fd *afd, int event_type)
{
    int err = 0;
    int fd = afd->fd;
    struct epoll_event ev;

    ev.data.ptr = afd;
    ev.events = 0;

    if ((afd->events & EPOLLIN) == EPOLLIN)
        ev.events |= EPOLLIN;

    if ((afd->events & EPOLLOUT) == EPOLLOUT)
        ev.events |= EPOLLOUT;

    ev.events |= event_type;

    if (afd->events != ev.events) {
        int ctl_mod;

        if (ev.events == 0)
            ctl_mod = EPOLL_CTL_DEL;
        else if (afd->events)
            ctl_mod = EPOLL_CTL_MOD;
        else
            ctl_mod = EPOLL_CTL_ADD;

        err = epoll_ctl(poller->epoll_fd, ctl_mod, fd, &ev);
        if (err)
            KE_AIO_SET_ERRNO(afd->aio);
        else
            afd->events = ev.events;
    }

    return (err);
}

static int ke_aio_set_read_event(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    return ke_aio_epoll_ctl(afd->aio->poller, afd, EPOLLIN);
}

static int ke_aio_set_write_event(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    return ke_aio_epoll_ctl(afd->aio->poller, afd, EPOLLOUT);
}

static int ke_aio_set_accept_event(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    return ke_aio_epoll_ctl(afd->aio->poller, afd, EPOLLIN);
}

static int ke_aio_set_connect_event(struct ke_aio_ioctx *ioctx)
{
    struct ke_aio_fd *afd = ioctx->afd;
    return ke_aio_epoll_ctl(afd->aio->poller, afd, EPOLLOUT);
}

#ifdef KE_AIO_ENABLE_REGULAR_FILE

static int ke_aio_submit(struct ke_aio_ioctx *ioctx, uint64_t off, int io_type)
{
    struct iocb iocb[1];
    struct iocb *iocbp = &iocb[0];
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio_epoll *poller = afd->aio->poller;
    
    memset(&iocb, 0, sizeof(iocb));
    iocb[0].aio_data = (uintptr_t)ioctx;
    iocb[0].aio_fildes = afd->fd;
    iocb[0].aio_buf = (uintptr_t)ioctx->rbuf;
    iocb[0].aio_nbytes = ioctx->buflen;
    iocb[0].aio_offset = off;
    iocb[0].aio_flags = IOCB_FLAG_RESFD;
    iocb[0].aio_resfd = poller->aio_event_fd;
    iocb[0].aio_lio_opcode = io_type;

    if (io_submit(poller->aio_ctx, 1, &iocbp) == 1) {
        afd->refcount++;
        return (0);
    }
    return (-1);        
}

static void ke_aio_report_file_read_done_task(void *user_data)
{
    struct ke_aio_file_io_task *task = user_data;
    struct ke_aio_ioctx *ioctx = task->ioctx;
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio *aio = afd->aio;
    struct ke_aio_epoll *poller = aio->poller;
    
    ioctx->on_read_done(ioctx->user_data, ioctx->rbuf, task->result_len);
    afd->refcount--;

    ke_lookaside_list_free(&poller->file_io_task_pool, task);
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);

    if (afd->refcount == 0 && afd->closed)
        ke_aio_closefd_internal(afd);
}

static void ke_aio_report_file_write_done_task(void *user_data)
{
    struct ke_aio_file_io_task *task = user_data;
    struct ke_aio_ioctx *ioctx = task->ioctx;
    struct ke_aio_fd *afd = ioctx->afd;
    struct ke_aio *aio = afd->aio;
    struct ke_aio_epoll *poller = aio->poller;
    
    ioctx->on_write_done(ioctx->user_data, ioctx->wbuf, task->result_len);
    ioctx->afd->refcount--;

    ke_lookaside_list_free(&poller->file_io_task_pool, task);
    ke_lookaside_list_free(&aio->ioctx_pool, ioctx);

    if (afd->refcount == 0 && afd->closed)
        ke_aio_closefd_internal(afd);
}

static void ke_aio_handle_file_event(struct ke_aio *aio)
{
    ssize_t n;
    uint64_t ready = 0;
    struct timespec ts;
    struct io_event events[KE_IO_EVENT_MAX_COUNT];
    struct ke_aio_epoll *poller = aio->poller;
    
    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    n = read(poller->epoll_fd, &ready, sizeof(ready));
    if (n != sizeof(ready))
        return;
    
    while (ready) {
        int i, nevts;

        nevts = io_getevents(poller->aio_ctx, 1, KE_IO_EVENT_MAX_COUNT, 
                             events, &ts);

        if (nevts == 0)
            break;
        
        if (nevts < 0)
            break;

        ready -= nevts;
        
        for (i = 0; i < nevts; i++) {
            struct ke_aio_file_io_task *task;
            struct ke_aio_ioctx *ioctx;

            ioctx = (struct ke_aio_ioctx *)events[i].data;
            task = ke_lookaside_list_alloc(&poller->file_io_task_pool);
            if (task) {
                task->result_len = events[i].res;
                task->ioctx = ioctx;
                if (ioctx->io_type == KAT_FILE_READ) {
                    ke_aio_post_task(aio, ke_aio_report_file_read_done_task,
                                     task);
                } else if (ioctx->io_type == KAT_FILE_WRITE) {
                    ke_aio_post_task(aio, ke_aio_report_file_write_done_task,
                                     task);
                }
            } /* end if */
        } /* end for */
    } /* end while */
}

static int ke_aio_submit_read(struct ke_aio_ioctx *ioctx, uint64_t off)
{
    return ke_aio_submit(ioctx, off, IOCB_CMD_PREAD);
}

static int ke_aio_submit_write(struct ke_aio_ioctx *ioctx, uint64_t off)
{
    return ke_aio_submit(ioctx, off, IOCB_CMD_PWRITE);    
}

#endif

static void ke_aio_report_error_event(struct ke_aio_fd *afd)
{
    struct ke_aio_ioctx *ioctx;

    while (KE_QUEUE_LEN(&afd->read_ioctx_queue) > 0) {
        ioctx = (struct ke_aio_ioctx *)KE_QUEUE_FRONT(&afd->read_ioctx_queue);
        KE_QUEUE_POP(&afd->read_ioctx_queue);
        ke_aio_error_event_handler(ioctx);
    }

    while (KE_QUEUE_LEN(&afd->write_ioctx_queue) > 0) {
        ioctx = (struct ke_aio_ioctx *)KE_QUEUE_FRONT(&afd->write_ioctx_queue);
        KE_QUEUE_POP(&afd->write_ioctx_queue);
        ke_aio_error_event_handler(ioctx);
    }
}

static void ke_aio_report_read_event(struct ke_aio_fd *afd)
{
    struct ke_aio_ioctx *ioctx;

    assert(KE_QUEUE_LEN(&afd->read_ioctx_queue) > 0);
    ioctx = (struct ke_aio_ioctx *)KE_QUEUE_FRONT(&afd->read_ioctx_queue);
    KE_QUEUE_POP(&afd->read_ioctx_queue);
    
    if (ioctx->io_type == KAT_TCP_ACCEPT)
        ke_aio_accept_event_handler(ioctx);
    else
        ke_aio_read_event_handler(ioctx);

    if (KE_QUEUE_LEN(&afd->read_ioctx_queue) == 0) {
        /* clear EPOLLIN event if no context in read queue */
        afd->events &= ~EPOLLIN;
        ke_aio_epoll_ctl(afd->aio->poller, afd, 0);
    }
}

static void ke_aio_report_write_event(struct ke_aio_fd *afd)
{
    struct ke_aio_ioctx *ioctx;

    assert(KE_QUEUE_LEN(&afd->write_ioctx_queue) > 0);    
    ioctx = (struct ke_aio_ioctx *)KE_QUEUE_FRONT(&afd->write_ioctx_queue);
    KE_QUEUE_POP(&afd->write_ioctx_queue);

    if (ioctx->io_type == KAT_TCP_CONNECT)
        ke_aio_connect_event_handler(ioctx);
    else
        ke_aio_write_event_handler(ioctx);

    if (KE_QUEUE_LEN(&afd->write_ioctx_queue) == 0)    {
        /* clear EPOLLOUT event if no context in write queue */        
        afd->events &= ~EPOLLOUT;
        ke_aio_epoll_ctl(afd->aio->poller, afd, 0);        
    }
}

/* run loop
 * @actr -- aio 
 */
void ke_aio_run(ke_aio_t handle)
{
    struct ke_aio *aio;
    struct ke_aio_epoll *poller;
    struct epoll_event events[KE_EVENTS_MAX_COUNT];

    aio = (struct ke_aio *)handle;
    poller = aio->poller;
    
    while (!aio->stop) {
        int timeout = -1, n, i;
        
        if (aio->before_poll)
            timeout = aio->before_poll(aio, aio->before_poll_user_data);

        if (timeout < 0)
            timeout = KE_AIO_DEFAULT_POLL_TIMEOUT;

        n = epoll_wait(poller->epoll_fd, events, KE_EVENTS_MAX_COUNT, timeout);
        if (n < 0) {
            if (errno != EINTR)
                break;
        }

        for (i = 0; i < n; i++) {
            struct ke_aio_fd *afd;
            int epevt;
            int read_event = 0, write_event = 0;

            epevt = events[i].events;

#ifdef KE_AIO_ENABLE_REGULAR_FILE
            if (events[i].data.ptr == &poller->aio_event_fd) {
                if (epevt & ~EPOLLOUT)
                    ke_aio_handle_file_event(aio);
                continue;
            }
#endif
            if (events[i].data.ptr == poller->wakeup_pipe_fd) {
                ke_aio_disable_wakeup(aio);
                continue;
            }

            afd = events[i].data.ptr;

            if (epevt & EPOLLHUP || epevt & EPOLLERR) {
                if (EPOLLIN == (afd->events & EPOLLIN))
                    afd->refcount++;

                if (EPOLLOUT == (afd->events & EPOLLOUT))
                    afd->refcount++;

                ke_aio_report_error_event(afd);

            } else {
                if (epevt & ~EPOLLOUT && EPOLLIN == (afd->events & EPOLLIN)) {
                    afd->refcount++;
                    read_event = 1;
                }

                if (epevt & ~EPOLLIN && EPOLLOUT == (afd->events & EPOLLOUT)) {
                    afd->refcount++;
                    write_event = 1;
                }

                if (read_event)
                    ke_aio_report_read_event(afd);
                
                if (write_event)
                    ke_aio_report_write_event(afd);
            }
                
            afd->refcount = 0;
            if (afd->closed)
                ke_aio_closefd_internal(afd);
        }

        ke_aio_run_post_task(aio);
        
        if (aio->after_poll) {
            aio->after_poll(aio, aio->after_poll_user_data,
                            n == 0 ? KE_AIO_POLL_TIMEOUT : KE_AIO_POLL_SUCCESS);
        }
    }
}

/* notify run loop to break
 * @handle -- aio to shutdown
 * return 0 -- success, else error
 */
int ke_aio_notify_exit(ke_aio_t handle)
{
    struct ke_aio *aio;

    aio = (struct ke_aio *)handle;
    aio->stop = 1;
    ke_aio_wakeup(handle);
    return (0);
}

/* wakeup the thread which is waiting on aio
 * @handle -- aio
 * return 0 -- success, else error
 */
int ke_aio_wakeup(ke_aio_t handle)
{
    struct ke_aio *aio;
    struct ke_aio_epoll *poller;
    struct epoll_event ev;

    aio = (struct ke_aio *)handle;
    poller = (struct ke_aio_epoll *)aio->poller;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLOUT;
    ev.data.ptr = poller->wakeup_pipe_fd;

    if (epoll_ctl(poller->epoll_fd, EPOLL_CTL_ADD, 
                  poller->wakeup_pipe_fd[1], &ev) < 0) {
        KE_AIO_SET_ERRNO(aio);
        return (-1);
    }
    return (0);
}

int ke_aio_disable_wakeup(ke_aio_t handle)
{
    struct ke_aio *aio;
    struct ke_aio_epoll *poller;
    struct epoll_event ev;

    aio = (struct ke_aio *)handle;
    poller = (struct ke_aio_epoll *)aio->poller;

    if (epoll_ctl(poller->epoll_fd, EPOLL_CTL_DEL, 
                  poller->wakeup_pipe_fd[1], &ev) < 0) {
        KE_AIO_SET_ERRNO(aio);
        return (-1);
    }
    return (0);
}

