/**
 * Copyright 2018-2019 Shawn Anastasio
 *
 * This file is part of libkvmchan.
 *
 * libkvmchan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libkvmchan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libkvmchan.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * This daemon interfaces with libvirt and allows VMs
 * to query and create vchans which they can't do by
 * themselves
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>

#include "daemon-priv.h"
#include "ringbuf.h"

// TODO: Support proper authentication and different libvirt hosts
#define LIBVIRT_HOST_URI "qemu:///system"

/// Event loop threads
struct thread_loop_data {
    ringbuf_t *rb;
    void *param;
};

static void *spawn_libvirt_loop(void *data_) {
    struct thread_loop_data *data = data_;

    int ret = run_libvirt_loop(data->rb, data->param);
    log(LOGL_ERROR, "libvirt loop exited with error: %d", ret);
    exit(EXIT_FAILURE);

    /*NOTREACHED*/
    return NULL;
}

static void *spawn_ivshmem_loop(void *data_) {
    struct thread_loop_data *data = data_;

    int ret = run_ivshmem_loop(data->rb, data->param);
    log(LOGL_ERROR, "ivshmem loop exited with error: %d", ret);
    exit(EXIT_FAILURE);

    /*NOTREACHED*/
    return NULL;
}

/// Helper functions

static void daemonize() {
    // Fork to background
    pid_t child = fork();
    if (child < 0) {
        log(LOGL_ERROR, "Failed to fork to background!");
        exit(EXIT_FAILURE);
    } else if (child > 0) {
        // Child forked successfully, parent can exit
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0);

    // Create a new session
    pid_t sid = setsid();
    if (sid < 0) {
        log(LOGL_ERROR, "Failed to set sid!");
        exit(EXIT_FAILURE);
    }

    // Chdir to /
    if (chdir("/") < 0) {
        log(LOGL_ERROR, "Failed to chdir!");
        exit(EXIT_FAILURE);
    }

    // Lastly, close all STDIO file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void show_help(const char *progname) {
    fprintf(stderr, "Usage: %s [-h|-d]\n", progname);
}

int add_epoll_fd(int epoll_fd, int fd, int event) {
    struct epoll_event ep_event = {
        .events = event,
        .data = {
            .fd = fd
        }
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ep_event);
}

int del_epoll_fd(int epoll_fd, int fd) {
    struct epoll_event ep_event = {
        .data = {
            .fd = fd
        }
    };

    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ep_event);
}

void sigint_handler(int sig) {
    (void)sig;

    // Call exit(2) to execute all on_exit(2) callbacks
    exit(EXIT_FAILURE);
}

/// Entry point, main event loop
int main(int argc, char **argv) {
    bool daemon = false;
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch(opt) {
            case 'h':
                show_help(argv[0]);
                return EXIT_SUCCESS;

            case 'd':
                daemon = true;
                break;

            default:
                fprintf(stderr, "Unknown argument!\n");
                show_help(argv[0]);
                return EXIT_FAILURE;
        }
    }


    // Daemonize if requested
    if (daemon)
        daemonize();

    // Install SIGINT handler
    struct sigaction sa = {
        .sa_handler = sigint_handler,
    };

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        log(LOGL_ERROR, "Failed to install SIGINT handler: %m");
        return EXIT_FAILURE;
    }

    // Create ringbufs for communicating with libvirt and ivshmem event loops
    ringbuf_t libvirt_rb, ivshmem_rb;
    int libvirt_eventfd, ivshmem_eventfd;
    const uint8_t rb_flags = RINGBUF_FLAG_BLOCKING | RINGBUF_FLAG_LOCAL_EVENTFD;
    void *libvirt_rb_buf = malloc_w(1024 + 1);
    void *ivshmem_rb_buf = malloc_w(1024 + 1);

    ringbuf_init(&libvirt_rb, libvirt_rb_buf, 1024 + 1, rb_flags);
    ringbuf_init(&ivshmem_rb, ivshmem_rb_buf, 1024 + 1, rb_flags);

    if ((libvirt_eventfd = ringbuf_get_eventfd(&libvirt_rb, NULL)) < 0) {
        log(LOGL_ERROR, "Failed to obtain eventfd for libvirt ringbuf!");
        return EXIT_FAILURE;
    }

    if ((ivshmem_eventfd = ringbuf_get_eventfd(&ivshmem_rb, NULL)) < 0) {
        log(LOGL_ERROR, "Failed to obtain eventfd for ivshmem ringbuf!");
        return EXIT_FAILURE;
    }

    // Spawn threads for the two event loops
    pthread_t libvirt_thread, ivshmem_thread;
    int ret;

    struct thread_loop_data libvirt_data = { &libvirt_rb, LIBVIRT_HOST_URI };
    if ((ret = pthread_create(&libvirt_thread, NULL, &spawn_libvirt_loop, &libvirt_data))) {
        log(LOGL_ERROR, "Failed to spawn libvirt thread: %s", strerror(ret));
        return EXIT_FAILURE;
    }

    struct thread_loop_data ivshmem_data = { &ivshmem_rb, IVSHMEM_SOCK_PATH };
    if ((ret = pthread_create(&ivshmem_thread, NULL, &spawn_ivshmem_loop, &ivshmem_data))) {
        log(LOGL_ERROR, "Failed to spawn libvirt thread: %s", strerror(ret));
        return EXIT_FAILURE;
    }

    // Initialize epoll to wait for events from event loops
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log(LOGL_ERROR, "Failed to initialize epoll: %m");
        return EXIT_FAILURE;
    }

    if (add_epoll_fd(epoll_fd, libvirt_eventfd, EPOLLIN) < 0) {
        log(LOGL_ERROR, "Failed to add libvirt eventfd to epoll: %m");
        return EXIT_FAILURE;
    }

    if (add_epoll_fd(epoll_fd, ivshmem_eventfd, EPOLLIN) < 0) {
        log(LOGL_ERROR, "Failed to add ivshmem eventfd to epoll: %m");
        return EXIT_FAILURE;
    }


    // Main event loop
    struct epoll_event events[5];
    int event_count;
    for(;;) {
        event_count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
        for(size_t i=0; i<event_count; i++) {
            if (events[i].data.fd == libvirt_eventfd) {
                ringbuf_clear_eventfd(&libvirt_rb);

                log(LOGL_INFO, "TEST");
                struct libvirt_event lv_event;
                ringbuf_read(&libvirt_rb, &lv_event, sizeof(struct libvirt_event));

                log(LOGL_INFO, "Got event from libvirt! Type: %d", lv_event.type);

            }
        }
    }
}
