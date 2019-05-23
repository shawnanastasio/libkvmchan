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
#include <sys/prctl.h>
#include <sys/socket.h>

#include "util.h"
#include "libvirt.h"
#include "ivshmem.h"
#include "ringbuf.h"
#include "vfio.h"

// TODO: Support proper authentication and different libvirt hosts
#define LIBVIRT_HOST_URI "qemu:///system"

/// Event loop threads
struct thread_loop_data {
    ringbuf_t *rb;
    void *param;
};

static void host_main(void);
static void guest_main(void);

/// Helper functions

static void daemonize() {
    // Fork to background
    pid_t child = fork();
    if (child < 0) {
        log(LOGL_ERROR, "Failed to fork to background!");
        exit(EXIT_FAILURE);
    } else if (child > 0) {
        // Child forked successfully, parent can exit
        _exit(EXIT_SUCCESS);
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

static void show_usage(const char *progname) {
    printf("Usage: %s [-h|-d|-g]\n", progname);
}

static void show_help(const char *progname) {
    show_usage(progname);
    printf("Start the kvmchand daemon\n\n");

    printf("  -h       Show this help screen\n");
    printf("  -d       Run as a daemon\n");
    printf("  -g       Run in guest mode\n");
}

static void sigint_handler(int sig) {
    (void)sig;

    run_exit_callbacks();
    _exit(EXIT_FAILURE);
}

static void sighup_handler(int sig) {
    (void)sig;

    run_exit_callbacks();
    _exit(EXIT_FAILURE);
}

static void sigchld_handler(int sig) {
    (void)sig;

    log(LOGL_ERROR, "ERROR: Child unexpectedly died!");

    run_exit_callbacks();
    _exit(EXIT_FAILURE);
}

/// Entry point, main event loop
int main(int argc, char **argv) {
    bool daemon = false;
    bool guest = false;
    int opt;
    while ((opt = getopt(argc, argv, "hdg")) != -1) {
        switch(opt) {
            case 'h':
                show_help(argv[0]);
                return EXIT_SUCCESS;

            case 'd':
                daemon = true;
                break;

            case 'g':
                guest = true;
                break;

            default:
                fprintf(stderr, "Unknown argument!\n");
                show_usage(argv[0]);
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

    // Install SIGCHLD handler
    sa.sa_handler = sigchld_handler;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        log(LOGL_ERROR, "Failed to install SIGCHLD handler: %m");
        return EXIT_FAILURE;
    }

    // Install SIGHUP handler
    sa.sa_handler = sighup_handler;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        log(LOGL_ERROR, "Failed to install SIGHUP handler: %m");
        return EXIT_FAILURE;
    }
    // Start daemon
    if (guest)
        guest_main();
    else
        host_main();

    /*NOTREACHED*/
    return EXIT_FAILURE;
}

// Entry point for daemon when run in host mode
static void host_main(void) {
    // Spawn processes for libvirt and ivshmem event loops.
    // Having multiple processes allows for more granular
    // security sandboxing and increases isolation.

    // Create socketpairs for IPC
    int main_libvirt_sv[2], main_ivshmem_sv[2], libvirt_ivshmem_sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_libvirt_sv) < 0)
        goto fail_errno;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_ivshmem_sv) < 0)
        goto fail_errno;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, libvirt_ivshmem_sv) < 0)
        goto fail_errno;

    pid_t libvirt, ivshmem;

    // Spawn libvirt process
    if ((libvirt = fork()) < 0) {
        goto fail_errno;
    } else if (libvirt == 0) {
        // Get notified when parent exits
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        // Close unused socketpair fds
        close(main_libvirt_sv[0]);
        close(libvirt_ivshmem_sv[1]);

        run_libvirt_loop(main_libvirt_sv[1], libvirt_ivshmem_sv[0],
                         LIBVIRT_HOST_URI);

        // NOTREACHED
        bail_out();
    }

    // Spawn ivshmem process
    if ((ivshmem = fork()) < 0) {
        goto fail_errno;
    } else if (ivshmem == 0) {
        // Get notified when parent exits
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        // Close unused socketpair fds
        close(main_ivshmem_sv[0]);
        close(libvirt_ivshmem_sv[0]);

        run_ivshmem_loop(main_ivshmem_sv[1], libvirt_ivshmem_sv[1],
                         IVSHMEM_SOCK_PATH);

        // NOTREACHED
        bail_out();
    }

    // Close unused fds
    close(libvirt_ivshmem_sv[0]);
    close(libvirt_ivshmem_sv[1]);
    close(main_libvirt_sv[1]);
    close(main_ivshmem_sv[1]);

    // Initialize epoll to wait for events from event loops
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto fail_errno;

    if (add_epoll_fd(epoll_fd, main_libvirt_sv[0], EPOLLIN) < 0)
        goto fail_errno;
    if (add_epoll_fd(epoll_fd, main_ivshmem_sv[0], EPOLLIN) < 0)
        goto fail_errno;

    // Main event loop
    struct epoll_event events[5];
    int event_count;
    for(;;) {
        event_count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
        for(size_t i=0; i<event_count; i++) {
            if (events[i].data.fd == main_libvirt_sv[0]) {

                struct libvirt_event lv_event;
                ssize_t n = read(main_libvirt_sv[0], &lv_event,
                                 sizeof(struct libvirt_event));

                if (n < 0) {
                    log(LOGL_WARN, "Malformed message received from"
                        " libvirt process! Bailing out.");
                    bail_out();
                }

                log(LOGL_INFO, "Got event from libvirt! Type: %d", lv_event.type);
            }
        }
    }

fail_errno:
    log(LOGL_ERROR, "Daemon init failed: %m");
    bail_out();
}

// Entry point for daemon when run in guest mode
static void guest_main(void) {
    // Create socketpairs for IPC
    int main_vfio_sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_vfio_sv) < 0)
        goto fail_errno;

    // Spawn VFIO process
    pid_t vfio;
    if ((vfio = fork()) < 0) {
        goto fail_errno;
    } else if (vfio == 0) {
        // Get notified when parent exits
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        // Close unused socketpair fds
        close(main_vfio_sv[0]);

        run_vfio_loop(main_vfio_sv[1]);

        // NOTREACHED
        bail_out();
    }

    // Initialize epoll to wait for events from event loops
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto fail_errno;

    if (add_epoll_fd(epoll_fd, main_vfio_sv[0], EPOLLIN) < 0)
        goto fail_errno;

    struct epoll_event events[5];
    int event_count;
    for(;;) {
        event_count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
        for(size_t i=0; i<event_count; i++) {
        }
    }

fail_errno:
    log(LOGL_ERROR, "Daemon init failed: %m");
    bail_out();
}
