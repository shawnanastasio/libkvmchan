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
#include <inttypes.h>

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
#include "ipc.h"
#include "connections.h"

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


static void handle_message(struct ipc_message *msg) {
    ASSERT(msg);
    struct ipc_cmd *cmd = &msg->cmd;
    struct ipc_message response = {
        .type = IPC_TYPE_RESP,
        .dest = msg->src,
        .fd = -1,
        .id = msg->id
    };

    switch(cmd->command) {
        case MAIN_IPC_CMD_TEST:
            response.resp.error = false;
            response.resp.ret = msg->cmd.args[0] << 1;
            break;

        default:
            log_BUG("Unknown IPC command received in main: %"PRIu64, cmd->command);
    }

    if (!ipc_send_message(&response, NULL))
        log_BUG("Unable to send response to IPC message!");
}
#if 0
static bool handle_message(int sockets[NUM_IPC_SOCKETS], struct ipc_message *msg) {

    struct ipc_cmd *cmd = &msg->cmd;
    struct ipc_message response = {
        .type = IPC_TYPE_RESP,
        .dest = msg->src,
        .fd = -1,
        .id = msg->id
    };

    switch(cmd->command) {
        case MAIN_IPC_CMD_TEST:
            response.resp.error = false;
            response.resp.ret = msg->cmd.args[0] << 1;
            break;

        case MAIN_IPC_CMD_VCHAN_INIT:
            //vchan_init();

        default:
            log(LOGL_WARN, "Unknown IPC command %d! Ignoring...", cmd->command);
            response.resp.error = true;
    }

    if (msg->flags & IPC_FLAG_WANTRESP)
        return ipc_server_send_message(sockets[dest_to_socket(msg->src)], &response);
    else
        return true;
}
#endif

// Entry point for daemon when run in host mode
static void host_main(void) {
    // Spawn processes for libvirt and ivshmem event loops.
    // Having multiple processes allows for more granular
    // security sandboxing and increases isolation.

    // Create socketpairs for IPC
    int main_libvirt_sv[2], main_ivshmem_sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_libvirt_sv) < 0)
        goto fail_errno;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_ivshmem_sv) < 0)
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

        run_libvirt_loop(main_libvirt_sv[1], LIBVIRT_HOST_URI);

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

        run_ivshmem_loop(main_ivshmem_sv[1], IVSHMEM_SOCK_PATH);

        // NOTREACHED
        bail_out();
    }

    // Close unused fds
    close(main_libvirt_sv[1]);
    close(main_ivshmem_sv[1]);

    // listen for messages
    int sockets[NUM_IPC_SOCKETS];
    for (uint8_t i=0; i<NUM_IPC_SOCKETS; i++)
        sockets[i] = -1;

    sockets[IPC_SOCKET_IVSHMEM] = main_ivshmem_sv[0];
    sockets[IPC_SOCKET_LIBVIRT] = main_libvirt_sv[0];

    ipc_server_start(sockets, IPC_DEST_MAIN, handle_message);

fail_errno:
    log(LOGL_ERROR, "Error encountered while initializing daemon: %m");
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

    // listen for messages
    int sockets[NUM_IPC_SOCKETS];
    for (uint8_t i=0; i<NUM_IPC_SOCKETS; i++)
        sockets[i] = -1;

    sockets[IPC_SOCKET_VFIO] = main_vfio_sv[0];

    ipc_server_start(sockets, IPC_DEST_MAIN, handle_message);

fail_errno:
    log(LOGL_ERROR, "Daemon init failed: %m");
    bail_out();
}
