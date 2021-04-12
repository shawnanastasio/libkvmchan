/**
 * Copyright 2018-2021 Shawn Anastasio
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
#include "config.h"
#include "libvirt.h"
#include "ivshmem.h"
#include "ringbuf.h"
#include "vfio.h"
#include "ipc.h"
#include "connections.h"
#include "localhandler.h"
#include "libkvmchan-priv.h"

// TODO: Support proper authentication and different libvirt hosts
#define LIBVIRT_HOST_URI "qemu:///system"

/// Event loop threads
struct thread_loop_data {
    ringbuf_t *rb;
    void *param;
};

#ifndef GUEST_ONLY
static void host_main(void);
#endif

static void guest_main(void);

/// Helper functions

static bool validate_runtime_dir(void) {
    struct stat s;
    if (stat(RUNTIME_BASE_DIR, &s) < 0) {
        if (errno == ENOENT) {
            // Doesn't exist, create it
            if (mkdir(RUNTIME_BASE_DIR, 0755) < 0)
                goto error;

            goto privsep_set_owner;
        } else
            goto error;
    }

    // Path exists, validate type and permissions
    if (!(s.st_mode & S_IFDIR)) {
        log(LOGL_ERROR, "Runtime directory is not a directory: %s", RUNTIME_BASE_DIR);
        return false;
    }

    if ((s.st_mode & ~S_IFMT) != 0755) {
        // Try to change permissions
        if (chmod(RUNTIME_BASE_DIR, 0755) < 0)
            goto error;
    }

    // Finally, if privsep is enabled, set the owner uid/gid of the dir accordingly
privsep_set_owner:
#ifdef USE_PRIVSEP
    {
        uid_t kvmchand_uid = get_uid_for_username(PRIVSEP_USER);
        if (kvmchand_uid == (uid_t)-1)
            goto error;
        gid_t kvmchand_gid = get_gid_for_groupname(PRIVSEP_GROUP);
        if (kvmchand_gid == (gid_t)-1)
            goto error;

        if (s.st_uid != kvmchand_uid || s.st_gid != kvmchand_gid)
            if (chown(RUNTIME_BASE_DIR, kvmchand_uid, kvmchand_gid) < 0)
                goto error;
    }
#endif

    return true;

error:
    log(LOGL_ERROR, "Unable to create runtime directory at %s: %m", RUNTIME_BASE_DIR);
    return false;
}

static void daemonize(void) {
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

    // Verify runtime base dir exists and has correct permissions
    if (!validate_runtime_dir())
        return EXIT_FAILURE;

    // Start daemon
    if (guest) {
        guest_main();
    } else {
#ifndef GUEST_ONLY
        host_main();
#else
        log(LOGL_ERROR, "kvmchand was built in guest-only mode. You must pass -g.");
        return EXIT_FAILURE;
#endif
    }

    /*NOTREACHED*/
    return EXIT_FAILURE;
}

static void handle_message(struct ipc_message *msg) {
    struct ipc_cmd *cmd = &msg->cmd;
    struct ipc_message response = {
        .type = IPC_TYPE_RESP,
        .resp.error = true,
        .dest = msg->src,
        .fd_count = 0,
        .id = msg->id
    };

    switch(cmd->command) {
#ifndef GUEST_ONLY
        case MAIN_IPC_CMD_VCHAN_INIT:
            response.resp.error = !vchan_init((uint32_t)cmd->args[0], (uint32_t)cmd->args[1],
                                           (uint32_t)cmd->args[2], (uint64_t)cmd->args[3],
                                           (uint64_t)cmd->args[4], (uint32_t *)&response.resp.ret,
                                           (pid_t *)&response.resp.ret2);
            break;

        case MAIN_IPC_CMD_VCHAN_CONN:
        {
            enum connections_error err = vchan_conn((uint32_t)cmd->args[0], (uint32_t)cmd->args[1],
                                                    (uint32_t)cmd->args[2], (uint32_t *)&response.resp.ret,
                                                    (pid_t *)&response.resp.ret2);
            response.resp.error = err != CONNECTIONS_ERROR_NONE;
            if (response.resp.error)
                response.resp.ret = err;
            break;
        }

        case MAIN_IPC_CMD_VCHAN_CLOSE:
            response.resp.error = !vchan_close((uint32_t)cmd->args[0], (uint32_t)cmd->args[1],
                                               (uint32_t)cmd->args[2]);
            break;

        case MAIN_IPC_CMD_UNREGISTER_DOM:
            response.resp.error = !vchan_unregister_domain((pid_t)cmd->args[0]);
            break;

        case MAIN_IPC_CMD_VCHAN_CLIENT_DISCONNECT:
            response.resp.ret = vchan_client_disconnect((uint32_t)cmd->args[0], (uint32_t)cmd->args[1], (uint32_t)cmd->args[2]);
            response.resp.error = response.resp.ret != CONNECTIONS_ERROR_NONE;
            break;

        case MAIN_IPC_CMD_VCHAN_GET_STATE:
            response.resp.ret = vchan_get_state((uint32_t)cmd->args[0], (uint32_t)cmd->args[1], (uint32_t)cmd->args[2]);
            response.resp.error = false;
            break;

        case MAIN_IPC_CMD_SHMEM_CREATE:
        {
            uint32_t ivposition;
            uint32_t region_id;
            size_t start_off;
            int memfd = -1;
            enum connections_error ret = shmem_create((uint32_t)cmd->args[0], (uint32_t)cmd->args[1], (uint32_t)cmd->args[2],
                                                      (size_t)cmd->args[3], (bool)cmd->args[4], &ivposition, &region_id, &start_off,
                                                      &memfd);

            response.resp.error = ret != CONNECTIONS_ERROR_NONE;
            if (response.resp.error) {
                response.resp.ret = ret;
            } else {
                response.resp.ret = ((uint64_t)region_id << 32) | ivposition;
                response.resp.ret2 = start_off;
                if (memfd > 0) {
                    response.flags = IPC_FLAG_FD;
                    response.fd_count = 1;
                    response.fds[0] = memfd;
                }
            }
            break;
        }

        case MAIN_IPC_CMD_SHMEM_CLOSE:
            response.resp.ret = shmem_close((uint32_t)cmd->args[0], (uint32_t)cmd->args[1],
                                            (uint32_t)cmd->args[2]);
            response.resp.error = response.resp.ret != CONNECTIONS_ERROR_NONE;
            break;
#endif
        default:
            log_BUG("Unknown IPC command received in main: %"PRIu64, cmd->command);
    }

    if (msg->flags & IPC_FLAG_WANTRESP) {
        if (!ipc_send_message(&response, NULL))
            log_BUG("Unable to send response to IPC message!");
    }
}

/**
 * Fork a child process and run its main loop.
 *
 * This is implemented as a macro to allow aribtrary argument forwarding to
 * the main loop function via C99 variadic macros.
 *
 * @param name        string literal name of child used for debugging purposes
 * @param sockpair    array of sockets used for IPC
 * @param main        main function to call after fork and setup
 * @param ...         extra arguments to pass to main function
 * @return            pid of child process, or -1 on failure.
 */
#define spawn_child_loop(name, sockpair, main, ...) \
    ({ \
        pid_t p = fork(); \
        if (p == 0) { \
            /* Get notified when parent exits */ \
            prctl_w(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0); \
            /* Set process name */ \
            const char *pr_name = "kvmchand_" name; \
            prctl_w(PR_SET_NAME, (unsigned long)pr_name, 0, 0, 0); \
            /* Close unused socketpair fd */ \
            close(sockpair[0]); \
            /* Call main loop */ \
            main(sockpair[1], ##__VA_ARGS__); \
            /* NOTREACHED */ \
            bail_out(); \
        } else if (p > 0) { \
            /* Close unused socketpair fd */ \
            close(sockpair[1]); \
        } \
        p; \
    })

#ifndef GUEST_ONLY
// Entry point for daemon when run in host mode
static void host_main(void) {
    // Spawn processes for libvirt and ivshmem event loops.
    // Having multiple processes allows for more granular
    // security sandboxing and increases isolation.

    // Create socketpairs for IPC
    int main_libvirt_sv[2], main_ivshmem_sv[2], main_localhandler_sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_libvirt_sv) < 0)
        goto fail_errno;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_ivshmem_sv) < 0)
        goto fail_errno;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_localhandler_sv) < 0)
        goto fail_errno;

    pid_t libvirt, ivshmem, localhandler;

    // Spawn libvirt process
    libvirt = spawn_child_loop("libvirt", main_libvirt_sv, run_libvirt_loop, LIBVIRT_HOST_URI);
    if (libvirt < 0)
        goto fail_errno;

    // Spawn ivshmem process
    ivshmem = spawn_child_loop("ivshmem", main_ivshmem_sv, run_ivshmem_loop);
    if (ivshmem < 0)
        goto fail_errno;

    // Spawn localhandler process
    localhandler = spawn_child_loop("localhandler", main_localhandler_sv, run_localhandler_loop, true);
    if (localhandler < 0)
        goto fail_errno;

    // Drop root privileges
    if (!drop_privileges(false)) {
        log(LOGL_ERROR, "Failed to drop root privileges but built with USE_PRIVSEP=1! Bailing out.");
        goto fail_errno;
    }

    // Initialize connections database
    connections_init();

    // listen for messages
    int sockets[NUM_IPC_SOCKETS];
    for (uint8_t i=0; i<NUM_IPC_SOCKETS; i++)
        sockets[i] = -1;

    sockets[IPC_SOCKET_IVSHMEM] = main_ivshmem_sv[0];
    sockets[IPC_SOCKET_LIBVIRT] = main_libvirt_sv[0];
    sockets[IPC_SOCKET_LOCALHANDLER] = main_localhandler_sv[0];

    ipc_server_start(sockets, handle_message);

fail_errno:
    log(LOGL_ERROR, "Error encountered while initializing daemon: %m");
    bail_out();
}
#endif

// Entry point for daemon when run in guest mode
static void guest_main(void) {
    // Create socketpairs for IPC
    int main_vfio_sv[2], main_localhandler_sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_vfio_sv) < 0)
        goto fail_errno;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_localhandler_sv) < 0)
        goto fail_errno;

    pid_t vfio, localhandler;

    // Spawn VFIO process
    vfio = spawn_child_loop("vfio", main_vfio_sv, run_vfio_loop);
    if (vfio < 0)
        goto fail_errno;

    // Spawn localhandler process
    localhandler = spawn_child_loop("localhandler", main_localhandler_sv, run_localhandler_loop, false);
    if (localhandler < 0)
        goto fail_errno;

    // Drop root privileges
    if (!drop_privileges(false)) {
        log(LOGL_ERROR, "Failed to drop root privileges but built with USE_PRIVSEP=1! Bailing out.");
        goto fail_errno;
    }

    // listen for messages
    int sockets[NUM_IPC_SOCKETS];
    for (uint8_t i=0; i<NUM_IPC_SOCKETS; i++)
        sockets[i] = -1;

    sockets[IPC_SOCKET_VFIO] = main_vfio_sv[0];
    sockets[IPC_SOCKET_LOCALHANDLER] = main_localhandler_sv[0];

    ipc_server_start(sockets, handle_message);

fail_errno:
    log(LOGL_ERROR, "Daemon init failed: %m");
    bail_out();
}
