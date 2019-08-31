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
 * This file contains an implementation of the API exported to
 * applications on the current domain that link against libkvmchan.
 *
 * Most libkvmchan functions will simply forward their arguments
 * to an endpoint in this API and the request will be handled
 * in the daemon.
 */

#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h>

#include "util.h"
#include "ipc.h"
#include "config.h"
#include "libkvmchan-priv.h"

struct localhandler_data {
    int epoll_fd;
    struct vec_int clients;
};

static void cleanup_socket_path(void *path_) {
    const char *path = path_;
    unlink(path);
}

/**
 * Handle IPC mesages from other kvmchand processes
 */
static void handle_ipc_message(struct ipc_message *msg) {

}

/*
 * Get local domain number
 */
static uint32_t get_local_domain_no(void) {
    // TODO: don't always assume host
    return 0;
}

/**
 * Handle messages from remote clients
 */
static bool handle_client_message(int fd, struct kvmchand_message *msg) {
    struct kvmchand_ret ret = { .error = true };

    switch(msg->command) {
        case KVMCHAND_CMD_HELLO:
            ret.ret = KVMCHAND_API_VERSION;
            ret.error = false;
            break;

        case KVMCHAND_CMD_SERVERINIT:
        {
            // Forward message to MAIN over IPC
            struct ipc_message ipc_msg = {
                .type = IPC_TYPE_CMD,
                .cmd = {
                    .command = MAIN_IPC_CMD_VCHAN_INIT,
                    .args = {
                        get_local_domain_no(),
                        msg->args[0],
                        msg->args[1],
                        msg->args[2],
                        msg->args[3],
                    }
                },
                .dest = IPC_DEST_MAIN,
                .flags = IPC_FLAG_WANTRESP
            };

            struct ipc_message ipc_resp;
            if (!ipc_send_message(&ipc_msg, &ipc_resp))
                goto error;

            // Forward response to client
            ret.error = ipc_resp.resp.error;
            ret.ret = ipc_resp.resp.ret;

            break;
        }


        default:
            log(LOGL_WARN, "Warning, unknown command from client fd %d. Ignoring.", fd);
    }

    if (socmsg_send(fd, &ret, sizeof(ret), -1) < 0) {
        log(LOGL_ERROR, "Failed to send response to client fd %d.", fd);
        return false;
    }

    return true;

error:
    // Try to send error to client
    ret.error = true;
    if (socmsg_send(fd, &ret, sizeof(ret), -1) < 0) {
        log(LOGL_ERROR, "Failed to send response to client fd %d.", fd);
        return false;
    }
    log(LOGL_WARN, "Error occurred while attempting to service client message!\n");
    return true; // True because it wasn't the client's fault
}

static bool remove_connection(struct localhandler_data *data, int fd) {
    for (size_t i=0; i<data->clients.count; i++) {
        if (data->clients.data[i] == fd) {
            bool res = true;
            if (del_epoll_fd(data->epoll_fd, fd) < 0)
                res = false;
            vec_int_remove(&data->clients, i);
            close(fd);
            return res;
        }
    }

    return false;
}

void run_localhandler_loop(int mainsoc) {
    struct localhandler_data data;

    if (!ipc_start(mainsoc, IPC_DEST_LOCALHANDLER, handle_ipc_message))
        goto error;

    // Set up the socket and bind it
    int socfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socfd < 0)
        goto error;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, LOCALHANDLER_SOCK_PATH, sizeof(addr.sun_path)-1);
    if (bind(socfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0)
        goto error;

    // Set proper permissions on the socket
    if (chmod(LOCALHANDLER_SOCK_PATH, 0666) < 0)
        goto error;

    // Install exit handler to remove socket
    if (!install_exit_callback(cleanup_socket_path, (void *)LOCALHANDLER_SOCK_PATH))
        goto error;

    // Start listening
    if (listen(socfd, 5) < 0)
        goto error;

    // Initialize epoll
    data.epoll_fd = epoll_create1(0);
    if (data.epoll_fd < 0)
        goto error;
    if (add_epoll_fd(data.epoll_fd, socfd, EPOLLIN) < 0)
        goto error;

    if (!vec_int_init(&data.clients, 10, NULL))
        goto error;

    // Poll for events
    struct epoll_event events[5];
    int event_count;
    for(;;) {
        event_count = epoll_wait(data.epoll_fd, events, ARRAY_SIZE(events), -1);
        for(int i=0; i<event_count; i++) {
            if (events[i].data.fd == socfd) {
                // Connection request on the socket, accept it
                int fd = accept(socfd, NULL, NULL);

                // Add connected fd to epoll
                if (add_epoll_fd(data.epoll_fd, fd, EPOLLIN) < 0) {
                    log(LOGL_WARN, "Failed to add fd to epoll set: %m.");
                    goto error;
                }

                if (!vec_int_push_back(&data.clients, fd)) {
                    log(LOGL_ERROR, "Failed to add fd to vec: %m.");
                    goto error;
                }

                log(LOGL_INFO, "Client connected! fd: %d", fd);
            } else {
                // Event from a client fd, handle it
                int fd = events[i].data.fd;
                struct kvmchand_message msg;
                ssize_t n = socmsg_recv(fd, &msg, sizeof(msg), NULL);
                if (n == 0) {
                    // Client disconnected
                    log(LOGL_INFO, "Client disconnected! fd: %d", fd);

                    if (!remove_connection(&data, fd))
                        log(LOGL_WARN, "Failed to delete client.");

                    continue;
                } else if (n != sizeof(msg)) {
                    log(LOGL_WARN, "Unexpected message received from client! Dropping client.");

                    if (!remove_connection(&data, fd))
                        log(LOGL_WARN, "Failed to delete client.");

                    continue;
                }

                // Valid message received, handle it
                if (!handle_client_message(fd, &msg))
                    if (!remove_connection(&data, fd))
                        log(LOGL_WARN, "Failed to delete client.");
           }
        }
    }

error:
    log(LOGL_ERROR, "localhandler encountered fatal error: %m!");
    bail_out();
}
