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
 * This file contains an implementation of an ivshmem server.
 * It is used to manage the shared memory regions and
 * interrupt eventfds allocated to VMs.
 *
 * For more information, see:
 * https://github.com/qemu/qemu/blob/master/docs/specs/ivshmem-spec.txt
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#include <unistd.h>
#include <endian.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "util.h"
#include "ivshmem.h"
#include "libkvmchan-priv.h"
#include "ipc.h"
#include "config.h"

struct ringbuf_conn_data {
    ringbuf_t host_to_client_rb;
    ringbuf_t client_to_host_rb;
    shmem_hdr_t *hdr;
};

struct conn_info {
    uint32_t ivposition; // IVPosition of this connection

    int socfd; // Socket file descriptor
    int shmfd; // Shared memory file descriptor

    int incoming_eventfds[NUM_EVENTFDS]; // eventfds used by client to notify us
    int outgoing_eventfds[NUM_EVENTFDS]; // eventfds used by us to notify client

    // Ringbuffer structures and mapped shared memory
    struct ringbuf_conn_data data;
};

struct pending_conn {
    int shmfd;
    int eventfds[NUM_EVENTFDS * 2]; // 2 incoming eventfds + 2 outgoing eventfds
    uint32_t ivposition;
};

struct client_info {
    pid_t pid;                    // PID of qemu process
    uint32_t dom;                 // Domain number of client
    pthread_t listener;           // Listener thread handle
    int listener_eventfd;         // Eventfd to kill the listener thread
    struct vec_voidp connections; // conn_info vec
    struct vec_voidp pending;     // pending_conn vec
    struct vec_u32 ivpositions;   // Reserved ivpositions
    uint32_t ivposition_last;     // Last allocated ivposition
};

struct ivshmem_server {
    int socfd; // Main socket fd
    struct vec_voidp clients; // client_info vec
};

struct ivshmem_server g_server;

/**
 * Send an ivshmem protocol message to a given socket.
 * @param socfd socket to send message to
 * @param msg   message to send
 * @param fd    file descriptor to pass via SCM_RIGHTS, or -1
 * @return      number of bytes sent, or -1 on failure.
 */
static ssize_t send_ivshmem_msg(int socfd, int64_t msg, int fd) {
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;

    int64_t buf = htole64(msg); // ivshmem spec mandates LE
    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = &buf, .iov_len = 8 };
    struct msghdr msgh = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = 0,
        .msg_control = (fd > 0) ? u.cmsgbuf : NULL,
        .msg_controllen = (fd > 0) ? CMSG_LEN(sizeof(int)) : 0,
    };

    /* Initialize the control message to hand off the fd */
    if (fd > 0) {
        cmsg = CMSG_FIRSTHDR(&msgh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(cmsg) = fd;
    }

    return sendmsg(socfd, &msgh, 0);
}

static void conn_info_destructor(void *conn_) {
    struct conn_info *conn = conn_;
    close(conn->socfd);
    close(conn->shmfd);
    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        close(conn->incoming_eventfds[i]);
        close(conn->outgoing_eventfds[i]);
    }
    free(conn);
}

static void client_info_destructor(void *client_) {
    struct client_info *client = client_;
    vec_voidp_destroy(&client->connections);
    vec_voidp_destroy(&client->pending);
    vec_u32_destroy(&client->ivpositions);

    // Kill the listener thread
    uint64_t buf = 1;
    ignore_value(write(client->listener_eventfd, &buf, 8));
    pthread_join(client->listener, NULL);

    close(client->listener_eventfd);
    free(client);
}

static void cleanup_socket_path(void *path_) {
    const char *path = path_;
    unlink(path);
}

/**
 * Get a client that's connected to the given ivshmem server.
 * @param server       ivshmem server to act on
 * @param pid          PID of client to search for
 * @param makenew      whether to make a new client if one with the given PID is not found
 * @param[out] idx_out index of the client in the server's clients vec
 * @return             client_info, or NULL if not found and makenew=false
 */
static struct client_info *get_client(struct ivshmem_server *server, pid_t pid, bool makenew,
                                      size_t *idx_out) {
    for(size_t i=0; i<server->clients.count; i++) {
        struct client_info *cur = server->clients.data[i];
        if (cur->pid == pid) {
            if (idx_out)
                *idx_out = i;
            return cur;
        }
    }
    if (!makenew)
        goto fail;

    // No matches found, make a new one
    struct client_info *new = malloc_w(sizeof(struct client_info));
    if (!vec_voidp_init(&new->connections, 10, conn_info_destructor))
        goto fail_new;
    new->pid = pid;
    new->dom = 0;

    // Initialize pending vec
    if (!vec_voidp_init(&new->pending, 10, free_destructor))
        goto fail_connections;

    // Initalize ivpositions vec, ivposition_last
    new->ivposition_last = KVMCHAND_IVPOSITION;
    if (!vec_u32_init(&new->ivpositions, 10, NULL))
        goto fail_pending;

    // Insert into vec and return
    if (!vec_voidp_push_back(&server->clients, new))
        goto fail_ivpositions;

    if (idx_out)
        *idx_out = server->clients.count - 1;
    return new;

fail_ivpositions:
    vec_u32_destroy(&new->ivpositions);
fail_pending:
    vec_voidp_destroy(&new->pending);
fail_connections:
    vec_voidp_destroy(&new->connections);
fail_new:
    free(new);
fail:
    return NULL;
}

/**
 * Get all file descriptors associated with a connection
 */
static bool get_conn_fds(struct ivshmem_server *server, pid_t pid, uint32_t ivposition, int *fds_out) {
    struct client_info *info = get_client(server, pid, false, NULL);
    if (!info)
        return false;

    struct conn_info *conn = NULL;
    for (size_t i=0; i<info->connections.count; i++) {
        struct conn_info *cur = info->connections.data[i];
        if (cur->ivposition == ivposition) {
            conn = cur;
            break;
        }
    }
    if (!conn)
        return false;

    fds_out[0] = conn->shmfd;
    fds_out[1] = conn->incoming_eventfds[0];
    fds_out[2] = conn->incoming_eventfds[1];
    fds_out[3] = conn->outgoing_eventfds[0];
    fds_out[4] = conn->outgoing_eventfds[1];
    return true;
}

/**
 * Allocate an ivposition for a client.
 * @param client  client to allocate ivposition for
 * @return        allocated ivposition, or 0 on failure
 */
static uint32_t client_allocate_ivposition(struct client_info *client) {
    if (client->ivpositions.count == (0xFFFFFFFF) - 2)
        return 0;

    // Keep incrementing ivposition_last until we have a free ivposition
    for (;;) {
        // Handle overflow, skipping over 0 and 1 (reserved)
        if (client->ivposition_last == 0xFFFFFFFF)
            client->ivposition_last = 1;

        client->ivposition_last++;
        if (!vec_u32_contains(&client->ivpositions, client->ivposition_last, NULL)) {
            vec_u32_push_back(&client->ivpositions, client->ivposition_last);
            return client->ivposition_last;
        }
    }

    return 0;
}

/**
 * Free a previously allocated ivposition.
 * @param client     client that ivposition was allocated for
 * @param ivposition ivposition to free
 */
static void client_free_ivposition(struct client_info *client, uint32_t ivposition) {
    for (size_t i=0; i<client->ivpositions.count; i++) {
        if (client->ivpositions.data[i] == ivposition) {
            client->ivposition_last = i - 1;
            vec_u32_remove(&client->ivpositions, i);
            return;
        }
    }

    log_BUG("Tried to free ivposition that wasn't allocated!\n");
}

/**
 * Get the domain number of a given client.
 * @param client client to get domain of
 * @return       domain number of client, or 0 on failure
 */
static uint32_t client_get_domain(struct client_info *client) {
    if (client->dom != 0)
        return client->dom;

    // Ask libvirt for the client's domain number
    struct ipc_message resp, msg = {
        .type = IPC_TYPE_CMD,
        .cmd = {
            .command = LIBVIRT_IPC_CMD_GET_ID_BY_PID,
            .args = { client->pid }
        },
        .dest = IPC_DEST_LIBVIRT,
        .flags = IPC_FLAG_WANTRESP
    };
    if (!ipc_send_message(&msg, &resp))
        goto fail;
    if (resp.resp.error)
        goto fail;
    client->dom = resp.resp.ret;
    return client->dom;

fail:
    log(LOGL_ERROR, "Failed to get domain number for client!\n");
    return 0;
}

static bool handle_kvmchand_message(struct client_info *client, struct conn_info *conn) {
    struct kvmchand_message msg;
    if (RB_SUCCESS != ringbuf_sec_read(&conn->data.client_to_host_rb, &conn->data.hdr->client_to_host_pub,
                                       &msg, sizeof(struct kvmchand_message))) {
        log(LOGL_ERROR, "Failed to receive message from client kvmchand!");
        return false;
    }

    // Handle command and send response
    struct kvmchand_ret ret = { .error = true };
    switch(msg.command) {
        case KVMCHAND_CMD_HELLO:
            ret.ret = KVMCHAND_API_VERSION;
            ret.error = false;
            break;

        case KVMCHAND_CMD_SERVERINIT:
        {
            uint32_t dom = client_get_domain(client);
            if (dom == 0)
                break;

            struct ipc_message ipc_resp, ipc_msg = {
                .type = IPC_TYPE_CMD,
                .cmd = {
                    .command = MAIN_IPC_CMD_VCHAN_INIT,
                    .args = {
                        dom,
                        msg.args[0],
                        msg.args[1],
                        msg.args[2],
                        msg.args[3],
                    },
                },
                .dest = IPC_DEST_MAIN,
                .flags = IPC_FLAG_WANTRESP
            };

            if (!ipc_send_message(&ipc_msg, &ipc_resp))
                break;

            ret.error = ipc_resp.resp.error;
            ret.ret = ipc_resp.resp.ret;

            break;
        }

        case KVMCHAND_CMD_CLIENTINIT:
        {
            uint32_t dom = client_get_domain(client);
            struct ipc_message ipc_resp, ipc_msg = {
                .type = IPC_TYPE_CMD,
                .cmd = {
                    .command = MAIN_IPC_CMD_VCHAN_CONN,
                    .args = {
                        msg.args[0],
                        dom,
                        msg.args[1],
                    },
                },
                .dest = IPC_DEST_MAIN,
                .flags = IPC_FLAG_WANTRESP
            };

            if (!ipc_send_message(&ipc_msg, &ipc_resp))
                break;

            ret.error = ipc_resp.resp.error;
            ret.ret = ipc_resp.resp.ret;

            break;
        }

        case KVMCHAND_CMD_CLOSE:
        {
            uint32_t dom = client_get_domain(client);
            struct ipc_message ipc_resp, ipc_msg = {
                .type = IPC_TYPE_CMD,
                .cmd = {
                    .command = MAIN_IPC_CMD_VCHAN_CLOSE,
                    .args = {
                        dom,
                        msg.args[0],
                        msg.args[1]
                    },
                },
                .dest = IPC_DEST_MAIN,
                .flags = IPC_FLAG_WANTRESP
            };

            if (!ipc_send_message(&ipc_msg, &ipc_resp))
                break;

            ret.error = ipc_resp.resp.error;

            break;
        }

        default:
            /* unimplemented */
            log(LOGL_INFO, "Unimplemented command received!");
            ret.ret = -1;
            break;
    }

    if (RB_SUCCESS != ringbuf_sec_write(&conn->data.host_to_client_rb, &conn->data.hdr->host_to_client_pub,
                                        &ret, sizeof(struct kvmchand_ret))) {
        log(LOGL_ERROR, "Failed to receive message from client kvmchand!");
        return false;
    }

    return true;
}

static void *conn_listener_thread(void *client_) {
    struct client_info *client = client_;
    // connection 0 is between the client and this daemon
    struct conn_info *conn = client->connections.data[0];

    // Map shared memory region
    void *shm = mmap(NULL, DAEMON_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                     conn->shmfd, 0);
    if (shm == (void *)-1) {
        log(LOGL_ERROR, "Failed to mmap shared region: %m");
        return NULL;
    }
    shmem_hdr_t *hdr = shm;
    hdr->magic = SHMEM_MAGIC;

    // Setup ring buffers
    conn->data.hdr = hdr;
    if (RB_SUCCESS != ringbuf_sec_init(&conn->data.host_to_client_rb, &hdr->host_to_client_pub,
                          (uint8_t *)shm + DAEMON_H2C_OFFSET, DAEMON_RING_SIZE,
                          RINGBUF_FLAG_BLOCKING, RINGBUF_DIRECTION_WRITE,
                          conn->incoming_eventfds[0], conn->outgoing_eventfds[0]))
        goto fail;

    if (RB_SUCCESS != ringbuf_sec_init(&conn->data.client_to_host_rb, &hdr->client_to_host_pub,
                          (uint8_t *)shm + DAEMON_C2H_OFFSET, DAEMON_RING_SIZE,
                          RINGBUF_FLAG_BLOCKING, RINGBUF_DIRECTION_READ,
                          conn->incoming_eventfds[1], conn->outgoing_eventfds[1]))
        goto fail;

    // Epoll on the incoming eventfds as well as the listener kill eventfd
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto fail;
    if (add_epoll_fd(epoll_fd, conn->incoming_eventfds[1], EPOLLIN) < 0)
        goto fail_epoll_create;
    if (add_epoll_fd(epoll_fd, client->listener_eventfd, EPOLLIN) < 0)
        goto fail_epoll_create;

    // Event loop
    struct epoll_event events[5];
    int event_count;
    for(;;) {
        event_count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
        for (int i=0; i<event_count; i++) {
            int cur_fd = events[i].data.fd;

            // Exit if event is from listener kill eventfd
            if (cur_fd == client->listener_eventfd)
                goto fail_epoll_create;

            if (!handle_kvmchand_message(client, conn)) {
                log(LOGL_ERROR, "Couldn't handle message from client! Continuing...");
                continue;
            }

            // Flush eventfd
            uint64_t buf;
            ignore_value(read(cur_fd, &buf, 8));
        }
    }

fail_epoll_create:
    close(epoll_fd);
fail:
    log(LOGL_INFO, "Stopping listener thread.");
    munmap(shm, DAEMON_SHM_SIZE);
    return NULL;
}

/**
 * Spawn a thread to handle kvmchand messages from a given client
 * @param server ivshmem server
 * @param conn   conn_info for client to handle
 * @return       success?
 */
static bool spawn_conn_listener_thread(struct client_info *client) {

    client->listener_eventfd = eventfd(0, 0);
    if (client->listener_eventfd < 0)
        return false;

    if (pthread_create(&client->listener, NULL, conn_listener_thread, client))
        return false;

    return true;
}

static bool do_init_sequence(struct ivshmem_server *server, int fd) {
    struct conn_info *conn = NULL;
    struct client_info *info = NULL;

    // Obtain the PID of the client
    socklen_t len = sizeof(struct ucred);
    struct ucred cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
        goto fail;

    log(LOGL_INFO, "Got connection from PID: %u", cred.pid);

    // Obtain client info
    info = get_client(server, cred.pid, true, NULL);
    if (!info)
        goto fail;

    // ID that corresponds to the IVPosition register.
    // For the first connection, id is always 1.
    int32_t id;

    // Create an entry for this connection in the client_info
    conn = malloc_w(sizeof(struct conn_info));
    conn->socfd = -1; conn->shmfd = -1;
    int eventfds[NUM_EVENTFDS * 2];
    for (size_t i=0; i<ARRAY_SIZE(eventfds); i++)
        eventfds[i] = -1; // Initialize to -1 to make cleanup easier

    bool first_conn = false;
    if (info->connections.count == 0) {
        first_conn = true;

        // Allocate eventfds
        for (size_t i=0; i<ARRAY_SIZE(eventfds); i++) {
            if ((eventfds[i] = eventfd(0, 0)) < 0)
                goto fail;

            if (i < NUM_EVENTFDS)
                conn->incoming_eventfds[i] = eventfds[i];
            else
                conn->outgoing_eventfds[i - NUM_EVENTFDS] = eventfds[i];
        }


        // The first connection is for communicating with this daemon
        if ((conn->shmfd = memfd_create("kvmchand_shm", 0)) < 0)
            goto fail;
        if (ftruncate(conn->shmfd, DAEMON_SHM_SIZE) < 0)
            goto fail;

        // Set IVPosition to 1
        id = 1;
    } else {
        // Grab the first entry in the pending connections vector and use
        // the data it contains to initalize this connection.
        if (info->pending.count == 0) {
            log(LOGL_ERROR, "Unexpected connection from QEMU on pid %u (no pending).", cred.pid);
            goto fail;
        }

        struct pending_conn *p = info->pending.data[0];
        conn->ivposition = p->ivposition;
        conn->shmfd = p->shmfd;
        id = p->ivposition;
        for (size_t i=0; i<ARRAY_SIZE(eventfds); i++) {
            eventfds[i] = p->eventfds[i];
        }

        vec_voidp_remove(&info->pending, 0);
    }
    conn->socfd = fd;
    for (size_t i=0; i<ARRAY_SIZE(eventfds); i++) {
        if (i < NUM_EVENTFDS)
            conn->incoming_eventfds[i] = eventfds[i];
        else
            conn->outgoing_eventfds[i - NUM_EVENTFDS] = eventfds[i];
    }


    if (!vec_voidp_push_back(&info->connections, conn))
        goto fail;

    // Send information to client
    if (send_ivshmem_msg(fd, 0, -1) < 0) // Protocol version (0)
        goto fail;

    if (send_ivshmem_msg(fd, id, -1) < 0) // Domain ID
        goto fail;

    if (send_ivshmem_msg(fd, -1, conn->shmfd) < 0) // shm fd
        goto fail;

    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (send_ivshmem_msg(fd, 0, conn->incoming_eventfds[i]) < 0) // peer eventfds (always id=0)
            goto fail;
    }

    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (send_ivshmem_msg(fd, id, conn->outgoing_eventfds[i]) < 0) // outgoing eventfds
            goto fail;
    }

    // If this is the first connection for the client,
    // spawn a listener thread
    if (first_conn && !spawn_conn_listener_thread(info))
        goto fail;

    return true;

fail:
    if (conn) {
        if (conn->socfd >= 0) close(conn->socfd);
        if (conn->shmfd >= 0) close(conn->shmfd);
        for (size_t i=0; i<ARRAY_SIZE(eventfds); i++)
            if (eventfds[i] > 0)
                close(eventfds[i]);

        free(conn);
    }

    // Only free info if it was created by us (and therefore has 0 connections)
    if (info && info->connections.count == 0)
        conn_info_destructor(info);

    return false;
}

static bool remove_connection_by_fd(struct ivshmem_server *server, int fd) {
    // Get client info by pid
    socklen_t len = sizeof(struct ucred);
    struct ucred cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
        return false;

    size_t client_i;
    struct client_info *client = get_client(server, cred.pid, false, &client_i);
    if (!client)
        return false;

    bool found_conn = false;
    size_t conn_i;
    for (size_t i=0; i<client->connections.count; i++) {
        struct conn_info *conn = client->connections.data[i];
        if (conn->socfd == fd) {
            found_conn = true;
            conn_i = i;
            break;
        }
    }
    if (!found_conn)
        return false;

    vec_voidp_remove(&client->connections, conn_i);

    // If no connections left, remove client
    if (client->connections.count == 0)
        vec_voidp_remove(&server->clients, client_i);

    return true;
}

static bool remove_connection_by_ivpos(struct ivshmem_server *server, pid_t pid,
                                       uint32_t ivposition) {

    struct client_info *client = get_client(server, pid, false, NULL);
    if (!client) {
        log(LOGL_ERROR, "remove_connection failed: no such client at pid %u\n", pid);
        return false;
    }

    bool found_conn = false;
    size_t conn_i;
    for (size_t i=0; i<client->connections.count; i++) {
        struct conn_info *conn = client->connections.data[i];
        if (conn->ivposition == ivposition) {
            found_conn = true;
            conn_i = i;
            break;
        }
    }
    if (!found_conn) {
        log(LOGL_ERROR, "remove_connection failed: no such connection at pid %u\n", pid);
        return false;
    }

    vec_voidp_remove(&client->connections, conn_i);

    return true;
}

/**
 * Register an upcomming connection from a QEMU process.
 * @param server   server instance to register on
 * @param pid      PID of QEMU process that will connect
 * @param shmfd    fd to shared memory
 * @param eventfds array of 4 eventfds to use
 * @param flip_fds whether or not to flip incoming/outgoing eventfd order
 * @return       newly allocated ivposition, or 0 on failure
 */
static uint32_t register_conn(struct ivshmem_server *server, pid_t pid, int shmfd,
                              int *eventfds, bool flip_fds) {
    struct client_info *client = get_client(server, pid, false, NULL);
    if (!client)
        goto fail;

    struct pending_conn *pending = malloc_w(sizeof(struct pending_conn));
    pending->shmfd = shmfd;
    pending->ivposition = client_allocate_ivposition(client);
    if (pending->ivposition == 0)
        goto fail_pending;

    if (!vec_voidp_push_back(&client->pending, pending))
        goto fail_ivposition;

    if (flip_fds) {
        // Flip incoming and outgoing eventfds
        pending->eventfds[0] = eventfds[2];
        pending->eventfds[1] = eventfds[3];
        pending->eventfds[2] = eventfds[0];
        pending->eventfds[3] = eventfds[1];
    } else {
        // 1:1 copy
        pending->eventfds[0] = eventfds[0];
        pending->eventfds[1] = eventfds[1];
        pending->eventfds[2] = eventfds[2];
        pending->eventfds[3] = eventfds[3];
    }

    return pending->ivposition;

fail_ivposition:
    client_free_ivposition(client, pending->ivposition);
fail_pending:
    free(pending);
fail:
    return 0;
}

/**
 * Handle IPC messages from other kvmchand processes
 */
static void handle_ipc_message(struct ipc_message *msg) {
    struct ipc_cmd *cmd = &msg->cmd;
    struct ipc_message response = {
        .type = IPC_TYPE_RESP,
        .resp.error = true,
        .dest = msg->src,
        .fd_count = 0,
        .id = msg->id
    };

    switch(cmd->command) {
        case IVSHMEM_IPC_CMD_REGISTER_CONN:
        {
            // Register up to two pending connections
            uint32_t ivpositions[2] = {0};
            int shmfd = msg->fds[0];
            int *eventfds = &msg->fds[1];

            // Register first connection (mandatory)
            pid_t pid = cmd->args[0];
            ivpositions[0] = register_conn(&g_server, pid, shmfd, eventfds, false);

            // Register second connection if present
            if ((pid = cmd->args[1]) > 0) {
                ivpositions[1] = register_conn(&g_server, pid, shmfd, eventfds, true);
            }

            response.resp.ret = ivpositions[0];
            response.resp.ret2 = ivpositions[1];
            response.resp.error = (response.resp.ret == 0 && response.resp.ret2 == 0);

            break;
        }

        case IVSHMEM_IPC_CMD_GET_CONN_FDS:
        {
            response.resp.error = !get_conn_fds(&g_server, (pid_t)cmd->args[0], (uint32_t)cmd->args[1],
                                                response.fds);

            if (!response.resp.error) {
                response.fd_count = 5;
                response.flags = IPC_FLAG_FD;
            }

            break;
        }

        case IVSHMEM_IPC_CMD_UNREGISTER_CONN:
        {
            bool success[2] = {true, true};
            for (uint8_t i=0; i<2; i++) {
                pid_t pid = (pid_t)cmd->args[i];
                uint32_t ivposition = (uint32_t)cmd->args[i + 2];

                if (pid <= 0)
                    continue;

                success[i] = remove_connection_by_ivpos(&g_server, pid, ivposition);
            }

            response.resp.error = !success[0] || !success[1];
            break;
        }

        default:
            log_BUG("Unknown IPC command received in ivshmem loop: %"PRIu64, cmd->command);
    }

    if (msg->flags & IPC_FLAG_WANTRESP) {
        if (!ipc_send_message(&response, NULL))
            log_BUG("Unable to send response to IPC message!");
    }
}

void run_ivshmem_loop(int mainsoc) {
    if (!ipc_start(mainsoc, IPC_DEST_IVSHMEM, handle_ipc_message))
        goto error;

    // Set up the socket and bind it
    int socfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socfd < 0)
        goto error;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, IVSHMEM_SOCK_PATH, sizeof(addr.sun_path)-1);
    if (bind(socfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0)
        goto error;

    // Set proper permissions on the socket
    if (chmod(IVSHMEM_SOCK_PATH, 0666) < 0)
        goto error;

    // Install exit handler to remove socket
    if (!install_exit_callback(cleanup_socket_path, (void *)IVSHMEM_SOCK_PATH))
        goto error;

    // Start listening
    if (listen(socfd, 5) < 0)
        goto error;

    // Initialize epoll
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto error;
    if (add_epoll_fd(epoll_fd, socfd, EPOLLIN) < 0)
        goto error;

    // Initialize ivshmem_server
    g_server.socfd = socfd;
    if (!vec_voidp_init(&g_server.clients, 10, client_info_destructor))
        goto error;

    // Poll for events
    struct epoll_event events[5];
    int event_count;

    for(;;) {
        event_count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
        for(int i=0; i<event_count; i++) {
            if (events[i].data.fd == socfd) {
                // Connection request on the socket, accept it
                int fd = accept(socfd, NULL, NULL);

                if (!do_init_sequence(&g_server, fd)) {
                    log(LOGL_WARN, "Couldn't do init sequence with client on fd %d: %m", fd);
                    close(fd);
                    continue;
                }

                // Add connected fd to epoll
                if (add_epoll_fd(epoll_fd, fd, EPOLLIN) < 0) {
                    log(LOGL_WARN, "Couldn't add fd to epoll set: %m");
                    goto error;
                }
            } else {
                // Event from a client fd, check if it was closed
                int fd = events[i].data.fd;
                char buf[1];
                ssize_t n = read(fd, buf, 1);
                if (n != 0) {
                    log(LOGL_ERROR, "Received unknown message from client on fd %d", fd);
                    continue;
                }

                // Client disconnected
                log(LOGL_INFO, "Client disconnected! fd: %d", fd);

                if (del_epoll_fd(epoll_fd, fd) < 0) {
                    log(LOGL_WARN, "Failed to remove fd %d from epoll set!", fd);
                }

                // Remove connection
                if (!remove_connection_by_fd(&g_server, fd)) {
                    log(LOGL_ERROR, "Failed to remove connection data!");
                    goto error;
                }
            }
        }
    }

error:
    log(LOGL_ERROR, "ivshmem server encountered fatal error: %m!");
    bail_out();
}
