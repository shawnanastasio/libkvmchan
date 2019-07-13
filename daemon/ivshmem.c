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
 * It is used to manage the shared file memory regions and
 * interrupt eventfds allocated to VMs.
 *
 * For more information, see:
 * https://github.com/qemu/qemu/blob/master/docs/specs/ivshmem-spec.txt
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

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

struct ringbuf_conn_data {
    ringbuf_t host_to_client_rb;
    ringbuf_t client_to_host_rb;
    shmem_hdr_t *hdr;
};

struct conn_info {
    int socfd; // Socket file descriptor
    int shmfd; // Shared memory file descriptor

    int incoming_eventfds[NUM_EVENTFDS]; // eventfds used by client to notify us
    int outgoing_eventfds[NUM_EVENTFDS]; // eventfds used by us to notify client

    // Ringbuffer structures and
    struct ringbuf_conn_data data;
};

struct client_info {
    pid_t pid; // PID of qemu process
    pthread_t listener; // Listener thread handle
    int listener_eventfd; // Eventfd to kill the listener thread
    struct vec_voidp connections; // conn_info vec
};

struct ivshmem_server {
    int socfd; // Main socket fd
    struct vec_voidp clients; // client_info vec
};

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
        return NULL;

    // No matches found, make a new one
    struct client_info *new = malloc_w(sizeof(struct client_info));
    if (!vec_voidp_init(&new->connections, 10, conn_info_destructor)) {
        free(new);
        return NULL;
    }
    new->pid = pid;

    // Insert into vec and return
    if (!vec_voidp_push_back(&server->clients, new)) {
        free(new);
        return NULL;
    }

    if (idx_out)
        *idx_out = server->clients.count - 1;
    return new;
}

static bool handle_kvmchand_message(struct conn_info *conn) {
    struct kvmchand_message msg;
    if (RB_SUCCESS != ringbuf_sec_read(&conn->data.client_to_host_rb, &conn->data.hdr->client_to_host_pub,
                                       &msg, sizeof(struct kvmchand_message))) {
        log(LOGL_ERROR, "Failed to receive message from client kvmchand!");
        return false;
    }

    // Handle command and send response
    struct kvmchand_ret ret;
    switch(msg.command) {
        case KVMCHAND_CMD_HELLO:
            ret.ret = KVMCHAND_API_VERSION;
            break;

        default:
            /* unimplemented */
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
    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (add_epoll_fd(epoll_fd, conn->incoming_eventfds[i], EPOLLIN) < 0)
            goto fail_epoll_create;
    }
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

            if (!handle_kvmchand_message(conn)) {
                log(LOGL_ERROR, "Couldn't handle message from client! Continuing...");
                continue;
            }
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
 * @return success?
 */
static bool spawn_conn_listener_thread(struct client_info *client) {

    client->listener_eventfd = eventfd(0, 0);
    if (client->listener_eventfd < 0)
        return false;

    if (pthread_create(&client->listener, NULL, conn_listener_thread, client))
        return false;

    return true;
}

static int do_init_sequence(struct ivshmem_server *server, int fd) {
    // Obtain the PID of the client
    socklen_t len = sizeof(struct ucred);
    struct ucred cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
        return -1;

    log(LOGL_INFO, "Got connection from PID: %u", cred.pid);

    // Obtain client info
    struct client_info *info = get_client(server, cred.pid, true, NULL);
    if (!info)
        return -1;

    // ID that corresponds to the IVPosition register.
    // For the first connection, id is always 1.
    int64_t id;

    // Create an entry for this connection in the client_info
    struct conn_info *conn = malloc_w(sizeof(struct conn_info));
    conn->socfd = -1; conn->shmfd = -1;
    int eventfds[NUM_EVENTFDS * 2];
    for (size_t i=0; i<ARRAY_SIZE(eventfds); i++)
        eventfds[i] = -1; // Initialize to -1 to make cleanup easier

    bool first_conn = false;
    if (info->connections.count == 0) {
        first_conn = true;

        // The first connection is for communicating with this daemon
        if ((conn->shmfd = memfd_create("kvmchand_shm", 0)) < 0)
            goto fail_malloc_conn;
        if (ftruncate(conn->shmfd, DAEMON_SHM_SIZE) < 0)
            goto fail_malloc_conn;

        // Allocate eventfds
        for (size_t i=0; i<ARRAY_SIZE(eventfds); i++) {
            if ((eventfds[i] = eventfd(0, 0)) < 0)
                goto fail_malloc_conn;

            if (i < NUM_EVENTFDS)
                conn->incoming_eventfds[i] = eventfds[i];
            else
                conn->outgoing_eventfds[i - NUM_EVENTFDS] = eventfds[i];
        }

        // Set IVPosition to 1
        id = 1;
    } else {
        // TODO
        log(LOGL_ERROR, "Unimplemented!");
        goto fail_malloc_conn;
    }
    conn->socfd = fd;

    if (!vec_voidp_push_back(&info->connections, conn))
        goto fail_malloc_conn;

    // Send information to client
    if (send_ivshmem_msg(fd, 0, -1) < 0) // Protocol version (0)
        goto fail_malloc_conn;

    if (send_ivshmem_msg(fd, id, -1) < 0) // Domain ID
        goto fail_malloc_conn;

    if (send_ivshmem_msg(fd, -1, conn->shmfd) < 0) // shm fd
        goto fail_malloc_conn;

    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (send_ivshmem_msg(fd, 0, conn->incoming_eventfds[i]) < 0) // peer eventfds (always id=0)
            goto fail_malloc_conn;
    }

    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (send_ivshmem_msg(fd, id, conn->outgoing_eventfds[i]) < 0) // outgoing eventfds
            goto fail_malloc_conn;
    }

    // If this is the first connection for the client,
    // spawn a listener thread
    if (first_conn && !spawn_conn_listener_thread(info))
        goto fail_malloc_conn;

    return 0;

fail_malloc_conn:
    if (conn->socfd >= 0) close(conn->socfd);
    if (conn->shmfd >= 0) close(conn->shmfd);
    for (size_t i=0; i<ARRAY_SIZE(eventfds); i++)
        if (eventfds[i] > 0)
            close(eventfds[i]);

    free(conn);

    return -1;
}

static bool remove_connection(struct ivshmem_server *server, int fd) {
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
    int conn_i;
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

/**
 * Handle IPC messages from other kvmchand processes
 */
static void handle_ipc_message(struct ipc_message *msg) {

}

void run_ivshmem_loop(int mainsoc, const char *sock_path) {
    if (!ipc_start(mainsoc, IPC_DEST_IVSHMEM, handle_ipc_message))
        goto error;

    // Set up the socket and bind it to the given path
    int socfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socfd < 0)
        goto error;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path)-1);
    if (bind(socfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0)
        goto error;

    // Set proper permissions on the socket
    if (chmod(sock_path, 0777) < 0)
        goto error;

    // Install exit handler to remove socket
    if (!install_exit_callback(cleanup_socket_path, (void *)sock_path))
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
    struct ivshmem_server server = { .socfd = socfd };
    if (!vec_voidp_init(&server.clients, 10, client_info_destructor))
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

                if (do_init_sequence(&server, fd) < 0) {
                    log(LOGL_WARN, "Couldn't do init sequence with client on fd %d: %m", fd);
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
                    //goto error;
                }

                // Client disconnected
                log(LOGL_INFO, "Client disconnected! fd: %d", fd);

                if (del_epoll_fd(epoll_fd, fd) < 0) {
                    log(LOGL_WARN, "Failed to remove fd %d from epoll set!", fd);
                }

                // Remove connection
                if (!remove_connection(&server, fd)) {
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
