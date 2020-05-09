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
 * This file contains the Inter-Process Communication (IPC) mechanisms
 * used for communication between forked kvmchand processes.
 */

#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#include "ipc.h"
#include "util.h"

struct dispatcher_data {
    bool is_server;
    union {
        int socfd; // is_server = false
        int socfds[NUM_IPC_SOCKETS]; // is_server = true
    };

    // Incremented for each new message
    uint32_t id_counter;

    // Request queue of ipc_messages to send
    struct vec_voidp requests;
    pthread_cond_t requests_cond;
    pthread_mutex_t requests_mutex;
};

struct receiver_data {
    bool is_server;
    union {
        int socfd; // is_server = false
        int socfds[NUM_IPC_SOCKETS]; // is_server = true
    };

    void (*message_handler)(struct ipc_message *);

    // List of responses received/to be received.
    struct vec_voidp responses;
    pthread_mutex_t responses_mutex;

    // Queue of messages to handle. FIFO.
    struct vec_voidp message_queue;
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
};

struct response {
    uint32_t id;

    /**
     * Caller waits on the condition after sending a request.
     * When the condition is notified, the request data is ready to be read.
     */
    pthread_cond_t cond;
    pthread_mutex_t mutex;

    // Response content. Valid after cond notifies
    struct ipc_message message;
    bool message_valid;
};

// Global IPC data for this process
struct ipc_data {
    struct dispatcher_data dispatcher_data;
    struct receiver_data receiver_data;
    pthread_t dispatcher_thread;
    pthread_t receiver_thread;
    pthread_t response_dispatcher_thread;
    uint8_t src;
} g_ipc_data;

static void response_destructor(void *resp_) {
    struct response *resp = resp_;
    pthread_cond_destroy(&resp->cond);
    pthread_mutex_destroy(&resp->mutex);
    free(resp);
}

static bool dispatcher_data_init(struct dispatcher_data *data, bool is_server, int socfd,
                                 int *socfds) {
    data->is_server = is_server;
    if (is_server) {
        for (uint8_t i=0; i<NUM_IPC_SOCKETS; i++)
            data->socfds[i] = socfds[i];
    } else {
        data->socfd = socfd;
    }
    data->id_counter = 0;

    if (!vec_voidp_init(&data->requests, 10, free_destructor))
        goto fail;

    if (pthread_cond_init(&data->requests_cond, NULL))
        goto fail_requests;

    if (pthread_mutex_init(&data->requests_mutex, NULL))
        goto fail_requests_cond;

    return true;

fail_requests_cond:
    pthread_cond_destroy(&data->requests_cond);
fail_requests:
    vec_voidp_destroy(&data->requests);
fail:
    return false;
}

static bool receiver_data_init(struct receiver_data *data, bool is_server, int socfd,
                               int *socfds, void (*message_handler)(struct ipc_message *)) {
    data->message_handler = message_handler;
    data->is_server = is_server;
    if (is_server) {
        for (uint8_t i=0; i<NUM_IPC_SOCKETS; i++)
            data->socfds[i] = socfds[i];
    } else {
        data->socfd = socfd;
    }

    if (!vec_voidp_init(&data->message_queue, 10, free_destructor))
        goto fail;
    if (pthread_mutex_init(&data->queue_mutex, NULL))
        goto fail_message_queue;
    if (pthread_cond_init(&data->queue_cond, NULL))
        goto fail_queue_mutex;
    if (!vec_voidp_init(&data->responses, 10, response_destructor))
        goto fail_queue_cond;
    if (pthread_mutex_init(&data->responses_mutex, NULL))
        goto fail_responses;

    return true;

fail_responses:
    vec_voidp_destroy(&data->responses);
fail_queue_cond:
    pthread_cond_destroy(&data->queue_cond);
fail_queue_mutex:
    pthread_mutex_destroy(&data->queue_mutex);
fail_message_queue:
    vec_voidp_destroy(&data->message_queue);
fail:
    return false;
}

static inline uint8_t dest_to_socket(uint8_t dest) {
    switch(dest) {
        case IPC_DEST_IVSHMEM:
            return IPC_SOCKET_IVSHMEM;
        case IPC_DEST_LIBVIRT:
            return IPC_SOCKET_LIBVIRT;
        case IPC_DEST_VFIO:
            return IPC_SOCKET_VFIO;
        case IPC_DEST_LOCALHANDLER:
            return IPC_SOCKET_LOCALHANDLER;
        default:
            log_BUG("Unknown IPC destination %u!", dest);
    }
}

static ssize_t ipcmsg_send(int socfd, void *data, size_t len, int fds[IPC_FD_MAX], uint8_t fd_count) {
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int) * IPC_FD_MAX)];
        struct cmsghdr align;
    } u;

    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = data, .iov_len = len };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = 0,
        .msg_control = fds ? u.cmsgbuf : NULL,
        .msg_controllen = fds ? CMSG_LEN(sizeof(int) * fd_count) : 0,
    };

    /* Initialize the control message to hand off the fds */
    if (fds) {
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);

        for (uint8_t i=0; i<fd_count; i++) {
            ((int *)CMSG_DATA(cmsg))[i] = fds[i];
        }
    }

    return sendmsg(socfd, &msg, 0);
}

static ssize_t ipcmsg_recv(int socfd, void *buf, size_t len, int fds_out[IPC_FD_MAX]) {
    ssize_t s;
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int) * IPC_FD_MAX)];
        struct cmsghdr align;
    } u;

    struct cmsghdr *cmsg;
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_flags = 0,
        .msg_control = u.cmsgbuf,
        .msg_controllen = CMSG_LEN(sizeof(int) * IPC_FD_MAX)
    };

    if ((s = recvmsg(socfd, &msg, 0)) < 0)
        return s;

    if (fds_out) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (msg.msg_controllen < CMSG_LEN(sizeof(int))) {
            fds_out[0] = -1;
            goto out;
        }

        // Copy all fds to fds_out
        uint8_t *in = CMSG_DATA(cmsg);
        uint8_t *max = in + msg.msg_controllen;
        uint8_t i=0;
        while (in + sizeof(int) <= max && i < IPC_FD_MAX) {
            fds_out[i++] = *(int *)in;
            in += sizeof(int);
        }

        // Set any remaining fds to -1
        for (; i<IPC_FD_MAX; i++) {
            fds_out[i] = -1;
        }
    }

out:
    return s;
}

static bool push_request(struct dispatcher_data *data, struct ipc_message *msg,
                         uint32_t *id_out) {
    bool res = false;
    ASSERT(!pthread_mutex_lock(&data->requests_mutex));

    // Update ID field if this isn't a response
    if (msg->type == IPC_TYPE_CMD) {
        msg->id = data->id_counter++;
        *id_out = msg->id;
    }

    if (!vec_voidp_push_back(&data->requests, msg))
        goto out;

    res = true;
    ASSERT(!pthread_cond_signal(&data->requests_cond));
out:
    ASSERT(!pthread_mutex_unlock(&data->requests_mutex));
    return res;
}

static struct response *get_response(struct receiver_data *queue, uint32_t id) {
    struct response *ret = NULL;
    ASSERT(!pthread_mutex_lock(&queue->responses_mutex));

    // Look for existing response
    for (size_t i=0; i<queue->responses.count; i++) {
        struct response *cur = queue->responses.data[i];
        if (cur->id == id) {
            ret = cur;
            goto out;
        }
    }

    // No response found, allocate one
    struct response *resp = malloc_w(sizeof(struct response));
    resp->id = id;
    if (pthread_cond_init(&resp->cond, NULL)) {
        free(resp);
        goto out;
    }
    if (pthread_mutex_init(&resp->mutex, NULL)) {
        pthread_cond_destroy(&resp->cond);
        free(resp);
        goto out;
    }
    resp->message_valid = false;

    if (!vec_voidp_push_back(&queue->responses, resp)) {
        pthread_mutex_destroy(&resp->mutex);
        pthread_cond_destroy(&resp->cond);
        free(resp);
        goto out;
    }

    ret = resp;

out:
    ASSERT(!pthread_mutex_unlock(&queue->responses_mutex));
    return ret;
}

static bool delete_response(struct receiver_data *queue, uint32_t id) {
    bool ret = false;
    ASSERT(!pthread_mutex_lock(&queue->responses_mutex));

    for (size_t i=0; i<queue->responses.count; i++) {
        struct response *cur = queue->responses.data[i];
        if (cur->id == id) {
            vec_voidp_remove(&queue->responses, i);
            ret = true;
            goto out;
        }
    }

out:
    ASSERT(!pthread_mutex_unlock(&queue->responses_mutex));
    return ret;
}

static bool server_receive_message(int socfd, struct ipc_message *out) {
    int incoming_fds[IPC_FD_MAX];
    ssize_t n = ipcmsg_recv(socfd, out, sizeof(struct ipc_message), incoming_fds);
    if (n <= 0)
        return false;

    if (out->flags & IPC_FLAG_FD) {
        for (uint8_t i=0; i<out->fd_count; i++) {
            if (incoming_fds[i] == -1) {
                errno = EINVAL;
                return false;
            }
        }

        memcpy(out->fds, incoming_fds, sizeof(int) * IPC_FD_MAX);
    }

    return true;
}

static void register_response(struct receiver_data *rdata, struct ipc_message *cur) {
    // Write this message to the appropriate response handle
    struct response *resp = get_response(rdata, cur->id);
    ASSERT(resp);

    // Lock struct and write message to it
    ASSERT(!pthread_mutex_lock(&resp->mutex));

    memcpy(&resp->message, cur, sizeof(struct ipc_message));
    resp->message_valid = true;
    ASSERT(!pthread_cond_signal(&resp->cond));

    ASSERT(!pthread_mutex_unlock(&resp->mutex));
}

static void *response_dispatcher_thread(void *rdata_) {
    struct receiver_data *rdata = rdata_;

    ASSERT(!pthread_mutex_lock(&rdata->queue_mutex));
    for(;;) {
        while (rdata->message_queue.count > 0) {
            struct ipc_message *cur = rdata->message_queue.data[0];

            // Call message handler
            rdata->message_handler(cur);

            vec_voidp_remove(&rdata->message_queue, 0);
        }

        // Wait for more messages
        ASSERT(!pthread_cond_wait(&rdata->queue_cond, &rdata->queue_mutex));
    }

    return NULL;
}

static void *dispatcher_thread(void *data_) {
    struct dispatcher_data *data = data_;

    ASSERT(!pthread_mutex_lock(&data->requests_mutex));
    for(;;) {
        if (data->requests.count == 0)
            goto skip;

        // Send all pending requests
        size_t initial_count = data->requests.count;
        for (size_t i=0; i<initial_count; i++) {
            struct ipc_message *msg = data->requests.data[0];
            ASSERT(msg);

            int *fds = (msg->flags & IPC_FLAG_FD) ? msg->fds : NULL;
            int dest = (data->is_server) ? data->socfds[dest_to_socket(msg->dest)]: data->socfd;
            if (dest < 0)
                log_BUG("Invalid IPC message destination!");

            if (ipcmsg_send(dest, msg, sizeof(struct ipc_message), fds, msg->fd_count) < 0) {
                log(LOGL_ERROR, "Unable to send IPC message: %m! fd: %d", data->socfd);
                goto skip;
            }

            vec_voidp_remove(&data->requests, 0);
        }

    skip:
        ASSERT(!pthread_cond_wait(&data->requests_cond, &data->requests_mutex));
    }

    return NULL;
}

static void *client_receiver_thread(void *data_) {
    struct receiver_data *data = data_;

    for(;;) {
        // Wait for message
        struct ipc_message msg;
        int incoming_fds[IPC_FD_MAX];
        ssize_t n = ipcmsg_recv(data->socfd, &msg, sizeof(struct ipc_message),
                                incoming_fds);
        if (n == 0) {
            log(LOGL_ERROR, "BUG! IPC socket reached EOF!");
            bail_out();
        }
        if (n < 0) {
            log(LOGL_ERROR, "BUG! Failed to read from IPC socket!");
            bail_out();
        }

        // Insert fds into struct if received
        if (msg.flags & IPC_FLAG_FD) {
            for (uint8_t i=0; i<msg.fd_count; i++) {
                ASSERT(incoming_fds[i] != -1);
            }

            memcpy(msg.fds, incoming_fds, sizeof(int) * IPC_FD_MAX);
        }

        if (msg.type == IPC_TYPE_RESP) {
            // If message is response, insert it into response queue
            register_response(data, &msg);
        } else {
            // Otherwise insert message into handle queue so it can be
            // handled by the response dispatcher thread.
            void *msg_copy = malloc_w(sizeof(struct ipc_message));
            memcpy(msg_copy, &msg, sizeof(struct ipc_message));

            ASSERT(!pthread_mutex_lock(&data->queue_mutex));
            ASSERT(vec_voidp_push_back(&data->message_queue, msg_copy));
            ASSERT(!pthread_cond_signal(&data->queue_cond));
            ASSERT(!pthread_mutex_unlock(&data->queue_mutex));
        }
    }

    return NULL;
}

/**
 * Server event loop that listens for messages,
 * forwards them or handles them when applicable.
 */
static void *server_receiver_thread(void *data_) {
    struct receiver_data *data = data_;

    // Initialize epoll to wait for events from event loops
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto fail_errno;

    for (uint8_t i=0; i<NUM_IPC_SOCKETS; i++) {
        if (data->socfds[i] > 0) {
            if (add_epoll_fd(epoll_fd, data->socfds[i], EPOLLIN) < 0)
                goto fail_errno;
        }
    }

    // Wait for events
    struct epoll_event events[5];
    int event_count;
    for(;;) {
        event_count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
        for(int i=0; i<event_count; i++) {
            int cur_fd = events[i].data.fd;

            struct ipc_message msg;
            if (!server_receive_message(cur_fd, &msg))
                goto fail_errno;

            if (msg.dest != IPC_DEST_MAIN) {
                // Message needs to be forwarded
                int socfd = data->socfds[dest_to_socket(msg.dest)];
                if (socfd < 0)
                    log_BUG("Invalid IPC destination %u!", msg.dest);

                int *fds = (msg.flags & IPC_FLAG_FD) ? msg.fds : NULL;
                if (ipcmsg_send(socfd, &msg, sizeof(struct ipc_message), fds, msg.fd_count) < 0)
                    goto fail_errno;

                // Close fds now that we're done forwarding them
                if (fds) {
                    for (uint8_t i=0; i<IPC_FD_MAX; i++) {
                        if (fds[i] != -1)
                            close(fds[i]);
                    }
                }

            } else if (msg.type == IPC_TYPE_RESP) {
                // Message needs to be inserted into response queue
                register_response(data, &msg);
            } else {
                // Message should be added to handle queue
                void *msg_copy = malloc_w(sizeof(struct ipc_message));
                memcpy(msg_copy, &msg, sizeof(struct ipc_message));

                ASSERT(!pthread_mutex_lock(&data->queue_mutex));
                if (!vec_voidp_push_back(&data->message_queue, msg_copy))
                    goto fail_errno;
                ASSERT(!pthread_cond_signal(&data->queue_cond));
                ASSERT(!pthread_mutex_unlock(&data->queue_mutex));
            }
        }
    }

fail_errno:
    log(LOGL_ERROR, "Error encountered while processing IPC messages: %m");
    bail_out();
    return NULL;
}

/**
 * Initialize g_ipc structure, spawn dispatcher/receiver threads,
 * and block for incoming messages. Will not return except on error.
 *
 * @param socfds           array of sockets
 * @param src              IPC_DEST_* that corresponds to this process
 * @param message_handler  handler for received non-response, non-forwarded messages
 */
void ipc_server_start(int socfds[NUM_IPC_SOCKETS],
                      void (*message_handler)(struct ipc_message *)) {
    if (!dispatcher_data_init(&g_ipc_data.dispatcher_data, true, -1, socfds))
        goto fail;

    if (!receiver_data_init(&g_ipc_data.receiver_data, true, -1, socfds, message_handler))
        goto fail;

    // Spawn dispatcher thread
    if ((errno = pthread_create(&g_ipc_data.dispatcher_thread, NULL, dispatcher_thread,
                                &g_ipc_data.dispatcher_data)))
        goto fail;

    // Spawn receiver thread
    if ((errno = pthread_create(&g_ipc_data.receiver_thread, NULL, server_receiver_thread,
                                &g_ipc_data.receiver_data)))
        goto fail;

    // Block and wait for messages to handle from the receiver thread
    response_dispatcher_thread(&g_ipc_data.receiver_data);

fail:
    log(LOGL_ERROR, "Error encountered in IPC server: %m!");
}

/**
 * Initialize g_ipc structure and spawn dispatcher/receiver threads.
 *
 * @param socfd            socket connection to main thread
 * @param src              IPC_DEST_* that corresponds to this process
 * @param message_handler  handler for received non-response messages
 * @return       success?
 */
bool ipc_start(int socfd, uint8_t src, void (*message_handler)(struct ipc_message *)) {
    g_ipc_data.src = src;
    if (!dispatcher_data_init(&g_ipc_data.dispatcher_data, false, socfd, NULL))
        goto fail;

    if (!receiver_data_init(&g_ipc_data.receiver_data, false, socfd, NULL, message_handler))
        goto fail;

    // Spawn dispatcher thread
    if ((errno = pthread_create(&g_ipc_data.dispatcher_thread, NULL, dispatcher_thread,
                                &g_ipc_data.dispatcher_data)))
        goto fail;

    // Spawn receiver thread
    if ((errno = pthread_create(&g_ipc_data.receiver_thread, NULL, client_receiver_thread,
                                &g_ipc_data.receiver_data)))
        goto fail;

    // Spawn response dispatcher thread
    if ((errno = pthread_create(&g_ipc_data.response_dispatcher_thread, NULL,
                                response_dispatcher_thread,
                                &g_ipc_data.receiver_data)))
        goto fail;

    return true;
fail:
    log(LOGL_ERROR, "Failed to start IPC threads: %m!");
    return false;
}

/**
 * Queue a message for delivery
 * @param msg  ipc message to insert into queue
 * @return     success?
 */
bool ipc_send_message(struct ipc_message *msg, struct ipc_message *response) {
    // We have no way of knowing if the passed pointer is on the
    // stack or heap and the vector assumes heap, so copy it first.
    struct ipc_message *msg_h = malloc_w(sizeof(struct ipc_message));
    memcpy(msg_h, msg, sizeof(struct ipc_message));

    // Set src field
    msg_h->src = g_ipc_data.src;

    uint32_t id = 0;
    if (!push_request(&g_ipc_data.dispatcher_data, msg_h, &id)) {
        free(msg_h);
        return false;
    }

    // If no response was requested, return
    if (!response || !(msg->flags & IPC_FLAG_WANTRESP))
        return true;

    // If a response was requested, block until it is received.
    struct response *resp = get_response(&g_ipc_data.receiver_data, id);
    if (!resp) {
        log(LOGL_ERROR, "BUG! Unable to get response struct!");
        return false;
    }

    // Lock response struct
    ASSERT(!pthread_mutex_lock(&resp->mutex));

    // If the response is already valid, just return it
    if (resp->message_valid)
        goto out;

    // Wait for response to become valid
    ASSERT(!pthread_cond_wait(&resp->cond, &resp->mutex));
    ASSERT(resp->message_valid);

out:
    memcpy(response, &resp->message, sizeof(struct ipc_message));

    ASSERT(!pthread_mutex_unlock(&resp->mutex));
    ASSERT(delete_response(&g_ipc_data.receiver_data, resp->id));
    return true;
}
