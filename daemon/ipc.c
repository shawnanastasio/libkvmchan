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
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "ipc.h"
#include "util.h"

struct dispatcher_data {
    int socfd;

    // Incremented for each new message
    uint32_t id_counter;

    // Request queue of ipc_messages to send
    struct vec_voidp requests;
    pthread_cond_t requests_cond;
    pthread_mutex_t requests_mutex;
};

struct receiver_data {
    int socfd;
    void (*message_handler)(struct ipc_message *);
    struct vec_voidp responses;
    pthread_mutex_t responses_mutex;
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
} g_ipc_data;

static void response_destructor(void *resp_) {
    struct response *resp = resp_;
    pthread_cond_destroy(&resp->cond);
    pthread_mutex_destroy(&resp->mutex);
    free(resp);
}

static bool dispatcher_data_init(struct dispatcher_data *data, int socfd) {
    data->socfd = socfd;
    data->id_counter = 0;

    if (!vec_voidp_init(&data->requests, 10, free_destructor))
        return false;

    if (pthread_cond_init(&data->requests_cond, NULL)) {
        vec_voidp_destroy(&data->requests);
        return false;
    }

    pthread_mutexattr_t attr;
    ASSERT(!pthread_mutexattr_init(&attr));
    ASSERT(!pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
    if (pthread_mutex_init(&data->requests_mutex, &attr)) {
        pthread_cond_destroy(&data->requests_cond);
        vec_voidp_destroy(&data->requests);
        return false;
    }

    return true;
}

static bool receiver_data_init(struct receiver_data *data, int socfd,
                               void (*message_handler)(struct ipc_message *)) {
    data->socfd = socfd;
    data->message_handler = message_handler;

    if (!vec_voidp_init(&data->responses, 10, response_destructor))
        return false;

    if (pthread_mutex_init(&data->responses_mutex, NULL)) {
        vec_voidp_destroy(&data->responses);
        return false;
    }

    return true;
}

static bool push_request(struct dispatcher_data *data, struct ipc_message *msg,
                         uint32_t *id_out) {
    bool res = false;
    ASSERT(!pthread_mutex_lock(&data->requests_mutex));

    // Update special fields (id, remote)
    msg->id = data->id_counter++;
    *id_out = msg->id;

    if (!vec_voidp_push_back(&data->requests, msg))
        goto out;

    res = true;
    ASSERT(!pthread_cond_signal(&data->requests_cond));
out:
    ASSERT(!pthread_mutex_unlock(&data->requests_mutex));
    return res;
}

static ssize_t socmsg_send(int socfd, void *data, size_t len, int fd) {
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
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
        .msg_control = (fd > 0) ? u.cmsgbuf : NULL,
        .msg_controllen = (fd > 0) ? CMSG_LEN(sizeof(int)) : 0,
    };

    /* Initialize the control message to hand off the fd */
    if (fd > 0) {
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(cmsg) = fd;
    }

    return sendmsg(socfd, &msg, 0);
}

static ssize_t socmsg_recv(int socfd, void *buf, size_t len, int *fd_out) {
    ssize_t s;
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
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
        .msg_controllen = CMSG_LEN(sizeof(int))
    };

    if ((s = recvmsg(socfd, &msg, 0)) < 0)
        return s;

    if (fd_out) {
        cmsg = CMSG_FIRSTHDR(&msg);
        if (msg.msg_controllen != CMSG_LEN(sizeof(int))) {
            *fd_out = -1;
            goto out;
        }

        *fd_out = *((int *)CMSG_DATA(cmsg));
    }

out:
    return s;
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

static void *client_dispatcher_thread(void *data_) {
    struct dispatcher_data *data = data_;

    ASSERT(!pthread_mutex_lock(&data->requests_mutex));
    for(;;) {
        if (data->requests.count == 0)
            goto skip;

        log(LOGL_INFO, "DEBUG: Got request!");

        // Send all pending requests
        size_t initial_count = data->requests.count;
        for (size_t i=0; i<initial_count; i++) {
            log(LOGL_INFO, "SENDING MESSAGE!");
            struct ipc_message *msg = data->requests.data[0];
            ASSERT(msg);

            int fd = (msg->flags & IPC_FLAG_FD) ? msg->fd : -1;
            if (socmsg_send(data->socfd, msg, sizeof(struct ipc_message), fd) < 0) {
                log(LOGL_ERROR, "BUG! Unable to send IPC message: %m! fd: %d", data->socfd);
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
        int incoming_fd = -1;
        ssize_t n = socmsg_recv(data->socfd, &msg, sizeof(struct ipc_message),
                                &incoming_fd);
        if (n == 0) {
            log(LOGL_ERROR, "BUG! IPC socket reached EOF!");
            bail_out();
        }
        if (n < 0) {
            log(LOGL_ERROR, "BUG! Failed to read from IPC socket!");
            bail_out();
        }

        // Insert fd into struct if received
        if (msg.flags & IPC_FLAG_FD) {
            ASSERT(incoming_fd > 0);
            msg.fd = incoming_fd;
        }

        // If this isn't a response, call the message handler
        if (msg.type != IPC_TYPE_RESP) {
            if (data->message_handler)
                data->message_handler(&msg);
            continue;
        }

        // Otherwise, get response struct
        struct response *resp = get_response(data, msg.id);
        ASSERT(resp);

        // Lock struct and write message to it
        ASSERT(!pthread_mutex_lock(&resp->mutex));

        memcpy(&resp->message, &msg, sizeof(struct ipc_message));
        resp->message_valid = true;
        ASSERT(!pthread_cond_signal(&resp->cond));

        ASSERT(!pthread_mutex_unlock(&resp->mutex));
    }

    return NULL;
}

// Server-facing API

/**
 * Read an incoming IPC message (used by main only)
 */
bool ipc_server_receive_message(int socfd, struct ipc_message *out) {
    int incoming_fd;
    ssize_t n = socmsg_recv(socfd, out, sizeof(struct ipc_message), &incoming_fd);
    if (n <= 0)
        return false;

    if (out->flags & IPC_FLAG_FD) {
        if (incoming_fd < 0) {
            errno = EINVAL;
            return false;
        }

        out->fd = incoming_fd;
    }

    return true;
}

/**
 * Send an IPC message (used by main only)
 */
bool ipc_server_send_message(int socfd, struct ipc_message *msg) {
    int fd = (msg->flags & IPC_FLAG_FD) ? msg->fd : -1;
    return (socmsg_send(socfd, msg, sizeof(struct ipc_message), fd) >= 0);
}


// Client-facing API

/**
 * Initialize g_ipc structure and spawn dispatcher/receiver threads.
 *
 * @param socfd            socket connection to main thread
 * @param message_handler  handler for received non-response messages
 * @return       success?
 */
bool ipc_start(int socfd, void (*message_handler)(struct ipc_message *)) {
    if (!dispatcher_data_init(&g_ipc_data.dispatcher_data, socfd))
        goto fail;

    if (!receiver_data_init(&g_ipc_data.receiver_data, socfd, message_handler))
        goto fail;

    // Spawn dispatcher thread
    int ret;
    if ((ret = pthread_create(&g_ipc_data.dispatcher_thread, NULL, client_dispatcher_thread,
                              &g_ipc_data.dispatcher_data))) {
        errno = ret;
        goto fail;
    }

    // Spawn receiver thread
    if ((ret = pthread_create(&g_ipc_data.receiver_thread, NULL, client_receiver_thread,
                              &g_ipc_data.receiver_data))) {
        errno = ret;
        goto fail;
    }

    return true;
fail:
    log(LOGL_ERROR, "Failed to start dispatcher: %m!");
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

    uint32_t id;
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
