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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <linux/vfio.h>

#include "libkvmchan.h"
#include "libkvmchan-priv.h"
#include "ringbuf.h"

// Represents global library state.
struct libkvmchan_state {
    // Socket connection to kvmchand
    int socfd;

    // Connected to host daemon?
    uint32_t flags;
#define STATE_FLAG_CONNECTED (1 << 0) // Connected to kvmchand?

    /**
     * Global libkvmchan lock.
     * It is unclear whether the original libvchan is thread-safe,
     * so we assume it is and include a simple global mutex to
     * prevent races. For applications compiled without -pthread,
     * this may be implemented as a no-op.
     */
    pthread_mutex_t mutex;
};

// Represents single vchan handle. Users only get opaque pointers.
struct libkvmchan {
    uint32_t flags;
#define KVMCHAN_FLAG_SERVER (1 << 0) // We're the server
#define KVMCHAN_FLAG_CONNECTED (1 << 1) // Client connected

    // Pointer to memory region that is shared between server/client
    void *shm;

    // Size of shared memory region
    size_t shm_size;

    // Domain number of peer
    uint32_t peer_dom;

    // Port of vchan
    uint32_t port;

    // Private ring buffer control structures
    ringbuf_t host_to_client_rb;
    ringbuf_t client_to_host_rb;
};

struct libkvmchan_state g_state = {
    .flags = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

//
// Helper functions
//

static ssize_t localmsg_send(int socfd, void *data, size_t len, int fds[KVMCHAND_FD_MAX], uint8_t fd_count) {
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int) * KVMCHAND_FD_MAX)];
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

static ssize_t localmsg_recv(int socfd, void *buf, size_t len, int fds_out[KVMCHAND_FD_MAX]) {
    ssize_t s;
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int) * KVMCHAND_FD_MAX)];
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
        .msg_controllen = CMSG_LEN(sizeof(int) * KVMCHAND_FD_MAX)
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
        while (in + sizeof(int) <= max && i < KVMCHAND_FD_MAX) {
            fds_out[i++] = *(int *)in;
            in += sizeof(int);
        }

        // Set any remaining fds to -1
        for (; i<KVMCHAND_FD_MAX; i++) {
            fds_out[i] = -1;
        }
    }

out:
    return s;
}

static inline void check_client_connected(struct libkvmchan *chan) {
    // If we're a client or the client has already connected, exit
    if (!(chan->flags & KVMCHAN_FLAG_SERVER) || (chan->flags & KVMCHAN_FLAG_CONNECTED))
        return;

    // Wait for the dummy byte from the client
    ringbuf_t *priv = &chan->client_to_host_rb;
    ringbuf_pub_t *pub = &((shmem_hdr_t *)(chan->shm))->client_to_host_pub;

    uint8_t dummy;
    assert(RB_SUCCESS == ringbuf_sec_read(priv, pub, &dummy, 1));
    chan->flags |= KVMCHAN_FLAG_CONNECTED;
}

static bool connect_to_daemon(struct libkvmchan_state *state) {
    // Create and connect socket
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        goto fail;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, LOCALHANDLER_SOCK_PATH, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        goto fail_fd;

    // Perform API version handshake
    struct kvmchand_ret ret;
    struct kvmchand_message msg = {
        .command = KVMCHAND_CMD_HELLO
    };
    if (localmsg_send(fd, &msg, sizeof(msg), NULL, 0) < 0)
        goto fail_fd;
    if (localmsg_recv(fd, &ret, sizeof(ret), NULL) < 0)
        goto fail_fd;

    if (ret.ret != KVMCHAND_API_VERSION) {
        errno = ENOTSUP;
        goto fail_fd;
    }

    state->socfd = fd;
    g_state.flags |= STATE_FLAG_CONNECTED;
    return true;

fail_fd:
    close(fd);
fail:
    return false;
}

static bool do_shm_map(struct libkvmchan *chan, bool is_dom0, int shmfd) {
    if (is_dom0) {
        // mmap shmfd directly
        struct stat statbuf;
        if (fstat(shmfd, &statbuf) < 0)
            return false;

        chan->shm_size = statbuf.st_size;
        chan->shm = mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
        if (chan->shm == (void *)-1)
            return false;

        return true;
    } else {
        // Obtain the offset and size of BAR2 from the VFIO driver
        struct vfio_region_info reg = {
            .argsz = sizeof(reg),
            .index = VFIO_PCI_BAR2_REGION_INDEX
        };
        if (ioctl(shmfd, VFIO_DEVICE_GET_REGION_INFO, &reg) < 0)
            return false;

        // mmap the region
        chan->shm_size = reg.size;
        chan->shm = mmap(NULL, reg.size, PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, reg.offset);
        if (chan->shm == (void *)-1)
            return false;

        return true;
    }
}

static bool get_conn_fds_deferred(uint32_t ivposition, int fds_out[KVMCHAND_FD_MAX]) {
    // When we're running on a guest, it may take up to a few seconds
    // for ivshmem devices to be attached and recognized by the kernel.
    // This means that the kvmchan server would have to block (and thus
    // prevent other threads from talking to it) until the device was
    // attached. Until kvmchand can handle multiple clients at a time,
    // this is unacceptable.
    //
    // For now, my workaround is to simply sleep and try to obtain the
    // fds afterwards. This is gross and stupid but it works for now.
    usleep(4 * 1000 * 1000);

    struct kvmchand_ret ret;
    struct kvmchand_message msg = {
        .command = KVMCHAND_CMD_GET_CONN_FDS,
        .args = {
            ivposition
        }
    };
    if (localmsg_send(g_state.socfd, &msg, sizeof(msg), NULL, 0) < 0)
        return false;
    if (localmsg_recv(g_state.socfd, &ret, sizeof(ret), fds_out) < 0)
        return false;
    if (ret.error) {
        errno = ENOENT;
        return false;
    }

    return true;
}

//
// Public API
//

/**
 * Establish a new vchan.
 * @param domain    domain number that is allowed to connect
 * @param port      port number of new vchan
 * @param read_min  minimum size of read ringbuf
 * @param write_min minimum size of write ringbuf
 */
struct libkvmchan *libkvmchan_server_init(uint32_t domain, uint32_t port, size_t read_min, size_t write_min) {
    struct libkvmchan *ret = NULL;
    if ((errno = pthread_mutex_lock(&g_state.mutex)))
        return NULL;
    if (!(g_state.flags & STATE_FLAG_CONNECTED)) {
        if (!connect_to_daemon(&g_state))
            goto out;
    }

    // Initialize libkvmchan struct
    ret = malloc(sizeof(struct libkvmchan));
    if (!ret)
        goto out;
    ret->flags = KVMCHAN_FLAG_SERVER;
    ret->peer_dom = domain;
    ret->port = port;

    // Send request to kvmchand
    int fds[KVMCHAND_FD_MAX];
    for (size_t i=0; i<KVMCHAND_FD_MAX; i++)
        fds[i] = -1;
    struct kvmchand_ret dret;
    struct kvmchand_message dmsg = {
        .command = KVMCHAND_CMD_SERVERINIT,
        .args = {
            domain,
            port,
            read_min,
            write_min
        }
    };
    if (localmsg_send(g_state.socfd, &dmsg, sizeof(dmsg), NULL, 0) < 0)
        goto out_fail_malloc_ret;
    if (localmsg_recv(g_state.socfd, &dret, sizeof(dret), fds) < 0)
        goto out_fail_malloc_ret;
    if (dret.error) {
        errno = EINVAL;
        goto out_fail_malloc_ret;
    }

    bool is_dom0 = true;
    uint32_t ivposition = dret.ret;
    if (dret.fd_count == 0) {
        // If we're not on dom0, we need to manually request the fds for this connection
        // static bool get_conn_fds_deferred(uint32_t ivposition, int fds_out[KVMCHAND_FD_MAX]) {
        is_dom0 = false;
        if (!get_conn_fds_deferred(ivposition, fds)) {
            goto out_fail_malloc_ret;
        }
    }

    if (!do_shm_map(ret, is_dom0, fds[0]))
        goto out_fail_fds;

    // Calculate size of ring buffers
    size_t rb_size = (ret->shm_size - sizeof(shmem_hdr_t)) / 2;
    size_t h2c_rb_start = sizeof(shmem_hdr_t);
    size_t c2h_rb_start = h2c_rb_start + h2c_rb_start;

    // Initialize ringbufs
    int incoming_eventfds[2] = { fds[1], fds[2] };
    int outgoing_eventfds[2] = { fds[3], fds[4] };
    shmem_hdr_t *shm_hdr = ret->shm;
    shm_hdr->magic = SHMEM_MAGIC;

    if (RB_SUCCESS != ringbuf_sec_init(&ret->host_to_client_rb, &shm_hdr->host_to_client_pub,
                        (uint8_t *)shm_hdr + h2c_rb_start, rb_size, RINGBUF_FLAG_BLOCKING,
                        RINGBUF_DIRECTION_WRITE, incoming_eventfds[0], outgoing_eventfds[0])) {
        errno = EIO;
        goto out_fail_fds;
    }


    if (RB_SUCCESS != ringbuf_sec_init(&ret->client_to_host_rb, &shm_hdr->client_to_host_pub,
                        (uint8_t *)shm_hdr + c2h_rb_start, rb_size, RINGBUF_FLAG_BLOCKING,
                        RINGBUF_DIRECTION_READ, incoming_eventfds[1], outgoing_eventfds[1])) {
        errno = EIO;
        goto out_fail_fds;
    }

    // Success
    goto out;

out_fail_fds:
    for (size_t i=0; i<KVMCHAND_FD_MAX; i++)
        if (fds[i] > 0)
            close(fds[i]);
out_fail_malloc_ret:
    free(ret);
    ret = NULL;
out:
    pthread_mutex_unlock(&g_state.mutex);
    return ret;
}

struct libkvmchan *libkvmchan_client_init(uint32_t domain, uint32_t port) {
    struct libkvmchan *ret = NULL;
    if ((errno = pthread_mutex_lock(&g_state.mutex)))
        return NULL;
    if (!(g_state.flags & STATE_FLAG_CONNECTED)) {
        if (!connect_to_daemon(&g_state))
            goto out;
    }

    // Initialize libkvmchan struct
    ret = malloc(sizeof(struct libkvmchan));
    if (!ret)
        goto out;
    ret->flags = 0;
    ret->peer_dom = domain;
    ret->port = port;

    // Send request to kvmchand
    int fds[KVMCHAND_FD_MAX];
    for (size_t i=0; i<KVMCHAND_FD_MAX; i++)
        fds[i] = -1;
    struct kvmchand_ret dret;
    struct kvmchand_message dmsg = {
        .command = KVMCHAND_CMD_CLIENTINIT,
        .args = {
            domain,
            port
        }
    };
    if (localmsg_send(g_state.socfd, &dmsg, sizeof(dmsg), NULL, 0) < 0)
        goto out_fail_malloc_ret;
    if (localmsg_recv(g_state.socfd, &dret, sizeof(dret), fds) < 0)
        goto out_fail_malloc_ret;
    if (dret.error) {
        errno = EINVAL;
        goto out_fail_malloc_ret;
    }

    bool is_dom0 = true;
    uint32_t ivposition = dret.ret;
    if (dret.fd_count == 0) {
        // If we're not on dom0, we need to manually request the fds for this connection
        // static bool get_conn_fds_deferred(uint32_t ivposition, int fds_out[KVMCHAND_FD_MAX]) {
        is_dom0 = false;
        if (!get_conn_fds_deferred(ivposition, fds)) {
            goto out_fail_malloc_ret;
        }
    }

    if (!do_shm_map(ret, is_dom0, fds[0]))
        goto out_fail_fds;

    // Calculate size of ring buffers
    size_t rb_size = (ret->shm_size - sizeof(shmem_hdr_t)) / 2;
    size_t h2c_rb_start = sizeof(shmem_hdr_t);
    size_t c2h_rb_start = h2c_rb_start + h2c_rb_start;

    // Initialize ringbufs
    int incoming_eventfds[2] = { fds[1], fds[2] };
    int outgoing_eventfds[2] = { fds[3], fds[4] };
    shmem_hdr_t *shm_hdr = ret->shm;

    // Verify magic
    if (shm_hdr->magic != SHMEM_MAGIC) {
        errno = EBADE;
        goto out_fail_fds;
    }

    if (RB_SUCCESS != ringbuf_sec_infer_priv(&ret->host_to_client_rb, &shm_hdr->host_to_client_pub,
                        (uint8_t *)shm_hdr + h2c_rb_start, rb_size, RINGBUF_FLAG_BLOCKING,
                        RINGBUF_DIRECTION_READ, incoming_eventfds[0], outgoing_eventfds[0])) {
        errno = EIO;
        goto out_fail_fds;
    }

    if (RB_SUCCESS != ringbuf_sec_infer_priv(&ret->client_to_host_rb, &shm_hdr->client_to_host_pub,
                        (uint8_t *)shm_hdr + c2h_rb_start, rb_size, RINGBUF_FLAG_BLOCKING,
                        RINGBUF_DIRECTION_WRITE, incoming_eventfds[1], outgoing_eventfds[1])) {
        errno = EIO;
        goto out_fail_fds;
    }

    // Finally, send a dummy byte to let the server know that the client has connected
    uint8_t dummy = 0;
    ringbuf_t *priv = &ret->client_to_host_rb;
    ringbuf_pub_t *pub = &((shmem_hdr_t *)(ret->shm))->client_to_host_pub;
    ringbuf_sec_write(priv, pub, &dummy, 1);

    // Success
    goto out;

out_fail_fds:
    for (size_t i=0; i<KVMCHAND_FD_MAX; i++)
        if (fds[i] > 0)
            close(fds[i]);
out_fail_malloc_ret:
    free(ret);
    ret = NULL;
out:
    pthread_mutex_unlock(&g_state.mutex);
    return ret;
}

/**
 * Packet-based read. Read exactly `size` bytes or fail.
 *
 * @return -1 on error, or `size`.
 */
int libkvmchan_recv(struct libkvmchan *chan, void *data, size_t size) {
    check_client_connected(chan);
    ringbuf_t *priv;
    ringbuf_pub_t *pub;
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        // We're the server, read from c2h ringbuf
        priv = &chan->client_to_host_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->client_to_host_pub;
    } else {
        // We're the client, read from h2c ringbuf
        priv = &chan->host_to_client_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->host_to_client_pub;
    }

    if (RB_SUCCESS != ringbuf_sec_read(priv, pub, data, size))
        return -1;

    return size;
}

/**
 * Packet-based write. Write exactly `size` bytes or fail.
 *
 * @return -1 on error, or `size`.
 */
int libkvmchan_send(struct libkvmchan *chan, void *data, size_t size) {
    check_client_connected(chan);
    ringbuf_t *priv;
    ringbuf_pub_t *pub;
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        // We're the server, write to h2c ringbuf
        priv = &chan->host_to_client_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->host_to_client_pub;
    } else {
        // We're the client, write to c2h ringbuf
        priv = &chan->client_to_host_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->client_to_host_pub;
    }

    if (RB_SUCCESS != ringbuf_sec_write(priv, pub, data, size))
        return -1;

    return size;
}

/**
 * Stream-based read. Read up to `size` bytes.
 *
 * @return -1 on error, or number of bytes written.
 */
int libkvmchan_read(struct libkvmchan *chan, void *data, size_t size) {
    check_client_connected(chan);
    ringbuf_t *priv;
    ringbuf_pub_t *pub;
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        // We're the server, read from c2h ringbuf
        priv = &chan->client_to_host_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->client_to_host_pub;
    } else {
        // We're the client, read from h2c ringbuf
        priv = &chan->host_to_client_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->host_to_client_pub;
    }

    if (RB_SUCCESS != ringbuf_sec_read_stream(priv, pub, data, size, &size))
        return -1;

    return size;
}

/**
 * Stream-based write. Write up to `size` bytes.
 *
 * @return -1 on error, or number of bytes read.
 */
int libkvmchan_write(struct libkvmchan *chan, void *data, size_t size) {
    check_client_connected(chan);
    ringbuf_t *priv;
    ringbuf_pub_t *pub;
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        // We're the server, write to h2c ringbuf
        priv = &chan->host_to_client_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->host_to_client_pub;
    } else {
        // We're the client, write to c2h ringbuf
        priv = &chan->client_to_host_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->client_to_host_pub;
    }

    if (RB_SUCCESS != ringbuf_sec_write_stream(priv, pub, data, size, &size))
        return -1;

    return size;
}

/**
 * Get a file descriptor that will unblock when data is available
 * to read from the appropriate ring buffer.
 *
 * This can be used with select() or poll().
 * libkvmchan_clear_eventfd MUST be used before requesting another eventfd!
 *
 * @param chan libkvmchan_t instance to act on
 * @return eventfd, or -1 on error
 */
int libkvmchan_get_eventfd(struct libkvmchan *chan) {
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        return ringbuf_get_eventfd(&chan->client_to_host_rb);
    } else {
        return ringbuf_get_eventfd(&chan->host_to_client_rb);
    }
}

/**
 * Invalidate an eventfd acquired from libkvmchan_get_eventfd.
 *
 * @param chan libkvmchan_t instance to act on
 */
void libkvmchan_clear_eventfd(struct libkvmchan *chan) {
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        return ringbuf_clear_eventfd(&chan->client_to_host_rb);
    } else {
        return ringbuf_clear_eventfd(&chan->host_to_client_rb);
    }
}

/**
 * Close an existing connection.
 *
 * @param chan connection to close
 */
bool libkvmchan_close(struct libkvmchan *chan) {
    bool ret = false;

    if ((errno = pthread_mutex_lock(&g_state.mutex)))
        return NULL;
    if (!(g_state.flags & STATE_FLAG_CONNECTED)) {
        if (!connect_to_daemon(&g_state))
            goto out;
    }

    // Close ringbufs
    ringbuf_close(&chan->host_to_client_rb);
    ringbuf_close(&chan->client_to_host_rb);

    // Unmap shm
    if (munmap(chan->shm, chan->shm_size) < 0)
        goto out;

    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        // Send message to daemon to close the connection
        struct kvmchand_ret kret;
        struct kvmchand_message msg = {
            .command = KVMCHAND_CMD_CLOSE,
            .args = {
                chan->peer_dom,
                chan->port,
            },
        };
        if (localmsg_send(g_state.socfd, &msg, sizeof(msg), NULL, 0) < 0)
            goto out;
        if (localmsg_recv(g_state.socfd, &kret, sizeof(kret), NULL) < 0)
            goto out;
    }

    ret = true;
out:
    // free chan struct
    free(chan);

    return ret;
}

/**
 * Get the amount of data available to read without blocking, in bytes.
 */
size_t libkvmchan_data_ready(struct libkvmchan *chan) {
    ringbuf_t *priv;
    ringbuf_pub_t *pub;
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        // We're the server, read from c2h ringbuf
        priv = &chan->client_to_host_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->client_to_host_pub;
    } else {
        // We're the client, read from h2c ringbuf
        priv = &chan->host_to_client_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->host_to_client_pub;
    }

    size_t ret = 0;
    assert(RB_SUCCESS == ringbuf_sec_available(priv, pub, &ret));

    return ret;
}

/**
 * Get the amount of space free to write without blocking, in bytes
 */
size_t libkvmchan_buffer_space(struct libkvmchan *chan) {
    ringbuf_t *priv;
    ringbuf_pub_t *pub;
    if (chan->flags & KVMCHAN_FLAG_SERVER) {
        // We're the server, write to h2c ringbuf
        priv = &chan->host_to_client_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->host_to_client_pub;
    } else {
        // We're the client, write to c2h ringbuf
        priv = &chan->client_to_host_rb;
        pub = &((shmem_hdr_t *)(chan->shm))->client_to_host_pub;
    }

    size_t ret = 0;
    assert(RB_SUCCESS == ringbuf_sec_free_space(priv, pub, &ret));

    return ret;
}
