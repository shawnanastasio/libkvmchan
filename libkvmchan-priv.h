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

#ifndef LIBKVMCHAN_PRIV_H
#define LIBKVMCHAN_PRIV_H

#include <stdint.h>
#include <stdbool.h>

#include <ringbuf.h>

// Base path for run-time sockets/config
#define RUNTIME_BASE_DIR        "/tmp/kvmchand"

// Socket path used by ivshmem server
#define IVSHMEM_SOCK_PATH       (RUNTIME_BASE_DIR "/ivshmem_socket")

// Socket path used by kvmchand localhandler
#define LOCALHANDLER_SOCK_PATH  (RUNTIME_BASE_DIR "/localhandler_socket")


/* client<->kvmchand API */

#define KVMCHAND_API_VERSION  1
#define KVMCHAND_MSG_NUM_ARGS 4

/**
 * A message sent from a client (API consumer) to kvmchand.
 */
struct kvmchand_message {
    uint64_t command;

    /**
     * Confirm client<->kvmchand communication works.
     *
     * ret - (i64) API version number supported by host
     */
#define KVMCHAND_CMD_HELLO      0

    /**
     * Create a new vchan.
     * args[0] - (u32) domain # of client
     * args[1] - (u32) port
     * args[2] - (u64) read_min
     * args[3] - (u64) write_min
     *
     * Note: In some cases it may not be possible to immediately return
     * all connection fds. In this case, ret will not indicate an error but
     * the fd count will be 0 and the user must request the fds at a later time
     * using KVMCHAND_CMD_GET_CONN_FDS.
     *
     * ret - (u32) The IVPosition of the new ivshmem device, or 0 if called from dom0.
     * fds_count - 5
     * fds - vchan shmfd, incoming eventfds 0-1, outgoing eventfds 0-1
     */
#define KVMCHAND_CMD_SERVERINIT 1

    /**
     * Connect to an existing vchan.
     * arg0 (int) - domain # of server
     * arg1 (int) - port
     *
     * Note: In some cases it may not be possible to immediately return
     * all connection fds. In this case, ret will not indicate an error but
     * the fd count will be 0 and the user must request the fds at a later time
     * using KVMCHAND_CMD_GET_CONN_FDS.
     *
     * ret - (u32) The IVPosition of the ivshmem device, or 0 if called from dom0.
     * fds_count - 5
     * fds - vchan shmfd, incoming eventfds 0-1, outgoing eventfds 0-1
     */
#define KVMCHAND_CMD_CLIENTINIT 2

    /**
     * Get connection fds for an existing vchan
     * arg0 (u32) - IVPosition of the ivshmem device backing the requested vchan
     *
     * ret (u32)
     */
#define KVMCHAND_CMD_GET_CONN_FDS 3

    /**
     * Close an existing vchan.
     * arg0 (u32) - domain # of client
     * arg1 (u32) - port
     */
#define KVMCHAND_CMD_CLOSE 4

    int64_t args[KVMCHAND_MSG_NUM_ARGS];
};

/**
 * A response sent from kvmchand to a client
 */
struct kvmchand_ret {
    int64_t ret;
    bool error;

    uint8_t fd_count; // Number of file descriptors returned
#define KVMCHAND_FD_MAX 5
};

/**
 * Header placed at start of every shared memory region
 */
#define SHMEM_MAGIC 0xDEADBEEFCAFEBABA
typedef struct shmem_hdr {
    uint64_t magic;
    ringbuf_pub_t host_to_client_pub;
    ringbuf_pub_t client_to_host_pub;
} shmem_hdr_t;

/* Maximum ring size (512MB). Chosen arbitrarily */
#define MAX_RING_SIZE 0x20000000

/* Size of SHM region between client and kvmchand */
#define DAEMON_SHM_SIZE 0x100000

/* Size of rbs shared between client and kvmchand */
#define DAEMON_RING_SIZE ((DAEMON_SHM_SIZE - sizeof(shmem_hdr_t)) / 2)

/* Offsets of rbs in shm region between client and kvmchand */
#define DAEMON_H2C_OFFSET (sizeof(shmem_hdr_t))
#define DAEMON_C2H_OFFSET (DAEMON_H2C_OFFSET + DAEMON_RING_SIZE)

/* IVPosition for ivshmem device used for guest<->host kvmchand communication */
#define KVMCHAND_IVPOSITION 1

/* Number of eventfds for each direction */
#define NUM_EVENTFDS 2

/* Macros */

// Ignore unused variable/return warnings.
// Especially for eventfd actions that can't fail.
// This macro was taken from gnulib.
#if 3 < __GNUC__ + (4 <= __GNUC_MINOR__)
# define ignore_value(x) \
    (__extension__ ({ __typeof__ (x) __x = (x); (void) __x; }))
#else
# define ignore_value(x) ((void) (x))
#endif

#endif // LIBKVMCHAN_PRIV_H
