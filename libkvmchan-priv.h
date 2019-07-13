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

#include <ringbuf.h>

/* client<->kvmchand API */

#define KVMCHAND_API_VERSION 1

/**
 * A message sent from a client (API consumer) to kvmchand.
 */
struct kvmchand_message {
    uint64_t command;

    /**
     * Confirm client<->kvmchand communication works.
     * arg0 (u64) - API version number supported by client
     *
     * ret  (i64) - API version number supported by host
     */
#define KVMCHAND_CMD_HELLO      0

    /**
     * Create a new vchan.
     * arg0 (int) - domain # of client
     * arg1 (int) - port
     * arg2 (u64) - read_min
     * arg3 (u64) - write_min
     *
     * ret (i64) - -1 on fail, else index of ivshmem device for new vchan
     */
#define KVMCHAND_CMD_SERVERINIT 1

    /**
     * Connect to an existing vchan.
     * arg0 (int) - domain # of server
     * arg1 (int) - port
     *
     * ret (i64) - -1 on fail, else index of ivshmem device for vchan
     */
#define KVMCHAND_CMD_CLIENTINIT 2

    uint64_t args[4];
};

/**
 * A response sent from kvmchand to a client
 */
struct kvmchand_ret {
    int64_t ret;
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
