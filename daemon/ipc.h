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

#ifndef KVMCHAND_IPC_H
#define KVMCHAND_IPC_H

#include <stdbool.h>

#define NUM_IPC_SOCKETS 3
#define IPC_SOCKET_IVSHMEM 0
#define IPC_SOCKET_LIBVIRT 1
#define IPC_SOCKET_VFIO    2

struct ipc_message {
    uint8_t type;
#define IPC_TYPE_CMD  0
#define IPC_TYPE_RESP 1

    union {
        struct ipc_cmd {
            uint64_t command;
            int64_t args[4];
        } cmd;

        struct ipc_resp {
            int64_t ret;
            bool error;
        } resp;
    };

    uint8_t src;
    uint8_t dest;
#define IPC_DEST_MAIN    0
#define IPC_DEST_IVSHMEM 1
#define IPC_DEST_LIBVIRT 2
#define IPC_DEST_VFIO    3

    uint8_t flags;
#define IPC_FLAG_FD        (1 << 0) // Pass an FD using SCM_RIGHTS
#define IPC_FLAG_WANTRESP  (1 << 1) // Expect a response

    /**
     * For sending, this FD will be used with SCM_RIGHTS.
     * For receiving, this FD will come from SCM_RIGHTS.
     *
     * Only if IPC_FLAG_FD is set.
     */
    int fd;

    /**
     * This is a unique sequence number for this message.
     * The response will reference this id.
     */
    uint32_t id;
};

// Main process commands

/**
 * dummy command.
 * args[0] - number
 *
 * return - number * 2
 */
#define MAIN_IPC_CMD_TEST 0

/**
 * Initialize a new vchan.
 * args[0] - (u32) domain # of server
 * args[1] - (u32) domain # of allowed client
 * args[2] - (u32) port
 * args[3] - (u64) read_min
 * args[4] - (u64) write_min
 *
 * resp.error - error?
 * resp.ret   - ?
 */
#define MAIN_IPC_CMD_VCHAN_INIT 1

void ipc_server_start(int socfds[NUM_IPC_SOCKETS], uint8_t src,
                      void (*message_handler)(struct ipc_message *));
bool ipc_start(int socfd, uint8_t src, void (*message_handler)(struct ipc_message *));
bool ipc_send_message(struct ipc_message *msg, struct ipc_message *response);

#endif // KVMCHAND_IPC_H
