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
#include <stdint.h>

#define NUM_IPC_SOCKETS 4
#define IPC_SOCKET_IVSHMEM      0
#define IPC_SOCKET_LIBVIRT      1
#define IPC_SOCKET_VFIO         2
#define IPC_SOCKET_LOCALHANDLER 3

struct ipc_message {
    uint8_t type;
#define IPC_TYPE_CMD  0
#define IPC_TYPE_RESP 1

    union {
        struct ipc_cmd {
            uint64_t command;
            int64_t args[5];
        } cmd;

        struct ipc_resp {
            int64_t ret;
            bool error;
        } resp;
    };

    uint8_t src;
    uint8_t dest;
#define IPC_DEST_MAIN         0
#define IPC_DEST_IVSHMEM      1
#define IPC_DEST_LIBVIRT      2
#define IPC_DEST_VFIO         3
#define IPC_DEST_LOCALHANDLER 4

    uint8_t flags;
#define IPC_FLAG_FD        (1 << 0) // Pass an FD using SCM_RIGHTS
#define IPC_FLAG_WANTRESP  (1 << 1) // Expect a response

    /**
     * For sending, this FD will be sent via SCM_RIGHTS.
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
 * Initialize a new vchan.
 * args[0] - (u32) domain # of server
 * args[1] - (u32) domain # of allowed client
 * args[2] - (u32) port
 * args[3] - (u64) read_min
 * args[4] - (u64) write_min
 *
 * resp.error - error?
 * resp.ret   - server's new IVPosition, or 0 if local
 */
#define MAIN_IPC_CMD_VCHAN_INIT 0

// libvirt process commands

/**
 * Get PID of QEMU process for a given domain ID.
 * args[0] - (u32) domain ID
 *
 * resp.error - domain doesn't exist?
 * resp.ret - (pid_t) pid
 */
#define LIBVIRT_IPC_CMD_GET_PID_BY_ID 0

/**
 * Attach a new ivshmem device to the given domain IDs.
 * args[0] - (u32) domain ID or -1
 * args[1] - (u32) domain ID or -1
 *
 * resp.ret - (u8) (!!error1 << 1) | !!error0
 */
#define LIBVIRT_IPC_CMD_ATTACH_IVSHMEM 1

// ivshmem process commandsk

/**
 * Register a new upcomming connection with ivshmem.
 * args[0] - (pid_t) QEMU pid that will soon connect, or -1
 * args[1] - (pid_t) Another QEMU pid that will soon connect, or -1
 * fd - memfd backing shared storage
 *
 * resp.error - error?
 * resp.ret - (u64) (((u64)ivposition0 << 32) | (u32)ivposition1)
 *
 * Since this function can register up to two QEMU pids, the return
 * value contains the IVPosition values for the ivshmem devices created.
 * The upper 32 bits contain the IVPosition for the pid in args[0], or 0 if not provided.
 * The lower 32 bits contain the IVPosition for the pid in args[1], or 0 if not provided.
 */
#define IVSHMEM_IPC_CMD_REGISTER_CONN 0

void ipc_server_start(int socfds[NUM_IPC_SOCKETS], uint8_t src,
                      void (*message_handler)(struct ipc_message *));
bool ipc_start(int socfd, uint8_t src, void (*message_handler)(struct ipc_message *));
bool ipc_send_message(struct ipc_message *msg, struct ipc_message *response);

#endif // KVMCHAND_IPC_H
