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
            int64_t ret2;
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
     * For sending, these FDs will be sent via SCM_RIGHTS.
     * For receiving, these FDs will come from SCM_RIGHTS.
     * fd_count contains the number of fds to send.
     *
     * Only if IPC_FLAG_FD is set.
     */
    uint8_t fd_count;
#define IPC_FD_MAX 5
    int fds[IPC_FD_MAX];

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
 * resp.ret   - (u32) server's new IVPosition (if remote), else client's new IVPosition
 * resp.ret2  - (pid_t) PID of client qemu process (if remote)
 */
#define MAIN_IPC_CMD_VCHAN_INIT 0

/**
 * Connect to an existing vchan.
 * args[0] - (u32) domain # of server
 * args[1] - (u32) domain # of client
 * args[2] - (u32) port
 *
 * resp.error - error?
 * resp.ret   - (u32) IVPosition of ivshmem device, or 0 if local
 * resp.ret2  - (pid_t) PID of server qemu process (if remote)
 */
#define MAIN_IPC_CMD_VCHAN_CONN 1

/**
 * Destroy an existing vchan.
 * args[0] - (u32) domain # of server
 * args[1] - (u32) domain # of client
 * args[2] - (u32) port
 *
 * resp.error - error?
 */
#define MAIN_IPC_CMD_VCHAN_CLOSE 2

/**
 * Notify that a guest domain has shut down.
 * args[0] - (u32) pid of guest domain
 *
 * resp.error - error?
 */
#define MAIN_IPC_CMD_UNREGISTER_DOM 3


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
 * Get domain ID from a given QEMU PID.
 * args[0] - (pid_t) pid of QEMU process
 *
 * resp.error - domain not found?
 * resp.ret - (u32) domain ID
 */
#define LIBVIRT_IPC_CMD_GET_ID_BY_PID 1

/**
 * Attach a new ivshmem device to the given domain IDs.
 * args[0] - (u32) domain ID or -1
 * args[1] - (u32) domain ID or -1
 * args[2] - (u32) ivposition for domain 0
 * args[3] - (u32) ivposition for domain 1
 *
 * resp.ret  - (u8) (!!error1 << 1) | !!error0
 */
#define LIBVIRT_IPC_CMD_ATTACH_IVSHMEM 2

/**
 * Detach a new ivshmem device from the given domain IDs.
 * args[0] - (u32) domain ID or -1
 * args[1] - (u32) domain ID or -1
 * args[2] - (u32) ivposition for domain 0
 * args[3] - (u32) ivposition for domain 1
 *
 * resp.ret  - (u8) (!!error1 << 1) | !!error0
 */
#define LIBVIRT_IPC_CMD_DETACH_IVSHMEM 3

// ivshmem process commands

/**
 * Register a new upcomming connection with ivshmem.
 * args[0] - (pid_t) QEMU pid that will soon connect, or 0
 * args[1] - (pid_t) Another QEMU pid that will soon connect, or 0
 * fds[0] - memfd backing shared storage
 * fds[1-4] - eventfds
 *
 * The first file descriptor contains the memfd backing the shared memory region.
 *
 * fds 1-4 contain the eventfds used for sending/receiving notifications.
 * Since this command accepts up to two QEMU clients, the eventfd interpretation
 * differs depending on the number of clients provided.
 *
 * If only one client is provided, the eventfds will be interpreted as follows:
 * fds[1] - incoming eventfd 0
 * fds[2] - incoming eventfd 1
 * fds[3] - outgoing eventfd 0
 * fds[4] - outgoing eventfd 1
 *
 * If two clients are provided, the eventfds will be cross-wired for the second
 * client. This means that client 1's incoming eventfds will be wired to client 2's
 * outgoing eventfds, and vice versa.
 *
 * resp.error - error?
 * resp.ret - (u64) ivposition0
 * resp.ret2 - (u32) ivposition1
 *
 * Since this function can register up to two QEMU pids, the return
 * value contains the IVPosition values for the ivshmem devices created.
 * The upper 32 bits contain the IVPosition for the pid in args[0], or 0 if not provided.
 * The lower 32 bits contain the IVPosition for the pid in args[1], or 0 if not provided.
 */
#define IVSHMEM_IPC_CMD_REGISTER_CONN 0

/**
 * Get all file descriptors (memfd, 4x eventfd) for a given connection.
 * args[0] - (pid_t) QEMU pid that connection was made with
 * args[1] - (u32) IVPosition of connection
 *
 * resp.error - error?
 * fds[0] - memfd
 * fds[1] - incoming eventfd 0
 * fds[2] - incoming eventfd 1
 * fds[3] - outgoing eventfd 0
 * fds[4] - outgoing eventfd 1
 */
#define IVSHMEM_IPC_CMD_GET_CONN_FDS 1

/**
 * Unregister existing connections.
 * args[0] - (pid_t) QEMU pid of first connection, or 0
 * args[1] - (pid_t) QEM pid of second connecton, or 0
 * args[2] - (u32) ivposition of first conection
 * args[3] - (u32) ivposition of second conection
 *
 * resp.error - error?
 */
#define IVSHMEM_IPC_CMD_UNREGISTER_CONN 2

// VFIO process commands

/**
 * Forward a kvmchand_message to dom 0.
 * args[0] - (u64) command
 * args[1] - (i64) argument 0
 * args[2] - (i64) argument 1
 * args[3] - (i64) argument 2
 * args[4] - (i64) argument 3
 *
 * resp.error - error?
 * resp.ret - (i64) return value
 */
#define VFIO_IPC_CMD_FORWARD_KVMCHAND_MSG 0

/**
 * Get all file descriptors (VFIO device fd, 4x eventfd) for a given connection.
 * args[0] - (u32) IVPosition of connection
 *
 * resp.error - error?
 * fds[0] - VFIO device fd of corresponding ivshmem device
 * fds[1] - incoming eventfd 0
 * fds[2] - incoming eventfd 1
 * fds[3] - outgoing eventfd 0
 * fds[4] - outgoing eventfd 1
 */
#define VFIO_IPC_CMD_GET_CONN_FDS 1

void ipc_server_start(int socfds[NUM_IPC_SOCKETS],
                      void (*message_handler)(struct ipc_message *));
bool ipc_start(int socfd, uint8_t src, void (*message_handler)(struct ipc_message *));
bool ipc_send_message(struct ipc_message *msg, struct ipc_message *response);

#endif // KVMCHAND_IPC_H
