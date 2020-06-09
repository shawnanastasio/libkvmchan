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

#ifndef KVMCHAND_CONNECTIONS_H
#define KVMCHAND_CONNECTIONS_H

#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>

#include "util.h"

struct peer {
    uint32_t dom;        // Domain ID
    pid_t pid;           // PID of QEMU if remote, or -1
    uint32_t ivposition; // IVPosition if remote, or 0
};

struct connection {
    struct peer server;
    struct peer client;
    uint32_t port;

    // memfd backing shared memory region
    int memfd;

    // Notification eventfds
    // TODO: For now, ownership of these eventfds is handled by ivshmem,
    // so we don't need to deallocate them in the connection destructor.
    //
    // Eventually this should be changed so we own all fds.
    int eventfds[4];
};

bool connections_init(void);
bool vchan_init(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                uint64_t read_min, uint64_t write_min, uint32_t *ivpos_out,
                pid_t *client_pid_out);
bool vchan_conn(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                uint32_t *ivpos_out, pid_t *pid_out);
bool vchan_close(uint32_t server_dom, uint32_t client_dom, uint32_t port);
bool vchan_unregister_domain(pid_t pid);

#endif //KVMCHAND_CONNECTIONS_H
