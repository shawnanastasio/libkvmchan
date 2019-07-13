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
    uint8_t type;
#define PEER_LOCAL  0 // Peer is on the local machine
#define PEER_REMOTE 1 // Peer is on another (virtual) machine

    uint32_t dom; // Domain number
};

struct connection {
    struct peer server;
    struct peer client;

    uint32_t port;

    // memfd backing shared memory region
    int memfd;
};

bool connections_init(void);
struct connection *connections_get_by_server_dom(uint32_t dom, uint32_t port);
bool connections_add(struct connection *conn);

#endif //KVMCHAND_CONNECTIONS_H
