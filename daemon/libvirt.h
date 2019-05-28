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

#ifndef KVMCHAND_LIBVIRT_H
#define KVMCHAND_LIBVIRT_H

#include <stdbool.h>

#include "ringbuf.h"

void run_libvirt_loop(int mainsoc, const char *host_uri);
//bool get_domain_id_by_pid(pid_t pid, unsigned int *id_out);

// Structs used for Main<->Libvirt event loop communication
struct libvirt_event {
    uint8_t type;
#define LVE_TYPE_STARTED 0 // VM started
#define LVE_TYPE_STOPPED 1 // VM stopped
};

#endif // KVMCHAND_LIBVIRT_H
