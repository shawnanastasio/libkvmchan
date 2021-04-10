/**
 * Copyright 2018-2021 Shawn Anastasio
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

enum connections_error {
    CONNECTIONS_ERROR_NONE,
    CONNECTIONS_ERROR_DOM_OFFLINE,
    CONNECTIONS_ERROR_BAD_PORT,
    CONNECTIONS_ERROR_NOT_FOUND,
    CONNECTIONS_ERROR_INVALID_OP,
    CONNECTIONS_ERROR_ALLOC_FAIL,
};

void connections_init(void);
bool vchan_init(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                uint64_t read_min, uint64_t write_min, uint32_t *ivpos_out,
                pid_t *client_pid_out);
enum connections_error vchan_conn(uint32_t server_dom, uint32_t client_dom, uint32_t port,
                uint32_t *ivpos_out, pid_t *pid_out);
bool vchan_close(uint32_t server_dom, uint32_t client_dom, uint32_t port);
bool vchan_unregister_domain(pid_t pid);
enum connections_error vchan_client_disconnect(uint32_t server_dom, uint32_t client_dom, uint32_t port);
int vchan_get_state(uint32_t server_dom, uint32_t client_dom, uint32_t port);

enum connections_error shmem_create(uint32_t server_dom, uint32_t client_dom, uint32_t page_size, size_t page_count,
                                    uint32_t *ivpos_out, pid_t *client_pid_out, uint32_t *region_id_out,
                                    size_t *start_off_out);
enum connections_error shmem_close(uint32_t server_dom, uint32_t client_dom, uint32_t region_id);

#endif //KVMCHAND_CONNECTIONS_H
