/**
 * Copyright 2021 Shawn Anastasio
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

#ifndef KVMCHAND_PAGE_ALLOCATOR_H
#define KVMCHAND_PAGE_ALLOCATOR_H

#include <stdint.h>

#include "util.h"

struct allocation_chunk {
    size_t start_offset; // Offset from the beginning of the region where this allocation starts
    size_t length;
    void *tag;

    int flags;
#define ALLOCATION_CHUNK_FLAG_FREE (1 << 0)
};
void allocation_chunk_destroy(struct allocation_chunk *);
DECLARE_LLIST_FOR_TYPE(allocation_chunk, struct allocation_chunk, allocation_chunk_destroy)

typedef int (*tag_comparator_t)(void *tag1, void *tag2);

struct page_allocator {
    struct llist_allocation_chunk chunks;
    void (*tag_destructor)(void *);

    // Size of the region managed by this allocator
    size_t total_size;
};

void page_allocator_init(struct page_allocator *priv, size_t total_size, void (*tag_destructor)(void *));
size_t page_allocator_allocate(struct page_allocator *priv, size_t size, void *tag);
void page_allocator_free(struct page_allocator *priv, struct allocation_chunk *chunk);
struct allocation_chunk *page_allocator_get_chunk_by_tag(struct page_allocator *priv, tag_comparator_t comparator, void *tag);
void page_allocator_destroy(struct page_allocator *priv);

#endif // KVMCHAND_PAGE_ALLOCATOR_H
