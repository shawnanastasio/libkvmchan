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

/**
 * A simple page allocator for keeping track of shared memory regions
 */

#include <stdbool.h>
#include <stdio.h> //sponge

#include "page_allocator.h"

void dump_chunks(struct page_allocator *priv) {
    fprintf(stderr, "CHUNKS {");
    llist_for_each(struct allocation_chunk, cur, &priv->chunks) {
        fprintf(stderr, "(start=%zu, len=%zu, free?=%s), ", cur->start_offset, cur->length,
               (cur->flags & ALLOCATION_CHUNK_FLAG_FREE) ? "T" : "F");
    }
    fprintf(stderr, "}\n");
}

void page_allocator_init(struct page_allocator *priv, size_t total_size, void (*tag_destructor)(void *)) {
    llist_allocation_chunk_init(&priv->chunks, priv);
    priv->total_size = total_size;
    priv->tag_destructor = tag_destructor;

    // Create the initial chunk that spans the entire region
    struct allocation_chunk *chunk = llist_allocation_chunk_new_at_front(&priv->chunks);
    chunk->start_offset = 0;
    chunk->length = total_size;
    chunk->tag = NULL;
    chunk->flags = ALLOCATION_CHUNK_FLAG_FREE;
    dump_chunks(priv);
}

static void split_chunk_tail(struct page_allocator *priv, struct allocation_chunk *chunk, size_t new_size) {
    ASSERT(chunk->length > new_size);
    size_t excess = chunk->length - new_size;

    // See if there is a chunk after this one that can absorb the extra space
    struct llist_allocation_chunk_footer *chunk_footer = llist_allocation_chunk_get_footer(&priv->chunks, chunk);
    if (chunk_footer->next && (chunk_footer->next->flags & ALLOCATION_CHUNK_FLAG_FREE)) {
        struct allocation_chunk *next = chunk_footer->next;
        next->start_offset -= excess;
        next->length += excess;
    } else {
        // Otherwise create a new chunk for the excess space
        struct allocation_chunk *new_chunk = llist_allocation_chunk_new_after(&priv->chunks, chunk);
        new_chunk->start_offset = chunk->start_offset + new_size;
        new_chunk->length = excess;
        new_chunk->tag = NULL;
        new_chunk->flags = ALLOCATION_CHUNK_FLAG_FREE;
    }

    chunk->length = new_size;
    dump_chunks(priv);
}

size_t page_allocator_allocate(struct page_allocator *priv, size_t size, void *tag) {
    fprintf(stderr, "requested allocation of size: %zu\n", size);
    dump_chunks(priv);

    // Walk the chunk list for a suitably sized free chunk
    llist_for_each(struct allocation_chunk, cur, &priv->chunks) {
        if ((cur->flags & ALLOCATION_CHUNK_FLAG_FREE) && cur->length >= size) {
            // If chunk is bigger than necessary, split off the tail end
            if (cur->length > size)
                split_chunk_tail(priv, cur, size);

            // Allocate this chunk
            cur->tag = tag;
            cur->flags &= ~ALLOCATION_CHUNK_FLAG_FREE;
            dump_chunks(priv);
            return cur->start_offset;
        }
    }
    dump_chunks(priv);

    return (size_t)-1;
}

void page_allocator_free(struct page_allocator *priv, struct allocation_chunk *chunk) {
    ASSERT((chunk->flags & ALLOCATION_CHUNK_FLAG_FREE) == 0);
    struct llist_allocation_chunk_footer *chunk_footer = llist_allocation_chunk_get_footer(&priv->chunks, chunk);
    chunk->flags |= ALLOCATION_CHUNK_FLAG_FREE;

    // Coalesce forward
    if (chunk_footer->next && (chunk_footer->next->flags & ALLOCATION_CHUNK_FLAG_FREE)) {
        struct allocation_chunk *next = chunk_footer->next;
        chunk->length += next->length;
        llist_allocation_chunk_remove(&priv->chunks, next);
    }

    // Coalesce backward
    if (chunk_footer->prev && (chunk_footer->prev->flags & ALLOCATION_CHUNK_FLAG_FREE)) {
        struct allocation_chunk *prev = chunk_footer->prev;
        prev->length += chunk->length;
        llist_allocation_chunk_remove(&priv->chunks, chunk);
    }
}

struct allocation_chunk *page_allocator_get_chunk_by_tag(struct page_allocator *priv, tag_comparator_t comparator, void *tag) {
    llist_for_each(struct allocation_chunk, cur, &priv->chunks) {
        if (comparator(cur->tag, tag) == 0)
            return cur;
    }
    return NULL;
}


void allocation_chunk_destroy(struct allocation_chunk *chunk) {
    struct llist_allocation_chunk *chunk_list = llist_allocation_chunk_get_footer_unsafe(chunk, sizeof(struct allocation_chunk))->parent_list;
    struct page_allocator *priv = chunk_list->l.user;
    if (priv->tag_destructor)
        priv->tag_destructor(chunk->tag);
}

void page_allocator_destroy(struct page_allocator *priv) {
    llist_allocation_chunk_destroy(&priv->chunks);
}
