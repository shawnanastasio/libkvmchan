#include "libkvmchan.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "ringbuf.h"

typedef struct shmem_hdr {
    uint64_t magic;
    ringbuf_t host_to_client_rb;
    ringbuf_t client_to_host_rb;
} shmem_hdr_t;


// Main struct. Users only get opaque pointers.
typedef struct libkvmchan {
    // flags. See LIBKVM_FLAG_*
    uint32_t flags;

    // pointer to memory region that is shared between host/client
    void *shm;

    // size of shared memory region
    size_t shm_size;

    // Ringbuffer security contexts
    ringbuf_sec_context_t *host_to_client_sec;
    ringbuf_sec_context_t *client_to_host_sec;
} libkvmchan_t;


char TEST_STR[] = "Hello, World! This is a test string.";

void *server_thread(void *handle) {
    libkvmchan_t *chan = libkvmchan_host_open(handle);
    if (!chan) {
        perror("libkvmchan_host_open");
        return NULL;
    }

    for(;;) {
        // Send a string and sleep for a second
        if (!libkvmchan_write(chan, TEST_STR, sizeof(TEST_STR))) {
            fprintf(stderr, "Failed to write test str! Buffer full?\n");
        }
        usleep(1000 * 1000);
    }

    return NULL;
}

void *client_thread(void *handle) {
    libkvmchan_t *chan = libkvmchan_client_open(handle);
    if (!chan) {
        perror("libkvmchan_client_open");
        return NULL;
    }

    for(;;) {
        // Read string
        char buf[sizeof(TEST_STR)];
        memset(buf, 0, sizeof(buf));
        if (!libkvmchan_read(chan, buf, sizeof(TEST_STR))) {
            printf("Failed to read test str!\n");
        } else {
            printf("Got test str: %s\n", buf);
            // Corrupt pos_end ptr to trigger security event
            shmem_hdr_t *hdr = chan->shm;
            //hdr->host_to_client_rb.pos_end += 1;
        }

        //assert(strcmp(buf, TEST_STR) == 0);

        usleep(1000 * 1000);
    }

    return NULL;
}


int main(int argc, char **argv) {
    // Manually create an shm_handle for testing
    // between two threads in the same process
    void *mem = malloc(0x10000);
    assert(mem && "failed to allocate memory");
    libkvmchan_shm_handle_t handle = {mem, 0x10000};

    // Spawn a server and client thread
    pthread_t server, client;
    assert(!pthread_create(&server, NULL, server_thread, &handle));
    assert(!pthread_create(&client, NULL, client_thread, &handle));
    pthread_join(server, NULL);
    pthread_join(client, NULL);
}
