/**
 * A small test program that uses libkvmchan
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libkvmchan.h"

#define perror_e(x) do { perror(x); exit(1); } while (0)

static void block_on_eventfd(int eventfd) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(eventfd, &rfds);
    select(eventfd + 1, &rfds, NULL, NULL, NULL);
}

/**
 * Wrappers for libkvmchan stream functions to emulate packet semantics.
 */
int read_wrapper(struct libkvmchan *chan, void *data, size_t size) {
    size_t read = 0;
    while (read < size) {
        size_t remaining = size - read;

        int n;
        if ((n = libkvmchan_read(chan, data+read, remaining)) < 0)
            return -1;

        read += n;
    }

    return read;
}

int write_wrapper(struct libkvmchan *chan, void *data, size_t size) {
    size_t written = 0;
    while (written < size) {
        size_t remaining = size - written;

        int n;
        if ((n = libkvmchan_write(chan, data+written, remaining)) < 0)
            return -1;

        written += n;
    }

    return written;
}


typedef int (*read_func_t)(struct libkvmchan *chan, void *data, size_t size);
typedef int (*write_func_t)(struct libkvmchan *chan, void *data, size_t size);

void do_test(bool client, int domain_no, int port_no, read_func_t read_func, write_func_t write_func) {
    const size_t num_runs = 10;
    struct libkvmchan *chan;

    if (client) {
        chan = libkvmchan_client_init(domain_no, port_no);
        if (!chan)
            perror_e("libkvmchan_client_init");

        // Keep sending hello (u32 len, string)
        for(size_t i=0; i<num_runs; i++) {
            char *hello_str = "Hello, libkvmchan server!";
            size_t hello_len = strlen(hello_str);

            if (write_func(chan, &hello_len, sizeof(size_t)) < 0)
                perror_e("libkvmchan_write1");
            if (write_func(chan, hello_str, hello_len) < 0)
                perror_e("libkvmchan_write2");

            printf("Sent message to server!\n");

            usleep(1 * 1000 * 1000);
        }

    } else {
        chan = libkvmchan_server_init(domain_no, port_no, 100, 100);
        if (!chan)
            perror_e("libkvmchan_server_init");

        // Wait for messages from client and print them out
        char str_buf[256];
        size_t len_buf;
        for (size_t i=0; i<num_runs; i++) {
            int fd = libkvmchan_get_eventfd(chan);
            if (fd < 0)
                perror_e("libkvmchan_get_eventfd");

            printf("Waiting for message...\n");
            block_on_eventfd(fd);
            printf("Received!\n");

            if (read_func(chan, &len_buf, sizeof(size_t)) < 0)
                perror_e("libkvmchan_read1");
            if (read_func(chan, &str_buf, len_buf) < 0)
                perror_e("libkvmchan_read1");

            str_buf[len_buf] = '\0';

            printf("Got message: %s\n", str_buf);
            libkvmchan_clear_eventfd(chan);

            usleep(1 * 1000 * 1000);
        }
    }

    printf("Done. Closing vchan.\n");
    if (!libkvmchan_close(chan))
        perror_e("libkvmchan_close");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("usage: %s: <c/s> <domain_no> <port_no>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argv[1][0] != 'c' && argv[1][0] != 's') {
        printf("usage: %s: <c/s> <domain_no> <port_no>\n", argv[0]);
        return EXIT_FAILURE;
    }

    bool client = argv[1][0] == 'c';
    int domain_no = atoi(argv[2]);
    int port_no = atoi(argv[3]);

    // Test w/ stream read/write functions
    do_test(client, domain_no, port_no, read_wrapper, write_wrapper);
}
