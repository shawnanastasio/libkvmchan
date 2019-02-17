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

/**
 * This daemon interfaces with libvirt and allows VMs
 * to query and create vchans which they can't do by
 * themselves
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "daemon-priv.h"

// TODO: Support proper authentication and different libvirt hosts
#define LIBVIRT_HOST_URI "qemu:///system"

void daemonize() {
    // Fork to background
    pid_t child = fork();
    if (child < 0) {
        log(LOGL_ERROR, "Failed to fork to background!");
        exit(EXIT_FAILURE);
    } else if (child > 0) {
        // Child forked successfully, parent can exit
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0);

    // Create a new session
    pid_t sid = setsid();
    if (sid < 0) {
        log(LOGL_ERROR, "Failed to set sid!");
        exit(EXIT_FAILURE);
    }

    // Chdir to /
    if (chdir("/") < 0) {
        log(LOGL_ERROR, "Failed to chdir!");
        exit(EXIT_FAILURE);
    }

    // Lastly, close all STDIO file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void show_help(const char *progname) {
    fprintf(stderr, "Usage: %s [-h|-d]\n", progname);
}

int main(int argc, char **argv) {
    bool daemon = false;
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch(opt) {
            case 'h':
                show_help(argv[0]);
                return EXIT_SUCCESS;

            case 'd':
                daemon = true;
                break;

            default:
                fprintf(stderr, "Unknown argument!\n");
                show_help(argv[0]);
                return EXIT_FAILURE;
        }
    }


    // Daemonize if requested
    if (daemon)
        daemonize();

    return run_libvirt_loop(LIBVIRT_HOST_URI);
}
