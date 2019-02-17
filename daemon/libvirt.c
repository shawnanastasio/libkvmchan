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
 * This file contains interfaces to the libvirt API.
 * Used to maintain lists of online VMs and establish the
 * ivshmem shared memory device links between them
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#include "daemon-priv.h"

// Array of strings of the names of currently running domains
struct vec g_running_domains;

static void print_running_domains(virConnectPtr conn) {
    puts("---Running Domains---");
    puts("Name               ID");
    for (size_t i=0; i<g_running_domains.count; i++) {
        const char *cur = g_running_domains.data[i];
        printf("%-18s %d\n", cur, virDomainGetID(virDomainLookupByName(conn, cur)));
    }
    puts("---------------------");
}

static void spawn_kvmchan_listener(virDomainPtr dom) {

}

static int lifecycle_change_callback(virConnectPtr conn, virDomainPtr dom,
                                     int event, int detail, void *opaque) {
    log(LOGL_INFO, "Domain %s(%d) changed state (event: %d, detail: %d)!",
            virDomainGetName(dom), virDomainGetID(dom), event, detail);
    switch(event) {
        case VIR_DOMAIN_EVENT_STARTED:
            ;
            // Add this domain to g_running_domains
            char *name = strdup(virDomainGetName(dom));
            if (!name) {
                log(LOGL_ERROR, "Failed to resolve domain's name!");
                break;
            }
            vec_push_back(&g_running_domains, name);

            // Dump this VM's configuration
            const char *xml = virDomainGetXMLDesc(dom, 0);
            printf("XML: %s\n", xml);
            break;
        case VIR_DOMAIN_EVENT_STOPPED:
            ;
            // Remove this domain from g_running_domains
            bool removed = false;
            const char *dom_name = virDomainGetName(dom);
            for (size_t i=0; i<g_running_domains.count; i++) {
                const char *cur_name = g_running_domains.data[i];
                if (strncmp(cur_name, dom_name, strlen(dom_name)) == 0) {
                    log(LOGL_INFO, "Removing domain %s\n", cur_name);
                    vec_remove(&g_running_domains, i);
                    removed = true;
                    break;
                }
            }
            if (!removed) {
                log(LOGL_ERROR, "Domain %s stopped but wasn't supposed to be running!\n",
                        virDomainGetName(dom));
            }
            break;
        default:
            log(LOGL_WARN, "Unknown lifecycle event %d! Ignoring...");
    }
    return 0;
}

static void connect_close_callback(virConnectPtr conn, int reason,
                                   void *opaque) {
    switch ((virConnectCloseReason) reason) {
    case VIR_CONNECT_CLOSE_REASON_ERROR:
        log(LOGL_ERROR, "Connection closed due to I/O error");
        return;

    case VIR_CONNECT_CLOSE_REASON_EOF:
        log(LOGL_ERROR, "Connection closed due to end of file");
        return;

    case VIR_CONNECT_CLOSE_REASON_KEEPALIVE:
        log(LOGL_ERROR, "Connection closed due to keepalive timeout");
        return;

    case VIR_CONNECT_CLOSE_REASON_CLIENT:
        log(LOGL_ERROR, "Connection closed due to client request");
        return;
    };

    log(LOGL_ERROR, "Connection closed due to unknown reason");
}

static void free_destructor(void *element) {
    free(element);
}

int run_libvirt_loop(const char *host_uri) {
    // Initialize libvirt API
    if (virInitialize() < 0) {
        log(LOGL_ERROR, "Failed to initialize libvirt");
        return EXIT_FAILURE;
    }


    if (virEventRegisterDefaultImpl() < 0) {
        log(LOGL_ERROR, "Failed to register event implementation: %s",
                virGetLastErrorMessage());
        return EXIT_FAILURE;
    }

    // Try to establish a connection to libvirtd
    virConnectPtr conn = virConnectOpen(host_uri);
    if (!conn) {
        log(LOGL_ERROR, "Failed to establish a connection to libvirt!");
        return EXIT_FAILURE;
    }

    if (virConnectRegisterCloseCallback(conn, connect_close_callback, NULL,
                                        NULL) < 0) {
        log(LOGL_ERROR, "Unable to register close callback");
        return EXIT_FAILURE;
    }

    // Register callback for VM lifecycle changes
    int event_id = virConnectDomainEventRegisterAny(conn, NULL,
                            VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                            VIR_DOMAIN_EVENT_CALLBACK(lifecycle_change_callback),
                            NULL, NULL);

    if (event_id < 0) {
        log(LOGL_ERROR, "Failed to install libvirt callback!");
        return EXIT_FAILURE;
    }

    // Establish initial list of running domains
    int n_domains = virConnectNumOfDomains(conn);
    if (!vec_init(&g_running_domains, n_domains, free_destructor)) {
        log(LOGL_ERROR, "Failed to allocate memory!");
        return EXIT_FAILURE;
    }

    if (n_domains > 0) {
        int *domains = calloc(n_domains, sizeof(int));
        if (!domains) {
            log(LOGL_ERROR, "Failed to allocate memory: %s!", strerror(errno));
            return EXIT_FAILURE;
        }

        n_domains = virConnectListDomains(conn, domains, n_domains);
        // Get name of each domain and add to g_running_domains
        for (int i=0; i<n_domains; i++) {
            virDomainPtr p = virDomainLookupByID(conn, domains[i]);
            if (!p) {
                log(LOGL_ERROR, "Failed to lookup domain!");
                return EXIT_FAILURE;
            }

            const char *name = virDomainGetName(p);
            if (!name) {
                log(LOGL_ERROR, "Failed to lookup domain name!");
                return EXIT_FAILURE;
            }

            assert(vec_push_back(&g_running_domains, strdup(name)));
        }
        free(domains);
    }

    // libvirt event loop
    for(;;) {
        print_running_domains(conn);
        if (virEventRunDefaultImpl() < 0) {
            log(LOGL_ERROR, "Failed to run event loop: %s",
                    virGetLastErrorMessage());
        }
    }

    // Shouldn't reach here except on error
    return EXIT_FAILURE;
}
