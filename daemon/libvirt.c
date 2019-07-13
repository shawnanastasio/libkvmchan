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

#include <unistd.h>
#include <semaphore.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <libvirt/libvirt.h>
#include <libvirt/libvirt-qemu.h>
#include <libvirt/virterror.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "config.h"
#include "util.h"
#include "libvirt.h"
#include "libkvmchan-priv.h"
#include "connections.h"
#include "ipc.h"

struct domain_info {
    char uuid_str[VIR_UUID_STRING_BUFLEN];
    pid_t pid; // PID of qemu process
};

// Vec of domain_info structs for currently running domains
static struct vec_voidp running_domains;
static sem_t running_domains_sem;

// libvirt connection
static virConnectPtr conn;

static bool get_domain_id_by_pid(pid_t pid, unsigned int *id_out) {
    bool ret = false;
    ASSERT(HANDLE_EINTR(sem_wait(&running_domains_sem)));

    for (size_t i=0; i<running_domains.count; i++) {
        struct domain_info *cur = running_domains.data[i];

        if (cur->pid == pid) {
            virDomainPtr dom = virDomainLookupByUUIDString(conn, cur->uuid_str);
            if (!dom)
                goto out;

            *id_out = virDomainGetID(dom);
            ret = true;
            goto out;
        }
    }

out:
    ASSERT(HANDLE_EINTR(sem_post(&running_domains_sem)));
    return ret;
}

static void print_running_domains(virConnectPtr conn) {
    puts("---Running Domains---");
    puts("Name               ID");

    sem_wait(&running_domains_sem);
    for (size_t i=0; i<running_domains.count; i++) {
        struct domain_info *cur = running_domains.data[i];
        virDomainPtr dom = virDomainLookupByUUIDString(conn, cur->uuid_str);
        printf("%-18s %d\n", virDomainGetName(dom), virDomainGetID(dom));
    }
    sem_post(&running_domains_sem);

    puts("---------------------");
}

/**
 * Since the libvirt developers have decided not to share
 * the QEMU process' pid with us lowly API consumers,
 * we have no choice but to walk /proc and check each
 * process' cmdline for the VM's UUID.
 *
 * As one would imagine, this is horrifically slow. Sigh.
 */
static bool find_qemu_process_pid(const char *uuid_str, pid_t *pid_out) {
    bool found = false;
    DIR *proc = opendir("/proc");
    if (!proc) {
        log(LOGL_ERROR, "Failed to open /proc: %m");
        return false;
    }

    struct dirent *cur;
    char path_buf[NAME_MAX + 14 /* len(/proc//cmdline) */ + 1];
    char cmdlinebuf[2048];
    int n;
    while ((cur = readdir(proc))) {
        // Skip non-numerical directories
        if (!str_is_number(cur->d_name)) {
            continue;
        }

        // Open this process' cmdline and check for the UUID
        snprintf(path_buf, sizeof(path_buf), "/proc/%s/cmdline", cur->d_name);
        int fd = open(path_buf, O_RDONLY);
        if (fd < 0) {
            continue;
        }

        if ((n = read(fd, cmdlinebuf, sizeof(cmdlinebuf) - 1)) <= 0) {
            close(fd);
            continue;
        }
        cmdlinebuf[n] = '\0';
        close(fd);

        if (memmem(cmdlinebuf, n, uuid_str, VIR_UUID_STRING_BUFLEN - 1)) {
            // UUID found, this is probably qemu
            *pid_out = atoi(cur->d_name);
            found = true;
            goto out;
        }
    }

out:
    closedir(proc);
    return found;
}

/**
 * Attach an ivshmem device to a given domain using QMP.
 * @param dom    domain to attach device to
 * @param path   path to ivshmem server socket
 * @param index  index of the new ivshmem device for the domain. Must be unique.
 * @return success?
 */
static bool attach_ivshmem_device(virDomainPtr dom, const char *path, int index) {
    char *result;

#ifdef USE_VFIO_NOIOMMU
    /**
     * NOIOMMU is easy, since we don't have to worry about IOMMU groups
     * we can just add the ivshmem devices anywhere without worrying
     * about dedicated pci host bridges.
     */

    // A QMP command to add a new chardev with formats %d %s (index, path)
    const char qmp_new_chardev_format[] = "{\"execute\":\"chardev-add\", \"arguments\": {\"id\":"
        "\"charshmem%d\", \"backend\":{ \"type\": \"socket\", \"data\": "
        "{\"server\": false, \"addr\": {\"type\": \"unix\", \"data\": {\"path\": \"%s\"} } } } } }";

    // A QMP command to add a new ivshmem device with format %d (index)
    const char qmp_new_ivshmem_format[] = "{\"execute\":\"device_add\", \"arguments\": {\"driver\": "
        "\"ivshmem-doorbell\", \"id\":\"shmem%1$d\", \"chardev\":\"charshmem%1$d\", \"vectors\": 2}}";

    // Fill in arguments for chardev and ivshmem commands
    char chardev_buf[sizeof(qmp_new_chardev_format) + 255 /* enough for the path? */];
    char ivshmem_buf[sizeof(qmp_new_chardev_format) + 255 /* enough for pci bus? */];
    snprintf(chardev_buf, sizeof(chardev_buf), qmp_new_chardev_format, index, path);
    snprintf(ivshmem_buf, sizeof(ivshmem_buf), qmp_new_ivshmem_format, index);

#elif defined(USE_VFIO_SPAPR)
    /**
     * With the SPAPR IOMMU mode, we have to ensure that all ivshmem devices
     * are on a separate spapr-pci-host-bridge. For now, assume that the user
     * has created a dedicated spapr-pci-host-bridge at index 1. In the future
     * this needs to be replaced with proper parsing of the domain XML to
     * determine the correct host bridge to use.
     *
     * For reference, adding a host bridge at index 1 can be done with the
     * following XML:
     *
     * <controller type='pci' index='1' model='pci-root'>
     *   <model name='spapr-pci-host-bridge'/>
     *   <target index='1'/>
     * </controller>
     */

    // A QMP command to add a new chardev with formats %d %s (index, path)
    const char qmp_new_chardev_format[] = "{\"execute\":\"chardev-add\", \"arguments\": {\"id\":"
        "\"charshmem%d\", \"backend\":{ \"type\": \"socket\", \"data\": "
        "{\"server\": false, \"addr\": {\"type\": \"unix\", \"data\": {\"path\": \"%s\"} } } } } }";

    // A QMP command to add a new ivshmem device with format %d %s (index, pci bus ID)
    const char qmp_new_ivshmem_format[] = "{\"execute\":\"device_add\", \"arguments\": {\"driver\": "
        "\"ivshmem-doorbell\", \"id\":\"shmem%1$d\", \"chardev\":\"charshmem%1$d\", \"vectors\": 2,"
        "\"bus\": \"%2$s\"}}";

    // Fill in arguments for chardev and ivshmem commands
    char chardev_buf[sizeof(qmp_new_chardev_format) + 255 /* enough for the path? */];
    char ivshmem_buf[sizeof(qmp_new_chardev_format) + 255 /* enough for pci bus? */];
    snprintf(chardev_buf, sizeof(chardev_buf), qmp_new_chardev_format, index, path);
    snprintf(ivshmem_buf, sizeof(ivshmem_buf), qmp_new_ivshmem_format, index,
             "pci.1.0" /* TODO: dynamically detect PCI host bridge to use via XML */);

#else
#error "Unimplemented IOMMU mode!"
#endif

    // Create new chardev
    if (virDomainQemuMonitorCommand(dom, chardev_buf, &result, 0) < 0) {
        log(LOGL_ERROR, "Failed to attach chardev to dom: %s", result);
        free(result);
        return false;
    }
    if (!strstr(result, "\"return\":{}")) {
        log(LOGL_ERROR, "QEMU rejected chardev: %s", result);
        free(result);
        return false;
    }
    free(result);

    // Create new ivshmem device
    if (virDomainQemuMonitorCommand(dom, ivshmem_buf, &result, 0) < 0) {
        log(LOGL_ERROR, "Failed to attach ivshmem device to dom: %s", result);
        free(result);
        return false;
    }
    if (!strstr(result, "\"return\":{}")) {
        log(LOGL_ERROR, "QEMU rejected ivshmem device: %s", result);
        free(result);
        return false;
    }
    free(result);

    return true;

}

#if 0
static bool spawn_kvmchan_listener(virDomainPtr dom) {
    // Dump the VM configuration and check for the appropriate ivshmem devices
    const char *xml = virDomainGetXMLDesc(dom, 0);
    if (!xml) {
        log(LOGL_ERROR, "Failed to obtain XML for domain %d!", virDomainGetID(dom));
        return;
    }

    // Parse the XML into a libxml DOM object
    xmlDocPtr doc = xmlParseDoc((const xmlChar *)xml);
    if (!doc) {
        log(LOGL_ERROR, "Failed to parse XML for domain %d!", virDomainGetID(dom));
        return;
    }

    // Confirm that the document is a valid libvirt KVM domain
    xmlNodePtr node = xmlDocGetRootElement(doc);
    if (xmlStrcmp(node->name, (const xmlChar *)"domain")) {
        log(LOGL_ERROR, "Invalid XML returned for domain %d!", virDomainGetID(dom));
        return;
    }

    const xmlChar *type = xmlGetProp(node, (const xmlChar *)"type");
    if (!type || xmlStrcmp(type, (const xmlChar *)"kvm")) {
        log(LOGL_ERROR, "Invalid domain type for domain %d, only KVM is supported.",
            virDomainGetID(dom));
        return;
    }

    log(LOGL_INFO, "Successfully parsed Domain XML!");

    // Lookup all ivshmem devices
    xmlXPathContextPtr context = xmlXPathNewContext(doc);
    xmlXPathObjectPtr result = xmlXPathEvalExpression((const xmlChar *)"/domain/devices/shmem",
                                                      context);

    if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
        xmlXPathFreeObject(result);
    }
    return true;
}
#endif

static int lifecycle_change_callback(virConnectPtr conn, virDomainPtr dom,
                                     int event, int detail, void *opaque) {
    char uuid[VIR_UUID_STRING_BUFLEN];
    virDomainGetUUIDString(dom, uuid);
    log(LOGL_INFO, "Domain %s(%d, UUID: %s) changed state (event: %d, detail: %d)!",
            virDomainGetName(dom), virDomainGetID(dom), uuid, event, detail);
    switch(event) {
        case VIR_DOMAIN_EVENT_STARTED:
            ;
            // Add this domain to running_domains
            struct domain_info *info = malloc_w(sizeof(struct domain_info));
            if (virDomainGetUUIDString(dom, info->uuid_str) < 0) {
                log(LOGL_WARN, "Failed to get UUID for domain! Ignoring...");
                free(info);
                break;
            }

            if (!find_qemu_process_pid(info->uuid_str, &info->pid)) {
                log(LOGL_WARN, "Failed to get PID for domain! Ignoring...");
                free(info);
                break;
            }
            log(LOGL_INFO, "Got PID: %d", info->pid);

            // Create a new ivshmem device on the guest
            // that will be used for guest<->kvmchand communication
            if (!attach_ivshmem_device(dom, IVSHMEM_SOCK_PATH, 0)) {
                log(LOGL_WARN, "Failed to attach ivshmem device! Ignoring...");
                free(info);
                break;
            }

            // Add VM to list of running domains
            sem_wait(&running_domains_sem);
            vec_voidp_push_back(&running_domains, info);
            sem_post(&running_domains_sem);

            // Inform main loop of the new VM
            /*
            struct libvirt_event ev = { .type = LVE_TYPE_STARTED };
            if (write(main_soc, &ev, sizeof(ev)) < 0) {
                log(LOGL_WARN, "Failed to send event to main process!");
                bail_out();
            }
            */

            break;
        case VIR_DOMAIN_EVENT_STOPPED:
            ;
            // Remove this domain from running_domains
            sem_wait(&running_domains_sem);
            bool removed = false;
            for (size_t i=0; i<running_domains.count; i++) {
                struct domain_info *cur = running_domains.data[i];

                if (strncmp(cur->uuid_str, uuid, VIR_UUID_STRING_BUFLEN) == 0) {
                    log(LOGL_INFO, "Removing domain %s\n", cur->uuid_str);
                    vec_voidp_remove(&running_domains, i);
                    removed = true;
                    break;
                }
            }
            sem_post(&running_domains_sem);

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

/**
 * Handle IPC messages from other kvmchand processes
 */
static void handle_ipc_message(struct ipc_message *msg) {

}

void run_libvirt_loop(int mainsoc, const char *host_uri) {
    if (!ipc_start(mainsoc, IPC_DEST_LIBVIRT, handle_ipc_message))
        goto error;

    // Initialize libvirt API
    if (virInitialize() < 0) {
        log(LOGL_ERROR, "Failed to initialize libvirt");
        goto error;
    }

    if (virEventRegisterDefaultImpl() < 0) {
        log(LOGL_ERROR, "Failed to register event implementation: %s",
                virGetLastErrorMessage());
        goto error;
    }

    // Try to establish a connection to libvirtd
    conn = virConnectOpen(host_uri);
    if (!conn) {
        log(LOGL_ERROR, "Failed to establish a connection to libvirt!");
        goto error;
    }

    if (virConnectRegisterCloseCallback(conn, connect_close_callback, NULL,
                                        NULL) < 0) {
        log(LOGL_ERROR, "Unable to register close callback");
        goto error;
    }

    // Register callback for VM lifecycle changes
    int event_id = virConnectDomainEventRegisterAny(conn, NULL,
                            VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                            VIR_DOMAIN_EVENT_CALLBACK(lifecycle_change_callback),
                            NULL, NULL);

    if (event_id < 0) {
        log(LOGL_ERROR, "Failed to install libvirt callback!");
        goto error;
    }

    // Establish initial list of running domains
    int n_domains = virConnectNumOfDomains(conn);
    if (!vec_voidp_init(&running_domains, n_domains, free_destructor)) {
        log(LOGL_ERROR, "Failed to allocate memory!");
        goto error;
    }

    if (sem_init(&running_domains_sem, 0, 1) < 0) {
        log(LOGL_ERROR, "Failed to init semaphore: %m");
        goto error;
    }

    if (n_domains > 0) {
        int *domains = calloc(n_domains, sizeof(int));
        if (!domains) {
            log(LOGL_ERROR, "Failed to allocate memory: %s!", strerror(errno));
            goto error;
        }

        n_domains = virConnectListDomains(conn, domains, n_domains);
        // Get name of each domain and add to running_domains
        for (int i=0; i<n_domains; i++) {
            virDomainPtr p = virDomainLookupByID(conn, domains[i]);
            if (!p) {
                log(LOGL_ERROR, "Failed to lookup domain!");
                free(domains);
                goto error;
            }

            struct domain_info *info = malloc_w(sizeof(struct domain_info));
            if (virDomainGetUUIDString(p, info->uuid_str)) {
                log(LOGL_ERROR, "Failed to lookup domain UUID!");
                free(domains);
                goto error;
            }

            if (!find_qemu_process_pid(info->uuid_str, &info->pid)) {
                log(LOGL_WARN, "Failed to lookup domain PID!");
                free(domains);
                goto error;
            }

            // Create a new ivshmem device on the guest
            // that will be used for guest<->kvmchand communication
            if (!attach_ivshmem_device(p, IVSHMEM_SOCK_PATH, 0)) {
                log(LOGL_WARN, "Failed to attach ivshmem device!");
                free(domains);
                goto error;
            }

            assert(vec_voidp_push_back(&running_domains, info));
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

error:
    log(LOGL_ERROR, "Libvirt loop encountered fatal error: %m!");
    bail_out();
}
