/**
 * Copyright 2018-2020 Shawn Anastasio
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
 * This file contains an implementation of a VFIO
 * userspace driver for ivshmem devices.
 * Used in guest-mode to communicate with the host
 * daemon and other VMs.
 *
 * A note on VFIO NOIOMMU. (Non-ppc64 systems only)
 * VFIO is a kernel subsystem for exposing direct device access
 * to userspace. It is used here to interface with ivshmem devices
 * without requiring a separate kernel driver. This has many security
 * and usability benefits.
 *
 * VFIO traditionally required an IOMMU (I/O Memory Management Unit)
 * in order to expose devices to userspace. This is a security feature
 * that prevents DMA-capable PCI devices from writing to privileged
 * memory. Unfortunately, in VMs an IOMMU is sometimes not available.
 * (On x86_64 and ppc64, virtualized IOMMUs are actually available,
 * but only ppc64's vIOMMU is used for now.)
 *
 * In kernel 4.14, the ability to use VFIO without an IOMMU (NOIOMMU mode)
 * was introduced. This addition allowed systems without an IOMMU,
 * like VMs, to leverage the VFIO framework, albeit without
 * protection from rogue DMA-capable devices. Because of this drawback,
 * NOIOMMU mode is considered unsafe, and enabling it taints the kernel.
 *
 * In the case of libkvmchan, though, this drawback is less relevant,
 * since the ivshmem device does not have arbitrary DMA r/w capabilities,
 * with the exception of MSI-X interrupt abilities. It is unclear
 * whether or not DMA as used by MSI-X constitutes a security risk
 * when used in this way, but it seems like a decent tradeoff.
 *
 * This means that in spite of being labeled as unsafe, VFIO NOIOMMU
 * is the probably safest possible way to interface with an ivshmem device
 * in cases where a virtualized IOMMU isn't available.
 * As mentioned previously, the only other way would be to write
 * a kernel driver that exposes the functionality of the ivshmem device
 * to userspace. This is a far worse solution for many reasons.
 * Here are a few:
 *
 *  - Kernel drivers run with a much higher privilege level
 *  - Less security features are available to kernel drivers
 *  - Kernel drivers must be recompiled for each kernel - worse user experience
 *  - The kernel API is constantly changing, increasing maintenance burden
 *  - Many, many more.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <linux/vfio.h>

#include "util.h"
#include "ipc.h"
#include "ringbuf.h"
#include "config.h"
#include "libkvmchan-priv.h"

#define REASONABLE_PATH_LEN 512

// Helper macro for reading ivshmem BAR 0 values
#if (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) && \
    defined(__powerpc64__)
// Due to a bug in QEMU, ivshmem BAR 0 values are always Big Endian on powerpc64,
// even when both the host and guest are in Little Endian mode (ppc64le).
// Work around this by byte swapping the values.
//
// https://bugs.launchpad.net/qemu/+bug/1824744

#include <endian.h>
#define ivshmem_to_host32(x) be32toh(x)
#define host_to_ivshmem32(x) htobe32(x)

#else

// On all other platforms without this bug, these macros are no-ops
#define ivshmem_to_host32(x) (x)
#define host_to_ivshmem32(x) (x)

#endif

// Values stolen from vfio-pci driver to calculate mmap offsets
// (is this information seriously not in linux/vfio.h???)
#define VFIO_PCI_OFFSET_SHIFT 40
#define VFIO_PCI_OFFSET(x, page_shift) ((x) << (VFIO_PCI_OFFSET_SHIFT - (page_shift)) \
                                            << (page_shift))

struct ivshmem_bar0 {
    uint32_t reserved[2];
    uint32_t ivposition;
    uint32_t doorbell;
    uint8_t reserved1[240];
};

struct ivshmem_group {
    char name[4];
};

struct vfio_connection {
    char name[12 /* len(0000:00:00.0) */ + 1];
    int device_fd;
    volatile struct ivshmem_bar0 *bar0;

    // eventfd data
    int incoming_eventfds[NUM_EVENTFDS];
    int outgoing_eventfds[NUM_EVENTFDS];

    // REQ eventfd. Used by VFIO to signal to userspace
    // that a device is being unplugged.
    int req_eventfd;

    /**
     * Outgoing eventfds need to be emulated using
     * a pthread that polls on the eventfds and
     * writes to the appropriate mailbox on events.
     */
    pthread_t outgoing_thread;
    int outgoing_thread_kill;
};

struct vfio_host_connection {
    struct vfio_connection *conn;
    void *shared;
    size_t shared_size;

    // ringbuffers
    ringbuf_t host_to_client_rb;
    ringbuf_t client_to_host_rb;
};

struct vfio_data {
    int container;
    int group;
    struct vfio_host_connection host_conn;
    struct vec_voidp connections;
};

static struct vfio_data *g_vfio_data = NULL;
static struct vec_voidp *g_ivshmem_devices = NULL;

// Epoll object for all VFIO PCI REQ fds
static int req_epollfd;

static void vfio_conn_free_eventfds(struct vfio_connection *conn);

static void print_ivshmem_devices(struct vec_voidp *devices) {
    size_t i=0;

    printf("{");
    goto skip_comma;

    for (; i<devices->count; i++) {
        printf(", ");
skip_comma:
        printf("%s", (char *)devices->data[i]);
    }
    printf("}\n");
}

static void connection_destructor(void *conn_) {
    struct vfio_connection *conn = conn_;

    if (munmap((void *)conn->bar0, sizeof(struct ivshmem_bar0)) < 0)
        goto fail;

    vfio_conn_free_eventfds(conn);
    close(conn->device_fd);

    return;

fail:
    log(LOGL_ERROR, "Failed to free connection: %m. Potential resource leak.");
}

#ifdef USE_VFIO_NOIOMMU
static bool vfio_noiommu_is_enabled(void) {
    int fd = open("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode",
                  O_RDONLY);
    if (fd < 0)
        return false;

    char buf[1];
    if (read(fd, buf, 1) < 0) {
        close(fd);
        return false;
    }

    if (*buf != 'Y') {
        close(fd);
        return false;
    }

    close(fd);
    return true;
}
#endif

static off_t vfio_region_mmap_offset(off_t region) {
    static bool init_done = false;
    static long page_size;
    static long page_shift;
    if (!init_done) {
        page_size = sysconf(_SC_PAGESIZE);
        page_shift = __builtin_ctz(page_size);
        init_done = true;
    }

    return VFIO_PCI_OFFSET(region, page_shift);
}

/**
 * Validate that all given ivshmem devices are in an isolated IOMMU group.
 * For now, assume that all ivshmem devices must be in the same group.
 * Not used for NOIOMMU.
 *
 * If group_out is not NULL, the ivshmem group containing the devices
 * will be written to it.
 *
 * @param devices vector of PCI device IDs to validate
 * @return all ivshmem devices in isolated group?
 */
#ifndef USE_VFIO_NOIOMMU
static bool validate_iommu_groups(struct vec_voidp *ivshmem_devices,
                                  struct ivshmem_group *group_out) {
    // Go through all iommu groups in /sys/kernel/iommu_groups and make sure
    // that all ivshmem devices are contained in a single group with nothing
    // else.

    DIR *all_groups = opendir("/sys/kernel/iommu_groups");
    if (!all_groups) {
        log(LOGL_ERROR, "Failed to open /sys/kernel/iommu_groups: %m!");
        return false;
    }

    char pathbuf[REASONABLE_PATH_LEN];
    struct dirent *group;
    bool ivshmem_group_found = false;
    char ivshmem_group[4];
    while ((group = readdir(all_groups))) {
        if (group->d_name[0] == '.')
            continue; // Skip hidden, ".", ".."

        // Scan all IDs in this group
        snprintf(pathbuf, sizeof(pathbuf), "/sys/kernel/iommu_groups/%s/devices", group->d_name);
        DIR *cur_group = opendir(pathbuf);
        if (!cur_group)
            goto fail;

        struct dirent *device;
        bool contains_ivshmem_device = false;
        bool contains_other_device = false;
        while ((device = readdir(cur_group))) {
            if (device->d_name[0] == '.')
                continue; // Skip hidden, ".", ".."

            if (vec_voidp_contains(ivshmem_devices, device->d_name, (voidp_comparator)strcmp))
                contains_ivshmem_device = true;
            else
                contains_other_device = true;
        }
        closedir(cur_group);

        if (contains_ivshmem_device && ivshmem_group_found) {
            // Found at least two groups w/ ivshmem devices
            log(LOGL_ERROR, "ivshmem device(s) detected in more than one IOMMU group!");
            goto cleanup;
        }

        if (contains_ivshmem_device) {
            ivshmem_group_found = true;
            strncpy(ivshmem_group, group->d_name, sizeof(ivshmem_group) - 1);
            ivshmem_group[sizeof(ivshmem_group) - 1] = '\0';
        }

        if (contains_ivshmem_device && contains_other_device) {
            log(LOGL_ERROR, "ivshmem device detected in non-isolated IOMMU group!");
            goto cleanup;
        }
    }

    if (!ivshmem_group_found)
        return false;

    // Write group if requested
    if (group_out)
        strcpy(group_out->name, ivshmem_group);

    return true;

fail:
    log(LOGL_ERROR, "Error while scanning iommu groups: %m");
cleanup:
    closedir(all_groups);
    return false;
}
#endif

static bool validate_vfio_configuration(struct vec_voidp *ivshmem_devices,
                                        struct ivshmem_group *group_out) {
    // Check if vfio_pci is loaded by accessing
    // /sys/bus/pci/drivers/vfio-pci
    int fd = open("/sys/bus/pci/drivers/vfio-pci", O_RDONLY);
    if (fd < 0) {
        log(LOGL_ERROR, "vfio-pci is not loaded!\n"
                " Make sure your kernel was built with CONFIG_VFIO_PCI\n"
                " and run `modprobe vfio-pci`.");
        return false;
    }
    close(fd);

#ifdef USE_VFIO_NOIOMMU
    ignore_value(ivshmem_devices);
    ignore_value(group_out);
    if (!vfio_noiommu_is_enabled()) {
        log(LOGL_ERROR, "vIOMMU support for your platform is not implemented and\n"
                " vfio noiommu mode is not enabled!\n"
                " Make sure your kernel was built with CONFIG_VFIO_NOIOMMU (4.14+ only)\n"
                " and run `echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`.\n");
        log(LOGL_ERROR, "For an explanation of why this is necessary, see the comments in vfio.c.");
        return false;
    }
#else
    if (!validate_iommu_groups(ivshmem_devices, group_out)) {
        log(LOGL_ERROR, "ivshmem devices are not in an isolated IOMMU group!\n"
                " Please reconfigure your VM to isolate all ivshmem devices.\n"
                " On ppc64, this means using a separate spapr-pci-host-bridge device\n"
                " for the ivshmem devices.");
        return false;
    }
#endif

    return true;
}

/**
 * Validate that all given ivshmem devices are bound to vfio-pci.
 *
 * @param  devices         vector of PCI device IDs to check
 * @return -1 on error, 0 when at least 1 device not present, or 1 when all present.
 */
static int validate_vfio_bind(struct vec_voidp *devices) {
    char pathbuf[REASONABLE_PATH_LEN];
    for (size_t i=0; i<devices->count; i++) {
        // Confirm that this PCI ID exists as a directory
        snprintf(pathbuf, sizeof(pathbuf), "/sys/bus/pci/drivers/vfio-pci/%s",
                 (char *)devices->data[i]);
        DIR *dir = opendir(pathbuf);
        if (!dir) {
            if (errno == ENOENT) {
                closedir(dir);
                return 0;
            }
            closedir(dir);
            log(LOGL_ERROR, "Error encountered while checking vfio-pci devices: %m!");
            return -1;
        }
        closedir(dir);
    }

    return 1;
}

static bool do_vfio_bind(void) {
    const char ivshmem_device_vendor[] = "1af4 1110\n";
    int new_id_fd = open("/sys/bus/pci/drivers/vfio-pci/new_id", O_WRONLY);
    if (new_id_fd < 0)
        goto error;
    if (write(new_id_fd, ivshmem_device_vendor, sizeof(ivshmem_device_vendor)) < 0)
        goto error;

    close(new_id_fd);
    return true;

error:
    close(new_id_fd);
    return false;
}

/**
 * Find all attached ivshmem devices and add their slot string to
 * a given vector.
 *
 * @param devices  vector to add found ivshmem device slots to
 * @param nodup    check vector and avoid adding duplicate devices
 * @return success?
 */
static bool enumerate_ivshmem_devices(struct vec_voidp *devices, bool nodup) {
    // Traverse /sys/bus/pci/devices for ivshmem devices
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        log(LOGL_ERROR, "Failed to open /sys/bus/pci/devices: %m");
        return false;
    }

    struct dirent *cur;
    char pathbuf[REASONABLE_PATH_LEN];
    char filebuf[6 /* len(0x0000) */ + 1];
    while ((cur = readdir(dir))) {
        int fd;
        ssize_t n;
        if (cur->d_name[0] == '.')
            continue; // Skip hidden, ".", ".."

        // If nodup is true, make sure the vec doesn't already have this device
        if (nodup) {
            for (size_t i=0; i<devices->count; i++) {
                if (strncmp(devices->data[i], cur->d_name, strlen(cur->d_name)) == 0)
                    goto skip_device; // Already have this device, skip
            }
        }

        // Check vendor ID
        snprintf(pathbuf, sizeof(pathbuf), "/sys/bus/pci/devices/%s/vendor",
                 cur->d_name);
        if ((fd = open(pathbuf, O_RDONLY)) < 0)
            goto error_noclose;
        if ((n = read(fd, filebuf, sizeof(filebuf) - 1)) < 6 /* 0x0000 */)
            goto error;
        filebuf[n] = '\0';
        close(fd);

        if (strncmp(filebuf, "0x1af4" /* ivshmem vendor ID */, 6))
            continue;

        // Check device ID
        snprintf(pathbuf, sizeof(pathbuf), "/sys/bus/pci/devices/%s/device",
                 cur->d_name);
        if ((fd = open(pathbuf, O_RDONLY)) < 0)
            goto error_noclose;
        if ((n = read(fd, filebuf, sizeof(filebuf) - 1)) < 6 /* 0x0000 */)
            goto error;
        filebuf[n] = '\0';
        close(fd);

        if (strncmp(filebuf, "0x1110" /* ivshmem device ID */, 6))
            continue;

        // Check that revision == 0x01. Older revisions are unsupported.
        snprintf(pathbuf, sizeof(pathbuf), "/sys/bus/pci/devices/%s/revision",
                 cur->d_name);
        if ((fd = open(pathbuf, O_RDONLY)) < 0)
            goto error_noclose;
        if ((n = read(fd, filebuf, sizeof(filebuf) - 1)) < 4 /* 0x00 */)
            goto error;
        filebuf[n] = '\0';
        close(fd);

        if (strncmp(filebuf, "0x01" /* rev 0x01 */, 4))
            continue;

        // Match found, add this device to the vector
        char *device = strdup(cur->d_name);
        if (!device)
            goto error_noclose;

        if (!vec_voidp_push_back(devices, device))
            goto error_noclose;

        continue;

    error:
        log(LOGL_ERROR, "Failed to check PCI device %s: %m", cur->d_name);
        close(fd);
        continue;

    error_noclose:
        log(LOGL_ERROR, "Failed to open/parse PCI information: %m");
        continue;

    skip_device:
        ;
    }

    closedir(dir);
    return true;
}

bool remove_ivshmem_device(struct vec_voidp *devices, char *name) {
    for (size_t i=0; i<devices->count; i++) {
        char *cur = devices->data[i];
        if (strcmp(cur, name) == 0) {
            vec_voidp_remove(devices, i);
            return true;
        }
    }

    return false;
}

static int vfio_get_device_fd(struct vfio_data *data, const char *device) {
    int fd;
    if ((fd = ioctl(data->group, VFIO_GROUP_GET_DEVICE_FD, device)) < 0) {
        log(LOGL_ERROR, "Unable to obtain device fd for %s: %m!", device);
        close(fd);
        return -1;
    }

    return fd;
}

/**
 * Notify peer 0 at the specified interrupt vector
 *
 * @param conn   vfio_connection to notify over
 * @param vector interrupt vector number to notify
 */
static inline void notify_doorbell(struct vfio_connection *conn, uint16_t vector) {
    // See ivshmem_spec.txt for more information
    conn->bar0->doorbell = host_to_ivshmem32(vector);
        //host_to_ivshmem32(((0 << 16) & 0xFFFF) | (vector & 0xFFFF));
}

static void *outgoing_thread(void *conn_) {
    struct vfio_connection *conn = conn_;

    // epoll on outgoing eventfds
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        goto fail;
    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (add_epoll_fd(epoll_fd, conn->outgoing_eventfds[i], EPOLLIN) < 0)
            goto fail_epoll_create;
    }
    if (add_epoll_fd(epoll_fd, conn->outgoing_thread_kill, EPOLLIN) < 0)
        goto fail_epoll_create;

    struct epoll_event events[5];
    int event_count;
    for(;;) {
        event_count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);
        for (int i=0; i<event_count; i++) {
            int cur_fd = events[i].data.fd;

            // Flush event
            uint64_t buf;
            ignore_value(read(cur_fd, &buf, 8));

            // Exit if event is from the kill eventfd
            if (cur_fd == conn->outgoing_thread_kill)
                goto fail_epoll_create;

            // Get index of eventfd in outgoing_eventfds
            int idx = -1;
            for (size_t i=0; i<NUM_EVENTFDS; i++) {
                if (conn->outgoing_eventfds[i] == cur_fd) {
                    idx = i;
                    break;
                }
            }
            ASSERT(idx >= 0);

            // Notify the doorbell corresponding to this vector
            notify_doorbell(conn, idx);
        }
    }

fail_epoll_create:
    close(epoll_fd);
fail:
    log(LOGL_INFO, "Stopping outgoing eventfd handler thread.");
    return NULL;
}

/**
 * Send a message to a remote kvmchand over a given vfio_host_connection.
 * Follows the command format in libkvmchan-priv.h.
 *
 * @param      conn     connection to use
 * @param      msg      message to send
 * @param[out] response remote kvmchand's response
 * @return     success?
 */
static bool kvmchand_send_message(struct vfio_host_connection *conn, struct kvmchand_message *msg,
                                  struct kvmchand_ret *response) {
    shmem_hdr_t *hdr = conn->shared;

    if (RB_SUCCESS != ringbuf_sec_write(&conn->client_to_host_rb, &hdr->client_to_host_pub,
                                        msg, sizeof(struct kvmchand_message))) {
        log(LOGL_ERROR, "Failed to send message to host kvmchand!");
        return false;
    }

    if (RB_SUCCESS != ringbuf_sec_read(&conn->host_to_client_rb, &hdr->host_to_client_pub,
                                       response, sizeof(struct kvmchand_ret))) {
        log(LOGL_ERROR, "Failed to receive response from host kvmchand!");
        return false;
    }

    return true;
}

static bool vfio_conn_get_eventfds(struct vfio_connection *conn) {
    // For incoming interrupts, request eventfds directly from VFIO
    struct vfio_irq_info irq = {
        .argsz = sizeof(irq),
        .index = VFIO_PCI_MSIX_IRQ_INDEX
    };
    if (ioctl(conn->device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq) < 0)
        goto fail;
    if (irq.count != NUM_EVENTFDS) {
        log(LOGL_ERROR, "Unexpected # of eventfds available on ivshmem device!");
        return false;
    }
    for (size_t i=0; i<NUM_EVENTFDS; i++)
        conn->incoming_eventfds[i] = -1;
    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        conn->incoming_eventfds[i] = eventfd(0, 0);
        if (conn->incoming_eventfds[i] < 0)
            goto fail_incoming_eventfd;
    }

    // Link allocated eventfds to IRQs using VFIO
    char irqset_buf[sizeof(struct vfio_irq_set) + sizeof(int) * NUM_EVENTFDS];
    struct vfio_irq_set *irqset = (void *)irqset_buf;
    irqset->argsz = sizeof(irqset_buf);
    irqset->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irqset->index = VFIO_PCI_MSIX_IRQ_INDEX;
    irqset->start = 0;
    irqset->count = NUM_EVENTFDS;
    for (size_t i=0; i<NUM_EVENTFDS; i++)
        ((int *)irqset->data)[i] = conn->incoming_eventfds[i];

    if (ioctl(conn->device_fd, VFIO_DEVICE_SET_IRQS, irqset_buf) < 0)
        goto fail_incoming_eventfd;

    // For outgoing interrupts we have to spawn a thread that will
    // epoll the eventfds and perform the appropriate action.
    for (size_t i=0; i<NUM_EVENTFDS; i++)
        conn->outgoing_eventfds[i] = -1;
    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        conn->outgoing_eventfds[i] = eventfd(0, 0);
        if (conn->outgoing_eventfds[i] < 0)
            goto fail_outgoing_eventfd;
    }
    conn->outgoing_thread_kill = eventfd(0, 0);
    if (conn->outgoing_thread_kill < 0)
        goto fail_outgoing_eventfd;

    if (pthread_create(&conn->outgoing_thread, NULL, outgoing_thread, conn))
        goto fail_outgoing_thread_kill_eventfd;

    // Allocate and request req_eventfd
    conn->req_eventfd = eventfd(0, 0);
    irqset->argsz = sizeof(struct vfio_irq_set) + sizeof(int) * 1;
    irqset->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irqset->index = VFIO_PCI_REQ_IRQ_INDEX;
    irqset->start = 0;
    irqset->count = 1;
    ((int *)irqset->data)[0] = conn->req_eventfd;

    if (ioctl(conn->device_fd, VFIO_DEVICE_SET_IRQS, irqset_buf) < 0) {
        log(LOGL_WARN, "Failed to register req_eventfd for device: %m. Ignoring.\n");
        close(conn->req_eventfd);
        conn->req_eventfd = -1;
    } else {
        // Add req_eventfd to global epoll object
        if (add_epoll_fd(req_epollfd, conn->req_eventfd, EPOLLIN) < 0)
            log(LOGL_WARN, "Failed to register req_eventfd with epoll: %m.\n");
    }

    return true;

fail_outgoing_thread_kill_eventfd:
    close(conn->outgoing_thread_kill);
fail_outgoing_eventfd:
    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (conn->outgoing_eventfds[i] >= 0)
            close(conn->outgoing_eventfds[i]);
    }
fail_incoming_eventfd:
    for (size_t i=0; i<NUM_EVENTFDS; i++) {
        if (conn->incoming_eventfds[i] >= 0)
            close(conn->incoming_eventfds[i]);
    }
fail:
    log(LOGL_ERROR, "Unable to obtain eventfds for ivshmem device: %m!");
    return false;
}

static void vfio_conn_free_eventfds(struct vfio_connection *conn) {
    for (size_t i=0; i<NUM_EVENTFDS; i++)
        close(conn->incoming_eventfds[i]);
    close(conn->req_eventfd);

    // Notify kill eventfd
    uint64_t buf = 1;
    ignore_value(write(conn->outgoing_thread_kill, &buf, 8));
    pthread_join(conn->outgoing_thread, NULL);
    close(conn->outgoing_thread_kill);

    for (size_t i=0; i<NUM_EVENTFDS; i++)
        close(conn->outgoing_eventfds[i]);
}

static bool vfio_conn_vec_rebuild(struct vfio_data *data, struct vec_voidp *ivshmem_devices) {
    for (size_t i=0; i<ivshmem_devices->count; i++) {
        const char *device = ivshmem_devices->data[i];

        // Skip if a connection already exists for this device
        bool exists = false;
        for (size_t i=0; i<data->connections.count; i++) {
            struct vfio_connection *conn = data->connections.data[i];
            if (strncmp(conn->name, device, sizeof(conn->name) - 1) == 0) {
                exists = true;
                break;
            }
        }
        if (exists)
            continue;

        // Create connection
        struct vfio_connection *conn = malloc_w(sizeof(struct vfio_connection));

        strncpy(conn->name, device, sizeof(conn->name) - 1);
        conn->name[sizeof(conn->name) - 1] = '\0';

        conn->device_fd = vfio_get_device_fd(data, device);
        if (conn->device_fd < 0)
            goto fail_conn;

        conn->bar0 = mmap(NULL, sizeof(struct ivshmem_bar0), PROT_READ | PROT_WRITE, MAP_SHARED, conn->device_fd, 0);
        if (conn->bar0 == (void *)-1)
            goto fail_device_fd;

        if (!vfio_conn_get_eventfds(conn))
            goto fail_mmap_bar0;

        // Insert into connection vec
        if (!vec_voidp_push_back(&data->connections, conn))
            goto fail_get_eventfds;

        continue;

    fail_get_eventfds:
        vfio_conn_free_eventfds(conn);
    fail_mmap_bar0:
        munmap((void *)conn->bar0, sizeof(struct ivshmem_bar0));
    fail_device_fd:
        close(conn->device_fd);
    fail_conn:
        free(conn);
        return false;
    }

    return true;
}

static struct vfio_connection *vfio_conn_find_by_ivposition(struct vfio_data *data,
                                                            struct vec_voidp *ivshmem_devices, uint32_t ivposition) {
    // Scan for any new ivshmem devices
    if (!enumerate_ivshmem_devices(ivshmem_devices, true))
        return false;

    if (data->connections.count != ivshmem_devices->count) {
        // Rebuild connection list
        if (!vfio_conn_vec_rebuild(data, ivshmem_devices)) {
            log(LOGL_ERROR, "Failed to rebuild vfio connection vec!");
            return false;
        }
    }

    // Go through all connections and find the given ivposition
    for (size_t i=0; i<data->connections.count; i++) {
        struct vfio_connection *conn = data->connections.data[i];
        if (ivshmem_to_host32(conn->bar0->ivposition) == ivposition) {
            return conn;
        }
    }

    return NULL;
}

static bool connect_to_host_daemon(struct vfio_data *data, struct vec_voidp *ivshmem_devices) {
    void *shared;
    size_t shared_size;

    struct vfio_connection *conn;
    if (!(conn = vfio_conn_find_by_ivposition(data, ivshmem_devices, KVMCHAND_IVPOSITION))) {
        log(LOGL_ERROR, "Failed to establish connection to daemon!");
        return false;
    }
    data->host_conn.conn = conn;

    /* Host ivshmem device found, initialize connection */

    // Map shared memory region
    struct vfio_region_info region = {
        .argsz = sizeof(region),
        .index = VFIO_PCI_BAR2_REGION_INDEX
    };
    if (ioctl(conn->device_fd, VFIO_DEVICE_GET_REGION_INFO, &region) < 0) {
        goto fail;
    }

    shared_size = region.size;
    shared = mmap(NULL, shared_size, PROT_READ | PROT_WRITE, MAP_SHARED, conn->device_fd,
                  vfio_region_mmap_offset(VFIO_PCI_BAR2_REGION_INDEX));
    if (shared == (void *)-1) {
        goto fail;
    }

    shmem_hdr_t *hdr = shared;
    if (hdr->magic != SHMEM_MAGIC) {
        log(LOGL_INFO, "Invalid magic in shared memory header!"
                       " Is kvmchand running on the host?");
        errno = EINVAL;
        goto fail_mmap_shared;
    }

    data->host_conn.shared = shared;
    data->host_conn.shared_size = shared_size;

    // Initialize ringbuffers
    if (RB_SUCCESS != ringbuf_sec_infer_priv(&data->host_conn.host_to_client_rb, &hdr->host_to_client_pub,
                                             (uint8_t *)shared + DAEMON_H2C_OFFSET, DAEMON_RING_SIZE,
                                             RINGBUF_FLAG_BLOCKING, RINGBUF_DIRECTION_READ,
                                             conn->incoming_eventfds[0], conn->outgoing_eventfds[0])) {
        log(LOGL_ERROR, "Failed to infer host_to_client_rb!");
        goto fail_mmap_shared;
    }

    if (RB_SUCCESS != ringbuf_sec_infer_priv(&data->host_conn.client_to_host_rb, &hdr->client_to_host_pub,
                                             (uint8_t *)shared + DAEMON_C2H_OFFSET, DAEMON_RING_SIZE,
                                             RINGBUF_FLAG_BLOCKING, RINGBUF_DIRECTION_WRITE,
                                             conn->incoming_eventfds[1], conn->outgoing_eventfds[1])) {
        log(LOGL_ERROR, "Failed to infer client_to_host_rb!");
        goto fail_mmap_shared;
    }

    // Send HELLO message to server and confirm response
    struct kvmchand_ret ret;
    struct kvmchand_message msg = {
        .command = KVMCHAND_CMD_HELLO,
        .args = { KVMCHAND_API_VERSION },
    };
    if (!kvmchand_send_message(&data->host_conn, &msg, &ret)) {
        log(LOGL_ERROR, "Failed to confirm connection to host kvmchand! Did it crash?");
        goto fail_mmap_shared;
    }

    if (ret.ret != KVMCHAND_API_VERSION) {
        log(LOGL_ERROR, "Host kvmchand uses API version %llu but we're on %llu! Aborting.", ret,
            KVMCHAND_API_VERSION);
        goto fail_mmap_shared;
    }

    log(LOGL_INFO, "Successfully connected to host daemon.");
    return true;

fail_mmap_shared:
    munmap(shared, shared_size);
fail:
    log(LOGL_ERROR, "Failed to connect to host daemon: %m!");
    return false;
}

/**
 * Initialize a vfio instance that can be used to access ivshmem devices.
 *
 * @param data        vfio_data struct to initialize
 * @param group_name  name of ivshmem group to use (not used in NOIOMMU)
 */
static bool vfio_init(struct vfio_data *data, struct vec_voidp *ivshmem_devices,
                      struct ivshmem_group *ivshmem_group) {
    int container = open("/dev/vfio/vfio", O_RDWR);
    if (container < 0) {
        log(LOGL_ERROR, "Unable to open vfio container: %m!");
        return false;
    }

#ifdef USE_VFIO_NOIOMMU
    int group = open("/dev/vfio/noiommu-0", O_RDWR);
#else
    char pathbuf[REASONABLE_PATH_LEN];
    snprintf(pathbuf, sizeof(pathbuf), "/dev/vfio/%s", ivshmem_group->name);
    int group = open(pathbuf, O_RDWR);
#endif
    if (group < 0) {
        log(LOGL_ERROR, "Unable to open vfio group:  %m!");
        goto fail_container_open;
    }

    // Check that the group is viable (this check may be useless in NOIOMMU mode)
    struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
    if (ioctl(group, VFIO_GROUP_GET_STATUS, &group_status) < 0) {
        log(LOGL_ERROR, "Failed to get vfio group status: %m!");
        goto fail_group_open;
    }
    if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        log(LOGL_ERROR, "vfio group is not viable!");
        goto fail_group_open;
    }

    // Add the group to the container
    if (ioctl(group, VFIO_GROUP_SET_CONTAINER, &container) < 0) {
        log(LOGL_ERROR, "Failed to set vfio group's container: %m!");
        goto fail_group_open;
    }

    // Set IOMMU mode
#if defined(USE_VFIO_NOIOMMU)
    if (ioctl(container, VFIO_SET_IOMMU, VFIO_NOIOMMU_IOMMU) < 0) {
        log(LOGL_ERROR, "Failed to set NOIOMMU mode on vfio container: %m!");
        goto fail_group_open;
    }
#elif defined(USE_VFIO_SPAPR)
    if (ioctl(container, VFIO_SET_IOMMU, VFIO_SPAPR_TCE_IOMMU) < 0) {
        log(LOGL_ERROR, "Failed to set SPAPR IOMMU mode on vfio container: %m!");
        goto fail_group_open;
    }
#else
#error "Unimplemented IOMMU mode"
#endif

    // Construct vector of connections
    if (!vec_voidp_init(&data->connections, 10, connection_destructor))
        goto fail_group_open;

    // Flush data and connect to host daemon
    data->container = container;
    data->group = group;
    if (!connect_to_host_daemon(data, ivshmem_devices))
        goto fail_conn_vec;

    // Success
    return true;

fail_conn_vec:
    vec_voidp_destroy(&data->connections);
fail_group_open:
    close(group);
fail_container_open:
    close(container);
    return false;
}

/**
 * Handle IPC messages from other kvmchand processes
 */
static void handle_ipc_message(struct ipc_message *msg) {
    struct ipc_cmd *cmd = &msg->cmd;
    struct ipc_message response = {
        .type = IPC_TYPE_RESP,
        .resp.error = true,
        .dest = msg->src,
        .fd_count = 0,
        .id = msg->id
    };

    switch(cmd->command) {
        case VFIO_IPC_CMD_FORWARD_KVMCHAND_MSG:
        {
            // Unpack command into a kvmchand_msg
            struct kvmchand_message kmsg = {
                .command = cmd->args[0],
                .args = {
                    cmd->args[1],
                    cmd->args[2],
                    cmd->args[3],
                    cmd->args[4],
                },
            };

            /**
             * For now, just message and block for the first response.
             * We don't have the fancy multiplexing and message sequencing
             * that the IPC system has, so only one thread can use the
             * ivshmem communication channel at a time.
             */
            struct kvmchand_ret ret;
            if (!kvmchand_send_message(&g_vfio_data->host_conn, &kmsg, &ret)) {
                log(LOGL_WARN, "Failed to forward message to dom0 kvmchand!");
                break;
            }

            log(LOGL_INFO, "resp from host: err: %d, ret: %d", ret.error, ret.ret);
            response.resp.error = ret.error;
            response.resp.ret = ret.ret;

            break;
        }

        case VFIO_IPC_CMD_GET_CONN_FDS:
        {
            uint32_t ivposition = (uint32_t)cmd->args[0];
            struct vfio_connection *conn = vfio_conn_find_by_ivposition(g_vfio_data, g_ivshmem_devices,
                                                                        ivposition);
            if (!conn) {
                // IVPosition not found, return error
                break;
            }

            // Return descriptors
            response.fd_count = 5;
            response.flags = IPC_FLAG_FD;
            response.fds[0] = conn->device_fd;
            response.fds[1] = conn->incoming_eventfds[0];
            response.fds[2] = conn->incoming_eventfds[1];
            response.fds[3] = conn->outgoing_eventfds[0];
            response.fds[4] = conn->outgoing_eventfds[1];

            response.resp.error = false;
            break;
        }

        default:
            log_BUG("Unknown IPC command received in ivshmem loop: %"PRIu64, cmd->command);
    }

    if (msg->flags & IPC_FLAG_WANTRESP) {
        if (!ipc_send_message(&response, NULL))
            log_BUG("Unable to send response to IPC message!");
    }
}

static struct vfio_connection *get_conn_by_req_eventfd(struct vfio_data *data, int fd, size_t *conn_i_out) {
    for (size_t i=0; i<data->connections.count; i++) {
        struct vfio_connection *cur = data->connections.data[i];
        if (cur->req_eventfd == fd) {
            if (conn_i_out)
                *conn_i_out = i;

            return cur;
        }
    }

    return NULL;
}

void run_vfio_loop(int mainsoc) {
    if ((req_epollfd = epoll_create1(0)) < 0) {
        log(LOGL_ERROR, "Failed to create epollfd: %m!");
        return;
    }

    if (!ipc_start(mainsoc, IPC_DEST_VFIO, handle_ipc_message)) {
        log(LOGL_ERROR, "Failed to start IPC threads: %m!");
        return;
    }

    // Enumerate all ivshmem devices
    struct vec_voidp ivshmem_devices;
    if (!vec_voidp_init(&ivshmem_devices, 10, free_destructor)) {
        log(LOGL_ERROR, "Failed to allocate vec of ivshmem devices!");
        return;
    }
    if (!enumerate_ivshmem_devices(&ivshmem_devices, false)) {
        log(LOGL_ERROR, "Failed to enumerate ivshmem devices!");
        return;
    }

    if (ivshmem_devices.count == 0) {
        log(LOGL_ERROR, "Unable to find ivshmem device!\n"
                " Is kvmchand running in host mode in dom0?");
        return;
    }
    g_ivshmem_devices = &ivshmem_devices;

    for (size_t i=0; i<ivshmem_devices.count; i++) {
        log(LOGL_INFO, "Got ivshmem device: %s", ivshmem_devices.data[i]);
    }

    // Validate vfio configuration
    struct ivshmem_group group;
    if (!validate_vfio_configuration(&ivshmem_devices, &group))
        return;

    // Confirm that all devices are bound to vfio-pci
    int ret = validate_vfio_bind(&ivshmem_devices);
    if (ret < 0)
        goto error;
    if (ret == 0) {
        // At least one ivshmem device was not bound to vfio-pci.
        // Try adding the ivshmem device/vendor ID to vfio-pci
        // and trying again.

        log(LOGL_WARN, "Some ivshmem devices aren't bound to vfio-pci. Attempting to bind...");

        if (!do_vfio_bind())
            goto error;

        // Check again
        ret = validate_vfio_bind(&ivshmem_devices);
        if (ret < 0)
            goto error;
        if (ret == 0) {
            log(LOGL_ERROR, "Manual binding failed! Please make sure all ivshmem devices"
                            " are bound to vfio-pci and try again.");
            bail_out();
        }

        log(LOGL_WARN, "Successfully bound ivshmem devices.");
    }

    // Initialize vfio
    struct vfio_data vfio;
    if (!vfio_init(&vfio, &ivshmem_devices, &group))
        goto error;
    g_vfio_data = &vfio;

    // Epoll loop to check for disconnected devices
    struct epoll_event events[5];
    int event_count;
    for (;;) {
        event_count = epoll_wait(req_epollfd, events, ARRAY_SIZE(events), -1);
        for (int i=0; i<event_count; i++) {
            int fd = events[i].data.fd;
            log(LOGL_INFO, "VFIO requesting ivshmem detach. fd: %d", fd);

            // This device is going to be removed.
            // For now, simply destroy our local data for it and acknowledge the
            // request. Eventually, we may want to take some other action, like
            // send a signal to all clients who are using the device.
            uint64_t buf;
            ignore_value(read(fd, &buf, sizeof(buf)));

            // Remove the fd from epoll
            if (epoll_ctl(req_epollfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
                log(LOGL_ERROR, "Failed to delete req fd: %m.");
                goto error;
            }

            // Remove connection
            size_t conn_i;
            struct vfio_connection *cur_conn = get_conn_by_req_eventfd(&vfio, fd, &conn_i);
            ASSERT(cur_conn);

            ASSERT(remove_ivshmem_device(&ivshmem_devices, cur_conn->name));
            vec_voidp_remove(&vfio.connections, conn_i);
        }
    }

error:
    log(LOGL_ERROR, "Vfio loop encountered fatal error: %m!");
}
