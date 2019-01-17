libkvmchan
======
libkvmchan is a library for sending data across shared memory channels like [KVM's ivshmem](https://github.com/qemu/qemu/blob/master/docs/specs/ivshmem-spec.txt).

It is meant to implement a subset of the functionality provided by [Xen's libvchan](https://www.cs.uic.edu/~xzhang/vchan/#x1-20002).
As of now, only blocking, packet-based communication is supported.

Overview
-----
libkvmchan uses a host/client architecture. Generally, the host is the KVM host system and the client is a virtual machine.
Since libkvmchan uses `ivshmem`, all client machines must be configured with an `ivshmem` device in qemu/libvirt.
This is described in the [Looking Glass Project's Documentation](https://looking-glass.hostfission.com/quickstart/linux/libvirt).

In addition to an attached `ivshmem` device, clients also need the [ivshmem-uio](https://github.com/shawnanastasio/ivshmem-uio)
kernel driver in order to communicate with the device.

Once `ivshmem` is configured, libkvmchan can be used. The host must be initialized first with the `libkvmchan_host_open`
function.
```C
// Open a handle to the POSIX shared memory region that we can pass to libkvmchan_host_open
libkvmchan_shm_handle_t *handle = libkvmchan_shm_open_posix("/my_vm_shared_memory_region");
if (!handle) {
    perror("libkvmchan_shm_open_posix");
    return 1;
}

// Initialize a libkvmchan host
libkvmchan_t *chan = libkvmchan_host_open("/my_vm_shared_memory_region");
if (!chan) {
    perror("libkvmchan_host_open");
    return 1;
}

while (1) {
    // Event loop
}
```
In this example, the POSIX shared memory region is named `my_vm_shared_memory_region`. This was set when attaching the `ivshmem`
device to your VM. Note that a host must be initialized before clients can connect.

After a host is initialized, clients can connect. Ensure that the `ivshmem-uio` kernel driver is loaded and use
`libkvmchan_client_open` to connect.
```C
// Open a handle to the same shared memory region. Since we're in a VM,
// this done via the uio driver rather than POSIX shared memory objects.
libkvmchan_shm_handle_t *handle = libkvmchan_shm_open_uio("uio0")
if (!handle) {
    perror("libkvmchan_shm_open_uio");
    return 1;
}

libkvmchan_t *chan = libkvmchan_client_open(handle);
if (!chan) {
    perror("libkvmchan_client_open");
    return 1;
}

while (1) {
    // Event loop
}
```
The first parameter to `libkvmchan_client_open` is the name of the uio device created by `ivshmem-uio` in /dev.
This is almost always `uio0`.

Once both host and client are connected, data can be sent/read using `libkvmchan_write` and `libkvmchan_read`.

Security
--------
Disclaimer: I provide absolutely zero security guarantees for libkvmchan. Before using it, please consider
whether or not your threat model allows you to trust random, unaudited C code from GitHub.
That being said, I have tried my best to architect the software in a robust and secure manner.
I also welcome security contributions from the community in the form of bug reports and code.

libkvmchan performs data validation and sanity checks on both the server and client.

Specifically, pointers, offsets, and counts in the internal ring buffer structures are validated before
each operation. Upon a client or server open, ring buffer metadata is validated and copied to
local, non-shared memory. On all subsequent operations, this copy is compared
to the one in the shared memory region. If any properties that the other process isn't allowed
to modify have changed, the operation will fail.

For properties that the other process is allowed to change, instead of comparing to the reference copy,
bounds checks and other sanity checks are performed.

The consequence of this architecture is that, barring implementation bugs, a malicious process
can't trick a trusted process to read/write outside of the bounds of the ring buffer. In the
worst case, a malicious process can only get a trusted process to overwrite existing data
in the ring buffer and corrupt it. This should have no security consequences for the
trusted process, since it will never read from any ring buffer that it writes to.


Why?
---
libkvmchan was created to assist in the porting of Xen-specific applications to KVM hosts, such as 
certain applications created by the [QubesOS Project](https://www.qubes-os.org).

License
----
All code is licensed under the GNU LGPL v3.0. Contributions are welcome.
