libkvmchan
======
libkvmchan is a library for sending data across shared memory channels like [KVM's ivshmem](https://github.com/qemu/qemu/blob/master/docs/specs/ivshmem-spec.txt).

It is meant to implement a subset of the functionality provided by [Xen's libvchan](https://www.cs.uic.edu/~xzhang/vchan/#x1-20002).
As of now, only blocking, streaming-based communication is supported.

Overview
-----
libkvmchan operates on the notion of a host and client. Generally, the host is the KVM host system and the client is a virtual machine.
Since libkvmchan uses `ivshmem`, all client machines must be configured with an `ivshmem` device in qemu/libvirt.
This is described in the [Looking Glass Project's Documentation](https://looking-glass.hostfission.com/quickstart/linux/libvirt).

In addition to an attached `ivshmem` device, clients also need the [ivshmem-uio](https://github.com/shawnanastasio/ivshmem-uio)
kernel driver in order to communicate with the device.

Once `ivshmem` is configured, libkvmchan can be used. The host must be initialized first with the `libkvmchan_host_open`
function.
```C
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
libkvmchan_t *chan = libkvmchan_client_open("/dev/uio0");
if (!chan) {
    perror("libkvmchan_client_open");
    return 1;
}

while (1) {
    // Event loop
}
```
The first parameter to `libkvmchan_client_open` is the path to the character device created by the kernel driver.
This is almost always `/dev/uio0`.

Once both host and client are connected, data can be sent/read using `libkvmchan_write` and `libkvmchan_read`.

Why?
---
libkvmchan was created to assist in the porting of Xen-specific applications to KVM hosts, such as 
certain applications created by the [QubesOS Project](https://www.qubes-os.org).

License
----
All code is licensed under the GNU LGPL v3.0. Contributions are welcome.