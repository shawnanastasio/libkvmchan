libkvmchan
======
libkvmchan is an implementation of the Xen [libvchan](https://www.cs.uic.edu/~xzhang/vchan/#x1-20002) shared memory API for KVM+QEMU. It utilizes [ivshmem](https://github.com/qemu/qemu/blob/master/docs/specs/ivshmem-spec.txt) to provide the memory backend and a custom
daemon to allow run-time configuration of vchans.

The full libvchan API has been implemented, which should allow for easy porting of Xen-specific applications to KVM.

Overview
-----
### Daemon
The bulk of libkvmchan's functionality is implemented in the `kvmchand` daemon.
Creation of vchans, hotplugging of `ivshmem` memory backend devices, and resource management are all performed there.
The daemon exposes a simple UNIX socket interface that allows client applications to request vchan operations.
The `libkvmchan.so` library wraps the socket interface and provides an API compatible with libvchan.

The daemon is highly compartmentalized, with each basic set of functionality isolated to its own process.
This allows for a granular privilege separation and sandboxing (not yet implemented).
The different processes communicate using a custom IPC mechanism that wraps UNIX sockets to provide a synchronous RPC interface (see `daemon/ipc.c`).

The different parts of the daemon are as follows:

* main (daemon.c) - Implements high level vchan bookkeeping and IPC packet routing. Allocates shared memory and keeps track of active vchans.

* ivshmem (ivshmem.c) - Implements the ivshmem server protocol. Allows assignment of shared memory to QEMU at run-time.

* libvirt (libvirt.c) - VM lifecycle management and run-time hardware configuration. Allows attaching/detaching ivshmem PCIe devices to VMs at run-time.

* localhandler (localhandler.c) - Implements the local UNIX socket API that allows clients in the same domain to create/destroy vchans. Used by libkvmchan.so

* VFIO (vfio.c) - Implements a userspace PCIe driver for ivshmem devices using the VFIO subsystem. Handles shared memory mapping and interrupts.

* IPC (ipc.c) - Implements the synchronous RPC framework that allows the other parts to talk to each other.

Due to the nature of libkvmchan's design, the `kvmchand` daemon must be running in every domain that wishes to use vchans. The daemon contains two modes that determine which features enabled - Host and Guest.

In Host mode, all of the above components except VFIO are enabled. This mode must be used on the host (dom 0) and is required for Guest mode daemons to function at all.

In Guest mode, only main, localhandler, VFIO, and IPC are used. In this mode, the daemon establishes a connection to the Host daemon via a reserved ivshmem device.
The implementations of most client vchan operations in this mode are simple wrappers that forward the requests to the Host daemon.
When the response to the request is received, it is sent back to the client over the local UNIX socket.

The disparity between daemon operation in Host and Client mode is abstracted from client API consumers.
This means that applications using `libkvmchan.so`'s wrappers do not need to worry about whether they are
operating in dom 0 or not.

Security
--------
__Disclaimer: I provide absolutely zero security guarantees for libkvmchan. Before using it, please consider
whether or not your threat model allows you to trust random, unaudited C code from GitHub.
That being said, I have tried my best to architect the software in a robust and secure manner.
I also welcome security contributions from the community in the form of bug reports and code.__

### Ring Buffer
At the heart of libkvmchan is the ring buffer implementation that sits on top of shared memory regions to provide read/write operations.
This section outlines the security measures provided by the ring buffer implementation.

The ring buffer performs data validation and sanity checks on both the server and client. 

Specifically, pointers, offsets, and counts in the internal structures are validated before each operation. 
Ring buffer data is split into two structures, `ringbuf_t` and `ringbuf_pub_t`.
The former stores trusted data outside of the shared memory region and can't be changed by the other end.
The latter sits in shared memory and stores information that can be changed by the other end.

To prevent abuse, all fields in the `ringbuf_pub_t` struct are copied to local, non-shared memory and validated before all operations.
This prevents TOCTOU attacks as well as malicious pointer manipulation.
If any pointers lie outside buffer bounds, any operations will immediately fail.

The consequence of this architecture is that, barring implementation bugs, a malicious process
can't trick a trusted process to read/write outside of the bounds of the ring buffer. In the
worst case, a malicious process can only get a trusted process to overwrite existing data
in the ring buffer and corrupt it. This should have no security consequences for the
trusted process, since it will never read from any ring buffer that it writes to.

### Daemon
See TODO

TODO
----
    * Write more demos/tests
    * Implement per-component sandboxing in the daemon using seccomp-bpf
    * Implement privilege de-escalation for all daemon components that don't need root (everything except VFIO)

Why?
---
libkvmchan was created to assist in the porting of Xen-specific applications to KVM hosts, such as 
certain applications created by the [QubesOS Project](https://www.qubes-os.org).

License
----
All code is licensed under the GNU LGPL v3.0. Contributions are welcome.
