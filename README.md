linux-netns-sysctl-verify
=========================
Linux network namespace sysctl safety verifier.

# Background
The Linux kernel provides runtime-configurable kernel parameters known as
["sysctls"][sysctl], which are accessed via `/proc/sys/`.

Linux also supports supports *network namespaces* (netns) which enable isolated
virtual network stacks and are used heavily by containerization platforms like
[LXC] or [Docker]. See [`network_namespaces(7)`][network_namespaces].

It's generally understood that the "net" sysctls (under `/proc/sys/net`) are
supposed to be "netns safe", meaning that manipulating sysctls from one network
namespace cannot affect any other network namespace. This isn't exactly
guaranteed, though.

It may be desirable to allow a container to write to net sysctls, specifically
parameters of devices which exist only within the container's netns.  However,
the latest version of Docker (20.10.6 as of this writing) mounts all of
`/proc/sys` read-only, to prevent changes made in a container from "leaking"
out of the container. This protection mechanism makes it more difficult (and
less secure) to run a [libvirt] QEMU VM inside of a Docker container.

This tool was inspired by conversation on [this runc issue][runc_2826].  Use of
this tool helped to uncover several bugs in the Linux kernel's implementation
of several sysctls, which have been subsequently fixed by this tool's author.
Additionally, a safety check was added to the kernel to prevent certain classes
of bugs from going unnoticed:

- [`2671fa4dc010`](https://github.com/torvalds/linux/commit/2671fa4dc010):
  `netfilter: conntrack: Make global sysctls readonly in non-init netns`
- [`97684f0970f6`](https://github.com/torvalds/linux/commit/97684f0970f6):
  `net: Make tcp_allowed_congestion_control readonly in non-init netns`
- [`31c4d2f160eb`](https://github.com/torvalds/linux/commit/31c4d2f160eb):
  `net: Ensure net namespace isolation of sysctls`


# Theory of Operation
The premise behind this tool is simple:
- Take a snapshot of all values in `/proc/sys/net`.
- Create a child process with a new netns (using `CLONE_NEWNET`).
- In the child netns, modify every writable value in `/proc/sys/net`.
- Exit the child netns.
- Take a second snapshot of `/proc/sys/net`.
- Compare the snapshots and report any differences.

Anything in the parent which changed as a result of manipulations in the child
is considered a "leak".



[sysctl]: https://man7.org/linux/man-pages/man8/sysctl.8.html
[network_namespaces]: https://man7.org/linux/man-pages/man7/network_namespaces.7.html
[LXC]: https://linuxcontainers.org/
[Docker]: https://docs.docker.com/get-started/overview/
[libvirt]: https://libvirt.org/
[runc_2826]: https://github.com/opencontainers/runc/issues/2826
