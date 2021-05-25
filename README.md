linux-netns-sysctl-verify
=========================
Linux network namespace sysctl safety verifier.

Ensure that `net` sysctls are network-namespace-safe.

# Usage

```
usage: verify.py [-h] [-v]

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Verbose output
```

Currently, this must be run as root, in order to use `CLONE_NEWNET`.

```
$ sudo ./verify.py -v
```

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

This tool was inspired by conversation on [this runc issue][runc_2826].

# Results
Use of this tool helped to uncover several bugs in the Linux kernel's
implementation of several sysctls, which have been subsequently fixed by this
tool's author:

- `netfilter: conntrack: Make global sysctls readonly in non-init netns`
  - Affected sysctls:
    - `net.nf_conntrack_max`
    - `net.netfilter.nf_conntrack_max`
    - `net.netfilter.nf_conntrack_expect_max`
  - Fixed in Kernels:
    - 5.13+: `v5.13-rc1` ([`2671fa4dc010`](https://github.com/gregkh/linux/commit/2671fa4dc010))
    - 5.12: `v5.12.2` ([`671c54ea8c7f`](https://github.com/gregkh/linux/commit/671c54ea8c7f))
    - 5.11: `v5.11.19` ([`fbf85a34ce17`](https://github.com/gregkh/linux/commit/fbf85a34ce17))
    - 5.10: `v5.10.35` ([`d3598eb3915c`](https://github.com/gregkh/linux/commit/d3598eb3915c))
    - 5.4: `v5.4.120` ([`baea536cf51f`](https://github.com/gregkh/linux/commit/baea536cf51f))
    - 4.19: `v4.19.191` ([`9b288479f7a9`](https://github.com/gregkh/linux/commit/9b288479f7a9))
    - 4.14: `v4.14.233` ([`68122479c128`](https://github.com/gregkh/linux/commit/68122479c128))
    - 4.9: `v4.9.269` ([`da50f56e826e`](https://github.com/gregkh/linux/commit/da50f56e826e))

- `net: Make tcp_allowed_congestion_control readonly in non-init netns`
  - Affected sysctls:
    - `net.ipv4.tcp_allowed_congestion_control`
  - Fixed in Kernels:
    - 5.12+: `v5.12-rc8` ([`97684f0970f6`](https://github.com/gregkh/linux/commit/97684f0970f6))
    - 5.11: `v5.11.16` ([`1ccdf1bed140`](https://github.com/gregkh/linux/commit/1ccdf1bed140))
    - 5.10: `v5.10.32` ([`35d7491e2f77`](https://github.com/gregkh/linux/commit/35d7491e2f77))
    - 5.4: (n/a)
    - 4.19: (n/a)
    - 4.14: (n/a)
    - 4.4: (n/a)

- `net: Only allow init netns to set default tcp cong to a restricted algo`
  - Related sysctls:
    - `net.ipv4.tcp_congestion_control` (affects)
    - `net.ipv4.tcp_allowed_congestion_control` (affected)
  - Fixed in Kernels:
    - 5.13+: `v5.13-rc1` ([`8d432592f30f`](https://github.com/gregkh/linux/commit/8d432592f30f))
    - 5.12: `v5.12.4` ([`e7d7bedd507b`](https://github.com/gregkh/linux/commit/e7d7bedd507b))
    - 5.11: `v5.11.21` ([`efe1532a6e1a`](https://github.com/gregkh/linux/commit/efe1532a6e1a))
    - 5.10: `v5.10.37` ([`6c1ea8bee75d`](https://github.com/gregkh/linux/commit/6c1ea8bee75d))
    - 5.4: `v5.4.119` ([`9884f745108f`](https://github.com/gregkh/linux/commit/9884f745108f))
    - 4.19: `v4.19.191` ([`992de06308d9`](https://github.com/gregkh/linux/commit/992de06308d9))
    - 4.14: (n/a)
    - 4.9: (n/a)


Additionally, a safety check was added to the kernel to prevent
certain classes of bugs from going unnoticed:

- [`31c4d2f160eb`](https://github.com/gregkh/linux/commit/31c4d2f160eb):
  `net: Ensure net namespace isolation of sysctls`


[sysctl]: https://man7.org/linux/man-pages/man8/sysctl.8.html
[network_namespaces]: https://man7.org/linux/man-pages/man7/network_namespaces.7.html
[LXC]: https://linuxcontainers.org/
[Docker]: https://docs.docker.com/get-started/overview/
[libvirt]: https://libvirt.org/
[runc_2826]: https://github.com/opencontainers/runc/issues/2826
