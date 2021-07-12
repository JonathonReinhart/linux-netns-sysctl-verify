#!/usr/bin/env python3
import difflib
import os
import sys
from pathlib import Path
import clone
import errno
import stat

SYSCTL_PATH = Path('/proc/sys')

# Modifications to these sysctls should be ignored
MODIFICATION_IGNORE = {
    # This can change at any time, regardless of sysctl changes (see issue #6)
    'net/netfilter/nf_conntrack_count',
}

IGNORE_WRITE_ERRORS = {
    # EPREM is is expected for restricted algos (see issue #2)
    'net/ipv4/tcp_congestion_control': errno.EPERM,
}

g_verbose = False

def vprint(*args, **kwargs):
    if g_verbose:
        return print(*args, **kwargs)


def warn(s):
    print(yellow(str(s)), file=sys.stderr)

def color(s, c):
    return f'\033[{c}m' + s + '\033[0m'

def red(s):
    return color(s, 31)

def green(s):
    return color(s, 32)

def yellow(s):
    return color(s, 33)


def iterate_sysctl(path=""):
    for root, dirs, files in os.walk(SYSCTL_PATH / path):
        root = Path(root)
        for fn in files:
            path = root / fn
            yield path

def iterate_sysctl_values(path=""):
    for path in iterate_sysctl(path):
        try:
            value = path.read_text().strip()
        except OSError as e:
            if isinstance(e, PermissionError) and not os.access(path, os.R_OK):
                # If it's not readable, just ignore it
                continue
            if e.errno == errno.EIO:
                if path.name == "stable_secret":
                    continue
            if e.errno == errno.EINVAL:
                if path.name == "forwarding" and path.parent.parent.parent.name == "decnet":
                    continue
            warn(f"Error reading {path}: {e}")
            continue

        yield path, value

def path_to_name(path):
    return str(path.relative_to(SYSCTL_PATH))

def snapshot():
    result = dict()
    for path, val in iterate_sysctl_values("net"):
        k = path_to_name(path)
        result[k] = val

    return result

def dict_compare(d1, d2):
    # https://stackoverflow.com/a/18860653/119527
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    shared_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o : (d1[o], d2[o]) for o in shared_keys if d1[o] != d2[o]}
    same = set(o for o in shared_keys if d1[o] == d2[o])
    return added, removed, modified, same

def dict_remove(d, keys):
    for k in keys:
        try:
            d.pop(k)
        except KeyError:
            pass

def get_avail_tcp_cong():
    return set(g_avail_tcp_cong)    # copy


def frob_tcp_cong(path, val):
    avail = get_avail_tcp_cong()
    avail.remove(val)
    res = avail.pop()   # arbitrary
    return res

def frob_tcp_allowed_cong(path, val):
    cur = set(val.split())
    cur.pop()   # arbitrary
    return " ".join(cur)


special_sysctls = {
    '/proc/sys/net/ipv4/ip_local_reserved_ports':   ("", "69-6969"),
    '/proc/sys/net/ipv4/tcp_congestion_control':    frob_tcp_cong,
    '/proc/sys/net/ipv4/tcp_allowed_congestion_control': frob_tcp_allowed_cong,
    '/proc/sys/net/ipv4/tcp_fastopen_key': ("00000000-00000000-00000000-00000000", "11111111-22222222-33333333-44444444"),
    '/proc/sys/net/ipv6/icmp/ratemask':                 ("0-1,3-127", "0-1,6-69"),
    '/proc/sys/net/ipv6/route/skip_notify_on_dev_down': ('256', '0'),
    '/proc/sys/net/rds/tcp/rds_tcp_rcvbuf':             ('0', '2305'),
    '/proc/sys/net/rds/tcp/rds_tcp_sndbuf':             ('0', '4609'),
    '/proc/sys/net/sctp/cookie_hmac_alg':               ('md5', 'sha1'),
    '/proc/sys/net/ipv4/vs/sync_ports':                 ('1', '2'),
    '/proc/sys/net/ipv4/tcp_adv_win_scale':             ('1', '2'),
}

def frob_special(path, val):
    f = special_sysctls.get(str(path))
    if isinstance(f, tuple):
        exp, new = f
        if val != exp:
            # TODO: Ideally we wouldn't have any fixed expected values,
            #       and we could always frob to something different...
            raise AssertionError(f"Expected current value to be {exp}, but found {val}")
        return new
    if f:
        return f(path, val)

    if path.parent.samefile("/proc/sys/net/netfilter/nf_log"):
        return frob_nf_log(path, val)
    return None


def frob_int_vec(path, val):
    parts = val.split()
    parts = [frob_int(path, p) for p in parts]
    if None in parts:
        return None
    return " ".join(parts)


def frob_nf_log(path, val):
    if val.startswith("nf_log"):
        return "NONE"

    assert val == "NONE"
    # TIP: `modprobe nfnetlink_log`
    return "nfnetlink_log"


U8_MAX  = 0xFF
U16_MAX = 0xFFFF
I32_MAX = 0x7FFFFFFF
U32_MAX = 0xFFFFFFFF

# Ranges/sequences of values for which integer values should be decremented.
# Use a sequence of ranges/sequences (unflattened) for fast `if ... in`.
intval_decrement = (
    range(1, 20),
    range(1300, 1500), # mtu
    (
        U8_MAX, U8_MAX+1,
        U16_MAX, U16_MAX+1,
        U32_MAX,
        I32_MAX,
        0x40000,
        0x400000,
    ),
)

def frob_int(path, val):
    # Does it look like an integer?
    try:
        ival = int(val)
    except ValueError:
        return

    # Try to adjust it in a way that will work without trying too hard here.
    for r in intval_decrement:
        if ival in r:
            ival -= 1
            break
    else:
        ival += 1

    return str(ival)


class FrobError(Exception):
    pass

def frob_sysctl(path, val):
    for frob in (frob_special, frob_int, frob_int_vec):
        try:
            new = frob(path, val)
        except AssertionError as e:
            raise FrobError(f"Error frobbing {path}: {e}")

        if new is not None:
            break
    else:
        raise NotImplementedError(f"Don't know how to frob")

    vprint("  -> ", new)
    try:
        path.write_text(new)
    except OSError as e:
        if not ignore_write_error(path, e):
            raise FrobError(f"Error writing {new!r} > {path}: {e}") from e

def ignore_write_error(path, e):
    try:
        return e.errno == IGNORE_WRITE_ERRORS[path_to_name(path)]
    except KeyError:
        return False


def do_netns_play():
    vprint("-"*80)
    print("Frobbing net sysctls in child netns")

    for path, val in iterate_sysctl_values("net"):
        vprint(f"{path}: {val}")

        # If not writable, ignore
        if not (path.stat().st_mode & stat.S_IWUSR):
            continue
        
        try:
            frob_sysctl(path, val)
        except (FrobError, NotImplementedError) as e:
            warn(e)

    vprint("-"*80)

def check_unpriv_userns():
    if os.geteuid() == 0:
        return

    name = "kernel.unprivileged_userns_clone"
    path = SYSCTL_PATH / name.replace(".", "/")
    if not path.exists():
        return

    val = int(path.read_text())
    if val == 0:
        print(f"Sysctl {name} is disallowing unprivileged userns creation.", file=sys.stderr)
        print(f"Either run this as root, or run:")
        print(f"sudo sysctl -w {name}=1")
        raise SystemExit(1)


def preload_globals():
    global g_avail_tcp_cong

    def get_cong(path):
        path = SYSCTL_PATH / path
        return set(path.read_text().strip().split())

    g_avail_tcp_cong = get_cong("net/ipv4/tcp_available_congestion_control")

    allow_tcp_cong = get_cong("net/ipv4/tcp_allowed_congestion_control")
    if allow_tcp_cong == g_avail_tcp_cong:
        warn("All available TCP congestion control algorithms are allowed.\n"
             "    Consider reducing net/ipv4/tcp_allowed_congestion_control\n"
             "    for a better test. E.g.:\n"
             "    sudo sysctl net.ipv4.tcp_allowed_congestion_control=cubic")


def parse_args():
    global g_verbose
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('-U', '--user', action='store_true',
            help="Create new user namespace")
    ap.add_argument('-v', '--verbose', action='store_true',
            help="Verbose output")
    args = ap.parse_args()

    g_verbose = args.verbose
    return args


def main():
    args = parse_args()

    preload_globals()

    s1 = snapshot()

    flags = clone.CLONE_NEWNET
    if args.user:
        check_unpriv_userns()
        flags |= clone.CLONE_NEWUSER

    clone.clone_call(do_netns_play, flags)

    s2 = snapshot()

    added, removed, modified, _ = dict_compare(s1, s2)

    dict_remove(modified, MODIFICATION_IGNORE)
 
    if added or removed or modified:
        print(red("\nParent net namespace modified!"))
        for a in added:
            print(f"+ {a}")
        for r in removed:
            print(f"- {r}")
        for k, (old, new) in modified.items():
            print(f"~ {k}: {old} -> {new}")
        raise SystemExit(1)
    print(green("No changes detected"))

if __name__ == '__main__':
    main()
