#!/usr/bin/env python3
import difflib
import os
import sys
from pathlib import Path
import clone

SYSCTL_PATH = Path('/proc/sys')

def warn(s):
    print(s, file=sys.stderr)

def snapshot():
    result = dict()
    for root, dirs, files in os.walk(SYSCTL_PATH / "net"):
        root = Path(root)
        for fn in files:
            path = root / fn
            try:
                value = path.read_text().strip()
            except PermissionError as e:
                #warn(str(e))
                continue

            k = str(path.relative_to(SYSCTL_PATH))
            result[k] = value

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

def dict_compare_describe(d1, d2):
    added, removed, modified, _ = dict_compare(d1, d2)
    if added:
        print("Added:", added)
    if removed:
        print("Removed:", removed)
    if modified:
        print("Modified:", modified)

def waitstatus_to_exitcode(status):
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALLED(status):
        return -os.WTERMSIG(status)
    raise ValueError(f"Unexpected status {status}")

def do_netns_play():
    def child_func():
        import time
        time.sleep(2)
    flags = clone.CLONE_NEWNET
    pid = clone.clone(child_func, flags)

    _, status = os.waitpid(pid, 0)
    status = waitstatus_to_exitcode(status)
    if status < 0:
        raise OSError(f"Child process terminated by signal {-status}")
    if status > 0:
        raise OSError(f"Child process exited with code {status}")




def main():
    s1 = snapshot()

    do_netns_play()

    s2 = snapshot()

    dict_compare_describe(s1, s2)

if __name__ == '__main__':
    main()
