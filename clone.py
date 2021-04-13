import ctypes
import os
import signal
from typing import Callable

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# <linux/prctl.h>
PR_SET_NAME = 15
PR_SET_SECCOMP = 22
PR_CAPBSET_DROP = 24
PR_SET_SECUREBITS = 28
PR_SET_NO_NEW_PRIVS = 38

_CHILD_STACK = ctypes.create_string_buffer(2 * 1024 * 1024)
"""
The memory area our child process will use for its stack.

Yup, this is low-level.

It would be lovely if libc's clone() behaved like fork() instead of forcing
a stack and a function to jump to. (It looks like libc's clone() is great for
spawning threads and annoying for everything else.) It's tempting to use the
raw syscall instead ... but Linux's clone() syscall has a history of changing
signature ... so let's stick with libc.
"""
_RUN_CHILD_STACK_POINTER = ctypes.c_void_p(
    ctypes.cast(_CHILD_STACK, ctypes.c_void_p).value + len(_CHILD_STACK)
)

CLONE_PARENT = 0x00008000

def libc_clone(run_child: Callable[[], None]) -> int:
    """
    Spawn a subprocess that calls run_child().

    Raise OSError on error.

    The caller gets no control over the clone() flags. They are:

        * CLONE_PARENT -- parent, not pyspawner, owns the subprocess.
        * signal.SIGCHLD -- send parent SIGCHLD on exit (the standard signal)
    """
    c_run_child = ctypes.PYFUNCTYPE(ctypes.c_int)(run_child)
    child_pid = _call_c_style(
        libc,
        "clone",
        c_run_child,
        _RUN_CHILD_STACK_POINTER,
        CLONE_PARENT | signal.SIGCHLD,
        0,
    )
    if child_pid < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, "error calling clone(): %s" % os.strerror(errno))
    assert child_pid != 0, "clone() should not return in the child process"
    return child_pid
