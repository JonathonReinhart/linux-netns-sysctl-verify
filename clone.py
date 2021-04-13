import ctypes
import os
import signal
import sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# <linux/sched.h>
#CLONE_VM               = 0x00000100    # set if VM shared between processes
CLONE_FS                = 0x00000200    # set if fs info shared between processes
CLONE_FILES             = 0x00000400    # set if open files shared between processes
#CLONE_SIGHAND          = 0x00000800    # set if signal handlers and blocked signals shared
#CLONE_PIDFD            = 0x00001000    # set if a pidfd should be placed in parent
CLONE_PTRACE            = 0x00002000    # set if we want to let tracing continue on the child too
CLONE_VFORK             = 0x00004000    # set if the parent wants the child to wake it up on mm_release
CLONE_PARENT            = 0x00008000    # set if we want to have the same parent as the cloner
#CLONE_THREAD           = 0x00010000    # Same thread group?
CLONE_NEWNS             = 0x00020000    # New mount namespace group
CLONE_SYSVSEM           = 0x00040000    # share system V SEM_UNDO semantics
#CLONE_SETTLS           = 0x00080000    # create a new TLS for the child
#CLONE_PARENT_SETTID    = 0x00100000    # set the TID in the parent
#CLONE_CHILD_CLEARTID   = 0x00200000    # clear the TID in the child
#CLONE_DETACHED         = 0x00400000    # Unused, ignored
CLONE_UNTRACED          = 0x00800000    # set if the tracing process can't force CLONE_PTRACE on this clone
#CLONE_CHILD_SETTID     = 0x01000000    # set the TID in the child
CLONE_NEWCGROUP         = 0x02000000    # New cgroup namespace
CLONE_NEWUTS            = 0x04000000    # New utsname namespace
CLONE_NEWIPC            = 0x08000000    # New ipc namespace
CLONE_NEWUSER           = 0x10000000    # New user namespace
CLONE_NEWPID            = 0x20000000    # New pid namespace
CLONE_NEWNET            = 0x40000000    # New network namespace
CLONE_IO                = 0x80000000    # Clone io context

DEFAULT_STACK_SIZE = 2 * 1024 * 1024

def clone(fn, flags=0, stacksize=DEFAULT_STACK_SIZE):
    """
    clone() creates a new process, in a manner similar to fork(2).

    Arguments:
    fn:         Function to run in child process
    flags:      CLONE_* flags
    stacksize:  Size of child stack (default is DEFAULT_STACK_SIZE)

    Returns: child pid.

    Raise OSError on error.
    """

    # Verify only supported flags are given
    supported_flags = ( 0
            # CLONE_VM would probably wreck Python
            | CLONE_FS
            | CLONE_FILES
            # CLONE_SIGHAND requires CLONE_VM
            # CLONE_PIDFD (unsure)
            | CLONE_PTRACE
            | CLONE_VFORK
            | CLONE_PARENT
            # CLONE_THREAD would probably wreck Python
            | CLONE_NEWNS
            | CLONE_SYSVSEM
            # CLONE_SETTLS is for threading
            # CLONE_PARENT_SETTID
            # CLONE_CHILD_CLEARTID
            # CLONE_DETACHED
            | CLONE_UNTRACED
            # CLONE_CHILD_SETTID
            | CLONE_NEWCGROUP
            | CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWUSER
            | CLONE_NEWPID
            | CLONE_NEWNET
            | CLONE_IO
            )
    unsupported_flags = flags & ~supported_flags
    if unsupported_flags:
        raise ValueError(f"Unsupported flags: 0x{unsupported_flags:X}")

    # Allow the user to specify signal to be sent at exit
    # but default to SIGCHLD if not set
    if (flags & 0xFF) == 0:
        flags |= signal.SIGCHLD


    # Allocate child stack
    child_stack = ctypes.create_string_buffer(2 * 1024 * 1024)
    child_stack_top = ctypes.c_void_p(
        ctypes.cast(child_stack, ctypes.c_void_p).value + len(child_stack)
    )

    # TODO
    arg = ctypes.c_void_p(0)

    def child_func_wrap():
        try:
            rc = fn()
        except:
            # Try to show a traceback
            # TODO: A more elaborate solution would marshal the exception
            #       object back to the parent via pipe.
            try:
                import traceback
                print("Child function raised exception:", file=sys.stderr)
                traceback.print_exc()
            finally:
                return 255
        if rc is None:
            return 0

    child_pid = libc.clone(
            ctypes.CFUNCTYPE(ctypes.c_int)(child_func_wrap),
            child_stack_top,
            flags,
            arg,
            )

    if child_pid < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, "error calling clone(): %s" % os.strerror(errno))

    assert child_pid != 0, "clone() should not return in the child process"
    return child_pid
