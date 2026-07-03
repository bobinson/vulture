import os
import signal


def kill_proc(pid):
    # Safe: no shell at all — kill the process via the os syscall wrapper.
    os.kill(int(pid), signal.SIGKILL)
