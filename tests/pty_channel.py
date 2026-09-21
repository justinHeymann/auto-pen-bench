"""A paramiko.Channel stand-in backed by a real shell on a POSIX PTY.

The fakes in ``support`` answer with canned bytes, which is what makes the unit
tests fast and deterministic -- but it also means they cannot show how the
completion protocol interacts with a *real* shell: bash's PS2 ``> ``
continuation prompt while it collects a here-document, the prompt printed after
the command, and the carriage returns the terminal layer inserts when a long
line wraps. A driver bug lived in exactly that interaction (a finished command
was interrupted as if it were waiting for input), so it is pinned here against
a real bash.

The module imports cleanly everywhere; ``AVAILABLE`` reports whether the tests
using it can run.
"""
import contextlib
import os
import select
import shutil
import signal
import subprocess
import sys
import time

try:  # POSIX only
    import fcntl
    import pty
    import struct
    import termios
except ImportError:  # pragma: no cover - Windows
    fcntl = pty = struct = termios = None

AVAILABLE = (
    pty is not None and sys.platform != 'win32'
    and shutil.which('bash') is not None
)

# The window size matters: it is what makes the terminal layer wrap the echoed
# command line, which is where the driver used to lose the completion marker.
COLUMNS = 80
LINES = 24


class PtyChannel:
    """A shell on a PTY, exposing the paramiko.Channel surface RemoteShell uses.

    Args:
        argv (list): The shell to spawn, e.g. ``['bash', '--norc']``.
        columns (int): Window width; the shell wraps its echo at this column.
        lines (int): Window height.

    Attributes:
        process (subprocess.Popen): The shell process.
        closed (bool): Whether the channel has been closed.
    """

    def __init__(self, argv=('bash', '--norc', '--noprofile'),
                 columns=COLUMNS, lines=LINES):
        if not AVAILABLE:
            raise RuntimeError(
                'PtyChannel needs a POSIX PTY and bash; skip with AVAILABLE'
            )
        self.master, slave = pty.openpty()
        self.columns = columns
        fcntl.ioctl(self.master, termios.TIOCSWINSZ,
                    struct.pack('HHHH', lines, columns, 0, 0))
        self.process = subprocess.Popen(
            list(argv), stdin=slave, stdout=slave, stderr=slave,
            preexec_fn=os.setsid, close_fds=True,
            env={**os.environ, 'PS1': 'root@kali:~# ', 'PS2': '> ',
                 'TERM': 'xterm-256color', 'COLUMNS': str(columns)},
        )
        os.close(slave)
        self.closed = False
        self._timeout = None

    def settimeout(self, timeout):
        self._timeout = timeout

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        os.write(self.master, data)

    def recv_ready(self):
        ready, _, _ = select.select([self.master], [], [], 0)
        return bool(ready)

    def recv(self, size):
        ready, _, _ = select.select([self.master], [], [], self._timeout)
        if not ready:
            raise TimeoutError('no data within the channel timeout')
        try:
            return os.read(self.master, size)
        except OSError:
            # The child exited and the PTY is gone; report EOF, which
            # receive_data() maps to an empty read.
            return b''

    def get_transport(self):
        """RemoteShell only checks this for liveness; a local PTY has none."""
        return None

    def close(self):
        self.closed = True
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
        self.process.wait()
        os.close(self.master)

    def wait_for_prompt(self, timeout=5.0):
        """Consume the shell's first prompt so a command starts from silence.

        Reads until the PTY has been quiet for one short poll, rather than
        until the whole budget is gone: the prompt arrives immediately, and
        waiting out the budget would add its full duration to every test.
        """
        self._timeout = 0.2
        deadline = time.monotonic() + timeout
        data = b''
        while time.monotonic() < deadline:
            try:
                data += self.recv(65536)
            except TimeoutError:
                break
        return data.decode(errors='replace')
