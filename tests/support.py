"""Shared helpers for the test suite.

The fakes here stand in for `paramiko.Channel`; the module loaders import the
standalone scripts of `setup/` and `scripts/`, which are not part of the
installed package.
"""
import importlib.util
import re
from pathlib import Path


def repo_root() -> Path:
    """The root of the repository holding this test suite."""
    return Path(__file__).resolve().parent.parent


def load_module(name: str, relative_path: str):
    """Load a standalone script (``setup/``, ``scripts/``) by file path.

    Importing it by module name would shadow onto the top-level ``setup.py``
    module (and the scripts are not a package), so it is loaded explicitly.
    """
    path = repo_root() / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeShell:
    """Minimal paramiko.Channel stand-in with a single canned output."""

    def __init__(self, output=b"ready\n"):
        self.output = output
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def send(self, value):
        self.sent.append(value)

    def recv_ready(self):
        return bool(self.output)

    def recv(self, _size):
        output, self.output = self.output, b""
        return output

    def close(self):
        self.closed = True


class EchoingShell(FakeShell):
    """Fake PTY shell: echoes what is typed, then runs it.

    The other fakes answer with the marker alone, so they cannot show the
    difference between the marker's own output and the shell's echo of the
    line printing it -- the distinction the completion protocol lives on.
    """

    def __init__(self, body="uid=0(root)"):
        super().__init__(b"")
        self.body = body
        self.chunks = []

    def send(self, value):
        super().send(value)
        echo = (
            "\x1b[?2004l\r\n" + value.replace("\n", "\r\n")
            + "\x1b[?2004h\r\n"
        )
        match = re.search(r"__AUTOPENBENCH_DONE_\d+__", value)
        if match:
            # The command's output, then the marker on a line of its own (its
            # own real newlines; the echo above only has literal ones).
            self.chunks.append(
                echo
                + "\x1b]3008;start=x;type=command;cwd=/root\x1b\\"
                + self.body.replace("\n", "\r\n") + "\r\n\r\n"
                + match.group(0) + "\r\n"
            )
        else:
            self.chunks.append(echo)

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, _size):
        return self.chunks.pop(0).encode() if self.chunks else b""


class MarkerShell(FakeShell):
    """Fake shell that echoes the completion marker sent by execute_cmd.

    This models a healthy interactive shell: any data already buffered is
    stale output from a previous command, and the response to the next
    `send()` is the command body followed by the completion marker.
    """

    def __init__(self, body="uid=0(root)", stale=b""):
        super().__init__(stale)
        self.body = body

    def send(self, value):
        super().send(value)
        match = re.search(r"__AUTOPENBENCH_DONE_\d+__", value)
        if match:
            self.output = f"{self.body}\n{match.group(0)}\n".encode()


class PromptShell(FakeShell):
    """Fake shell whose answer to a command is an interactive prompt.

    Models a real `ssh` waiting for a password: `_drain` finds nothing
    buffered, the prompt arrives only once the command has been sent, and
    no completion marker ever follows it.
    """

    def __init__(self, prompt="student@192.168.1.0's password: "):
        super().__init__(b"")
        self.prompt = prompt

    def send(self, value):
        super().send(value)
        self.output = b"^C\nroot@kali:~# " if value == "\x03" \
            else self.prompt.encode()


class ChunkedShell(FakeShell):
    """Fake shell that answers a marker-carrying command in several chunks.

    Models a command that is still producing output: every chunk before the
    completion marker ends in a line that looks like a prompt (bash's `> `
    continuation prompt, then the shell prompt itself). A command that keeps
    writing is not waiting for input, so none of those may interrupt it.
    """

    def __init__(self, lead_chunks=(
            b"cat > /tmp/probe.py <<'PY'\n> print('x')\n",
            b"> PY\nroot@kali:~# ",
            b"root@kali:~# ",
            b"root@kali:~# ",
    ), body=b"probe-output\n", wrap_marker=False):
        super().__init__(b"")
        self.lead_chunks = list(lead_chunks)
        self.body = body
        self.wrap_marker = wrap_marker
        self.pending = []

    def send(self, value):
        super().send(value)
        if value == "\x03":
            self.pending = []
            self.output = b"^C\nroot@kali:~# "
            return
        match = re.search(r"__AUTOPENBENCH_DONE_\d+__", value)
        self.pending = list(self.lead_chunks)
        if match:
            marker = match.group(0)
            if self.wrap_marker:
                # What the PTY emits when that line wraps: the boundary
                # character echoed a second time after the cursor reset.
                middle = len(marker) // 2
                marker = (marker[:middle] + "\r"
                          + marker[middle - 1] + marker[middle:])
            self.pending.append(
                b"\n" + self.body + b"\n" + marker.encode()
                + b"\nroot@kali:~# \n"
            )
        self.output = b""

    def recv_ready(self):
        return bool(self.pending) or bool(self.output)

    def recv(self, _size):
        if self.pending:
            return self.pending.pop(0)
        return super().recv(_size)


class MsfConsoleShell(FakeShell):
    """Fake channel sitting inside an interactive msfconsole.

    msfconsole runs a console line through the system shell, so what follows a
    command is its own `msf ... >` prompt rather than the Kali shell prompt,
    and the completion marker is msfconsole's business like any other line.

    A program that flushes the PTY input queue while it runs discards the
    marker typed ahead of it -- nmap does that for every scan wider than a
    single host -- so the console prompt comes back with the command's full
    output and no marker. A marker sent on its own at that prompt survives,
    because msfconsole executes it through the shell like the first one.
    """

    prompt = 'msf auxiliary(gather/x) > '

    def __init__(self, body='Nmap done: 256 IP addresses (1 host up) scanned'):
        super().__init__(b'')
        self.body = body
        self.pending = []
        self.flushed = False

    def send(self, value):
        super().send(value)
        if value == "\x03":
            self.pending = []
            self.output = f'^C\n{self.prompt}'.encode()
            return
        match = re.search(r'__AUTOPENBENCH_DONE_\d+__', value)
        if not match:
            return
        if not self.flushed:
            # The command flushed the marker out of the input queue while it
            # ran: its output and the console prompt, no marker.
            self.flushed = True
            self.pending = [f'{self.body}\n{self.prompt}'.encode()]
        else:
            # Sent on its own at the console prompt: msfconsole runs it
            # through the shell, which answers with the marker.
            self.pending = [
                b'[*] exec: \n',
                f'\n{match.group(0)}\n{self.prompt}'.encode(),
            ]

    def recv_ready(self):
        return bool(self.pending) or bool(self.output)

    def recv(self, _size):
        if self.pending:
            return self.pending.pop(0)
        return super().recv(_size)


class RunawayShell(FakeShell):
    """Fake shell whose first marker-carrying command never finishes.

    Models the shipped incident: a loop scanning 254 subnets kept echoing
    progress lines, so every later observation returned the loop's output
    instead of the command that was actually sent. Ctrl+C stops it.
    """

    runaway_cmd = "for i in {1..254}"
    BUFFERED_LINES = 3

    def __init__(self):
        super().__init__(b"")
        self.running = False
        self.pending = 0

    def send(self, value):
        super().send(value)
        if value == "\x03":
            self.running = False
            self.pending = 0
            self.output = b"^C\nroot@kali:~# "
        elif self.runaway_cmd in value:
            self.running = True
            self.pending = self.BUFFERED_LINES
            self.output = b"Scanning 192.168.31.0/24\n"
        else:
            match = re.search(r"__AUTOPENBENCH_DONE_\d+__", value)
            if match and not self.running:
                self.output = f"uid=0(root)\n{match.group(0)}\n".encode()

    def recv_ready(self):
        return bool(self.output) or self.pending > 0

    def recv(self, _size):
        if self.pending > 0:
            self.pending -= 1
            return b"Scanning 192.168.32.0/24\n"
        return super().recv(_size)
