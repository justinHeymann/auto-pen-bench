"""RemoteShell: the completion protocol, prompts and receive helpers."""
import itertools
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from autopenbench.shell import remote_shell as remote_shell_mod
from autopenbench.shell.remote_shell import (
    RemoteShell,
    normalize_newlines,
    receive_data,
)
from autopenbench.tools import wait_for_message
from support import (
    ChunkedShell,
    EchoingShell,
    FakeShell,
    MarkerShell,
    PromptShell,
    RunawayShell,
)

# --- Forbidden network tools ------------------------------------------------


def test_remote_shell_blocks_forbidden_network_tools():
    shell = FakeShell()
    remote_shell = RemoteShell(shell)

    assert remote_shell.execute_cmd("nc -lvnp 4444") == "Don't use netcat or socat!"
    assert shell.sent == []


@pytest.mark.parametrize(
    "cmd",
    [
        "nc -lvnp 4444",
        "/usr/bin/nc -l",
        "ncat -l 4444",
        ";nc -l 4444",
        "nc.openbsd -l",
        "socat TCP-LISTEN:4444,fork",
        # Behind a command wrapper, which used to smuggle them past the check
        "sudo nc -lvnp 4444",
        "timeout 5 nc -l 1",
        "nohup nc -l 1",
        "xargs nc",
        "busybox nc -l 1",
        "sudo -u root socat TCP-LISTEN:4444,fork",
        'bash -c "nc -l 1"',
    ],
)
def test_uses_forbidden_net_tool_blocks_variants(cmd):
    assert remote_shell_mod.uses_forbidden_net_tool(cmd) is True


@pytest.mark.parametrize(
    "cmd",
    [
        "echo nc",
        "ls /usr/bin | grep socat",
        "which ncat",
        "nmap -sV 192.168.1.0",
        "sudo nmap -sV 192.168.1.0",
    ],
)
def test_uses_forbidden_net_tool_allows_plain_mentions(cmd):
    assert remote_shell_mod.uses_forbidden_net_tool(cmd) is False


# --- Completion-marker protocol ---------------------------------------------


def test_execute_cmd_uses_marker_and_strips_it_from_output():
    shell = MarkerShell(body="uid=0(root)")

    out = RemoteShell(shell).execute_cmd("id")

    assert "uid=0(root)" in out
    assert "AUTOPENBENCH_DONE" not in out
    assert "printf" in shell.sent[0]


def test_execute_cmd_observation_is_free_of_harness_plumbing():
    """The shell echoes the `printf` line that prints the completion marker.

    Matching the bare marker would stop at that echo -- before the command's
    output had been read -- and hand the agent the harness's own plumbing
    instead of the result.
    """
    shell = EchoingShell(body="uid=0(root)")

    out = RemoteShell(shell).execute_cmd("id")

    assert "uid=0(root)" in out
    assert "AUTOPENBENCH_DONE" not in out  # nor the marker
    assert "printf" not in out             # nor the echoed marker command
    assert "\x1b" not in out               # nor terminal escapes


def test_execute_cmd_drains_stale_output_before_running_command():
    shell = MarkerShell(body="fresh output", stale=b"stale-leftover\n")

    out = RemoteShell(shell).execute_cmd("whoami")

    assert "fresh output" in out
    assert "stale-leftover" not in out


def test_execute_cmd_does_not_interrupt_a_command_that_is_still_printing():
    """A command that keeps producing output is not waiting for input.

    The shipped incident: a multi-line send echoes bash's `> ` continuation
    prompt and then the shell prompt, so three prompt-looking lines appeared
    before the completion marker. They were counted as evidence of an
    interactive prompt and the already-finished command was interrupted -- the
    full result was in the observation, followed by a Ctrl+C.
    """
    shell = ChunkedShell()

    out = RemoteShell(shell).execute_cmd("cat > /tmp/probe.py <<'PY'\nPY")

    assert "probe-output" in out
    assert "interrupted" not in out
    assert "\x03" not in shell.sent


def test_execute_cmd_recognises_a_marker_split_by_a_line_wrap():
    """The completion marker must survive a PTY line wrap.

    Where the echo wraps, the boundary character is emitted twice around a
    cursor-reset CR. The literal marker then never appears in the raw capture,
    which used to make a finished command look like an interactive prompt.
    """
    shell = ChunkedShell(wrap_marker=True)

    out = RemoteShell(shell).execute_cmd("id")

    assert "probe-output" in out
    assert "interrupted" not in out
    assert "AUTOPENBENCH_DONE" not in out


def test_execute_cmd_times_out_when_marker_never_arrives(monkeypatch):
    shell = FakeShell(output=b"")
    ticks = itertools.count(0, 20)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    out = RemoteShell(shell).execute_cmd("sleepy-command")

    assert "Timed out waiting for shell prompt" in out


def test_execute_cmd_interrupts_a_command_that_outlives_its_deadline(monkeypatch):
    """A long-running command must not outlive its step.

    The shipped incident: an agent launched a 254-subnet scan loop, the
    harness gave up waiting for the marker and returned, and the loop kept
    writing to the channel -- every later observation showed its output
    instead of the command that was actually sent, blinding the agent for the
    rest of the run.
    """
    shell = RunawayShell()
    ticks = itertools.count(0, 20)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )
    monkeypatch.setattr(remote_shell_mod.time, "sleep", lambda _seconds: None)
    remote = RemoteShell(shell)

    out = remote.execute_cmd(
        "for i in {1..254}; do nmap -sn 192.168.$i.0/24; done"
    )

    assert "\x03" in shell.sent
    assert "Scanning" in out                      # collected output is kept
    assert "without printing its completion marker" in out
    assert "Timed out waiting for shell prompt" in out

    # The session is usable again: the next command gets its own result
    # instead of the loop's leftovers.
    follow_up = remote.execute_cmd("id")

    assert "uid=0(root)" in follow_up
    assert "Scanning" not in follow_up


def test_command_timeout_seconds_is_configurable(monkeypatch):
    """The per-command budget is tunable, and the default stays below the
    runner's action timeout (genai's ACTION_TIMEOUT_SECONDS, 30 s) so the
    harness interrupts the command before the runner aborts mid-read."""
    assert remote_shell_mod.command_timeout_seconds() == (
        remote_shell_mod.DEFAULT_COMMAND_TIMEOUT_SECONDS
    )
    assert remote_shell_mod.DEFAULT_COMMAND_TIMEOUT_SECONDS < 30

    monkeypatch.setenv("AUTOPENBENCH_CMD_TIMEOUT", "5.5")
    assert remote_shell_mod.command_timeout_seconds() == 5.5


# --- Commands that prompt for a password ------------------------------------


def test_execute_cmd_sudo_uses_password_heuristic_without_marker(monkeypatch):
    # Answers the sent command with the sudo password prompt (a FakeShell's
    # canned output would be discarded by the pre-command drain instead).
    shell = PromptShell(prompt="[sudo] password for student:")
    # Jump past the password-prompt deadline without sleeping.
    ticks = itertools.count(0, 10)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    out = RemoteShell(shell).execute_cmd("sudo id")

    # No completion marker is sent for sudo/su (it could be consumed as the
    # password), and the password prompt is surfaced to the agent.
    assert "AUTOPENBENCH_DONE" not in "".join(shell.sent)
    assert "password" in out.lower()
    # The prompt stays alive: the agent answers it with its next command.
    assert "\x03" not in shell.sent


def test_execute_cmd_sudo_ignores_password_in_the_command_echo(monkeypatch):
    """A sudo command that merely mentions a password (`sudo grep password
    /etc/shadow`) must not end the wait at its own echo: only the real
    prompt, on the last output line, counts."""
    shell = FakeShell(output=b"sudo grep password /etc/shadow\n")
    # Jump past the password-prompt deadline without sleeping.
    ticks = itertools.count(0, 10)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    out = RemoteShell(shell).execute_cmd("sudo grep password /etc/shadow")

    # The wait did not stop at the echo: the deadline hit, and the harness
    # interrupted the (fake) command instead of reporting a phantom prompt.
    assert "Timed out waiting for sudo password prompt" not in out
    assert "\x03" in shell.sent
    assert "interrupted (Ctrl+C)" in out


@pytest.mark.parametrize("cmd", ["su -", "su - root", "su root", "su"])
def test_execute_cmd_sends_no_marker_for_su_variants(cmd, monkeypatch):
    """Every `su` form must be sent without a completion marker.

    The marker is typed into the password prompt and consumed as the password,
    so `su -`/`su - root` (which a `cmd[:2] == 'su '` check misses) would hang
    the shell and desync every later observation.
    """
    shell = FakeShell(output=b"Password: ")
    ticks = itertools.count(0, 10)
    monkeypatch.setattr(remote_shell_mod.time, "monotonic", lambda: next(ticks))

    RemoteShell(shell).execute_cmd(cmd)

    assert "AUTOPENBENCH_DONE" not in "".join(shell.sent)
    # The prompt stays alive: the agent answers it with its next command.
    assert "\x03" not in shell.sent


def test_execute_cmd_leaves_a_su_password_prompt_waiting_for_input(monkeypatch):
    """`su` is sent without a marker, so the agent answers it with the
    password instead of the prompt being interrupted."""
    shell = PromptShell(prompt="Password: ")
    ticks = itertools.count(0, 0.1)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    out = RemoteShell(shell).execute_cmd("su")

    assert "\x03" not in shell.sent
    assert "still waiting for input" in out
    assert "Password:" in out


def test_execute_cmd_interrupts_a_prompt_a_marker_command_cannot_answer(monkeypatch):
    """A marker-carrying command waiting at a prompt must not outlive its step.

    An `ssh` left reading the channel already ate the completion marker, eats
    the *next* command too, and desynchronizes every later observation.
    """
    shell = PromptShell()
    ticks = itertools.count(0, 0.1)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    out = RemoteShell(shell).execute_cmd("ssh student@192.168.1.0")

    assert "\x03" in shell.sent
    assert "interrupted (Ctrl+C)" in out


def test_execute_cmd_reports_when_interrupt_cannot_be_sent():
    class BrokenShell(FakeShell):
        def send(self, value):
            super().send(value)
            if value == "\x03":
                raise OSError("Socket is closed")

    shell = BrokenShell(output=b"student@192.168.1.0's password: ")

    out = RemoteShell(shell)._interrupt_foreground_process()

    assert "no longer usable" in out


# --- Session state ----------------------------------------------------------


def test_remote_shell_tracks_metasploit_session_state():
    remote_shell = RemoteShell(FakeShell())

    assert remote_shell.check_metasploit_shell(
        "Command shell session 1 opened"
    ) is True
    remote_shell.msfshell = True
    assert remote_shell.check_metasploit_shell(
        "Command shell session 1 closed"
    ) is False


def test_remote_shell_is_alive_tracks_channel_state():
    shell = FakeShell()
    remote_shell = RemoteShell(shell)

    assert remote_shell.is_alive() is True

    shell.closed = True
    assert remote_shell.is_alive() is False


def test_remote_shell_is_alive_reports_dead_transport():
    class DeadTransportShell(FakeShell):
        def get_transport(self):
            return SimpleNamespace(is_active=lambda: False)

    assert RemoteShell(DeadTransportShell()).is_alive() is False


def test_remote_shell_close_releases_the_channel_and_its_transport():
    shell = FakeShell()
    transport = Mock()
    shell.get_transport = lambda: transport

    RemoteShell(shell).close()

    assert shell.closed is True
    transport.close.assert_called_once()


# --- Output cleaning and the receive helpers --------------------------------


def test_normalize_newlines_repairs_the_duplicated_wrap_character():
    """A wrap echoes the boundary character twice around a cursor-reset CR.

    ``/tmp/\r/pass.txt`` is the shell's echo of ``/tmp/pass.txt``, not a
    doubled slash; leaving it in hands the agent a command line it never sent
    (and can break the completion marker that straddles the wrap).
    """
    assert normalize_newlines("ls /tmp/\r/pass.txt") == "ls /tmp/pass.txt"
    assert normalize_newlines("h\rhexdump -C") == "hexdump -C"
    assert normalize_newlines("xxd -p\rp") == "xxd -p"
    assert normalize_newlines("grep -\r-oP x") == "grep -oP x"
    # Real CRLF line endings and blank lines stay intact.
    assert normalize_newlines("a\r\nb\r\nc") == "a\nb\nc"
    assert normalize_newlines("a\n\r\nb") == "a\n\nb"


def test_clean_output_strips_escapes_and_normalises_line_endings():
    raw = "a\r\n\x1b]3008;start=x;cwd=/root\x1b\\b\x1b[?2004hc\r\n"

    assert remote_shell_mod.clean_output(raw) == "a\nbc\n"


def test_wait_for_message_detects_shell_prompt():
    shell = FakeShell(output=b"Welcome\nroot@kali:~# ")

    out = wait_for_message(shell)

    assert "root@kali" in out


def test_wait_for_message_times_out_without_prompt(monkeypatch):
    shell = FakeShell(output=b"no prompt here")
    ticks = itertools.count(0, 20)
    monkeypatch.setattr(
        "autopenbench.tools.ssh_connect.time.monotonic", lambda: next(ticks)
    )

    out = wait_for_message(shell)

    assert "Timed out waiting for a shell prompt" in out


def test_receive_data_returns_empty_on_eof():
    shell = FakeShell(output=b"")

    assert receive_data(shell) == ""


def test_receive_data_decodes_non_utf8_with_fallback():
    shell = FakeShell(output=b"\xff\xfeA\x00")

    out = receive_data(shell)

    assert isinstance(out, str)
    assert len(out) > 0


def test_receive_data_keeps_every_byte_of_a_binary_payload(monkeypatch):
    """Never drop a byte: a binary payload must stay readable and reversible.

    Decoding with ``errors="replace"`` collapses every byte the codec cannot
    map into U+FFFD, so a compiled binary, a ciphertext or a memory dump
    arrives mutilated and the agent cannot tell which bytes were real.
    """
    monkeypatch.setattr(
        remote_shell_mod.chardet, "detect", lambda _data: {"encoding": None}
    )
    payload = bytes(range(256))
    shell = FakeShell(output=payload)

    out = receive_data(shell)

    assert "\ufffd" not in out
    assert len(out) == len(payload)
    assert out.encode("latin-1") == payload


def test_receive_data_rejects_a_multibyte_encoding_guess(monkeypatch):
    """A multi-byte guess merges bytes, so it is not byte-preserving.

    chardet reports ``utf-16-be`` at 0.95 confidence for an ordinary binary
    chunk; decoding with it turns two bytes into one character. The bytes it
    swallows would not even be the same ones from run to run, since the guess
    is made per chunk and chunks end wherever the read happened to stop.
    """
    monkeypatch.setattr(
        remote_shell_mod.chardet,
        "detect",
        lambda _data: {"encoding": "utf-16-be"},
    )
    payload = bytes(range(32)) * 2
    shell = FakeShell(output=payload)

    out = receive_data(shell)

    assert len(out) == len(payload)
    assert out.encode("latin-1") == payload


def test_receive_data_honours_a_single_byte_encoding_guess(monkeypatch):
    """Legacy text stays text: a single-byte guess is byte-preserving.

    One byte maps to one character, so a real non-UTF-8 encoding may be used
    and the payload still survives intact -- here as Cyrillic rather than as
    latin-1 mojibake.
    """
    monkeypatch.setattr(
        remote_shell_mod.chardet, "detect", lambda _data: {"encoding": "cp1251"}
    )
    payload = "Привет".encode("cp1251")
    shell = FakeShell(output=payload)

    out = receive_data(shell)

    assert out == "Привет"
    assert len(out) == len(payload)


def test_receive_data_falls_back_when_chardet_cannot_decide(monkeypatch):
    """chardet reports None for binary chunks, which is not a codec name."""
    monkeypatch.setattr(
        remote_shell_mod.chardet, "detect", lambda _data: {"encoding": None}
    )
    shell = FakeShell(output=b"\xff\xfeA\x00")

    out = receive_data(shell)

    assert isinstance(out, str)
    assert "A" in out


def test_receive_data_times_out(monkeypatch):
    shell = FakeShell(output=b"")
    shell.recv = Mock(side_effect=socket.timeout)
    ticks = itertools.count(0, 5)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    assert receive_data(shell) == ""
