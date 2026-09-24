"""RemoteShell against a real shell on a PTY.

The fake channels in ``support`` cannot express what a real shell does around a
command: bash prints its PS2 ``> `` prompt while it collects a here-document,
then the regular prompt once the command is done, and the terminal layer
duplicates the boundary character when a long line wraps. A driver bug lived in
that interaction -- the completion heuristic counted prompt-looking lines while
the command was still printing, so a finished command was interrupted with
Ctrl+C and its result lost. Two more ways for a finished command to look stuck
are pinned here as well: a program that flushes the PTY input queue while it
runs, which discards the completion marker typed ahead of it, and a fixed
observation for both give-up paths. These tests need no docker and no API key.

Skipped where there is no POSIX PTY and no bash.
"""
import shutil

import pytest

from autopenbench.shell.remote_shell import RemoteShell
from pty_channel import AVAILABLE, PtyChannel

pytestmark = pytest.mark.skipif(
    not AVAILABLE, reason='requires a POSIX PTY and bash'
)

# A command that discards whatever is queued on the PTY's input side while it
# runs. nmap does exactly this for every scan wider than a single host, which
# is why a completed scan was reported as a step the harness had lost.
NEEDS_PYTHON = pytest.mark.skipif(
    shutil.which('python3') is None, reason='requires python3 on PATH'
)
FLUSH_LOOP = (
    'python3 -c "import termios, sys, time\n'
    'for _ in range(2):\n'
    '    termios.tcflush(sys.stdin, termios.TCIFLUSH)\n'
    '    time.sleep(0.3)"'
)


@pytest.fixture
def channel():
    """A bash on a PTY, with its startup prompt already consumed."""
    try:
        channel = PtyChannel()
    except OSError as error:
        # A constrained environment (a container or sandbox that has run out
        # of PTY devices) can raise here even though the import-time AVAILABLE
        # probe succeeded. Skip rather than erroring: the test cannot run, but
        # nothing is wrong with the code under test.
        pytest.skip(f'cannot allocate a PTY: {error}')
    try:
        channel.wait_for_prompt()
        # Keep the polls short so a failing expectation fails fast instead of
        # waiting for the command timeout.
        channel.settimeout(0.2)
        yield channel
    finally:
        channel.close()


@pytest.fixture
def shell(channel, monkeypatch):
    """A RemoteShell over ``channel`` with a small command budget."""
    monkeypatch.setenv('AUTOPENBENCH_CMD_TIMEOUT', '10')
    return RemoteShell(channel)


def test_execute_cmd_runs_a_simple_command(shell):
    out = shell.execute_cmd('echo simple-output')

    assert 'simple-output' in out


def test_execute_cmd_runs_a_here_document(shell):
    """bash collects the body behind its PS2 prompt before running anything."""
    out = shell.execute_cmd("cat <<'EOF'\nheredoc-body\nEOF")

    assert 'heredoc-body' in out
    assert 'interrupted' not in out


def test_execute_cmd_runs_a_command_after_a_here_document(shell, tmp_path):
    """The regression: the second command was interrupted mid-line.

    Sending a here-document and a follow-up command in one write makes three
    prompt-looking lines appear (PS2, the prompt, the prompt again) before the
    completion marker. They were counted as evidence of an interactive prompt,
    so the follow-up command was Ctrl+C'd as it was being typed -- bash reported
    the mangled name (``ython3: command not found``) and the result was lost.
    """
    target = tmp_path / 'probe.txt'
    out = shell.execute_cmd(
        f"cat > {target} <<'EOF'\nfile-body\nEOF\ncat {target}"
    )

    assert 'file-body' in out
    assert 'interrupted' not in out
    assert target.read_text() == 'file-body\n'


def test_execute_cmd_keeps_the_output_of_a_command_whose_echo_wraps(shell):
    """A long command line wraps in the echo; the result must still arrive."""
    marker = 'wrapped-echo-marker'
    out = shell.execute_cmd('echo ' + 'x' * 120 + ' ' + marker)

    assert marker in out
    assert 'interrupted' not in out


@NEEDS_PYTHON
def test_execute_cmd_recovers_a_completion_marker_the_command_flushed(
        shell, monkeypatch):
    """A command that flushes the PTY input queue must still be seen as done.

    The completion marker is typed ahead with the command, so a program that
    discards the input queue while it runs (nmap, for any scan wider than one
    host) throws it away: the command then finishes and prints its prompt
    without a marker, which looks exactly like a program waiting for input.
    The driver used to answer that with Ctrl+C and report a lost step although
    the command's whole output was already collected -- and, with a judge in
    the loop, threw away the milestones that output had earned.

    The shell is at its own prompt by then, so the marker is re-sent: the step
    is reported as the completion it is, and the agent keeps its full budget.
    """
    monkeypatch.setenv('AUTOPENBENCH_CMD_TIMEOUT', '6')

    out = shell.execute_cmd(f'echo flushed-body; {FLUSH_LOOP}')

    assert 'flushed-body' in out
    assert 'interrupted' not in out
    assert 'Timed out' not in out
    # The shell is handed back usable, so the episode can continue.
    assert 'still-alive' in shell.execute_cmd('echo still-alive')


def test_execute_cmd_reports_a_prompt_whose_command_already_returned(
        shell, monkeypatch):
    """A prompt is not proof that something is still waiting for input.

    `read -p ...` consumes the completion marker typed ahead of it as its
    input and returns, so the shell is back at its own prompt and nothing is
    waiting. The step used to be Ctrl+C'd and reported as lost, which spent a
    step of the agent's budget on a command whose output was complete.
    """
    monkeypatch.setenv('AUTOPENBENCH_CMD_TIMEOUT', '6')

    out = shell.execute_cmd('read -p "Password: " secret')

    assert 'Password:' in out
    assert 'interrupted' not in out
    assert 'Timed out' not in out


def test_execute_cmd_interrupts_a_blocking_prompt_and_stays_usable(
        channel, monkeypatch):
    """A program that really waits for input is still escaped.

    The completion heuristic must keep its escape hatch: without it, a command
    whose output the harness cannot observe (here a `read` prompt that keeps
    asking, exactly what a password prompt looks like) would hold the step
    until the runner's action timeout; with it, the driver takes the shell back
    and returns what it saw. The loop matters: a single `read` is answered by
    the marker typed ahead of it and returns, but this one is still waiting
    after that, so re-sending the marker cannot resolve it either.
    """
    monkeypatch.setenv('AUTOPENBENCH_CMD_TIMEOUT', '3')
    shell = RemoteShell(channel)

    out = shell.execute_cmd(
        'while read -p "Password: " secret; do echo tried; done'
    )

    assert 'interrupted' in out or 'Timed out waiting for shell prompt' in out
    # The shell is handed back usable, so the episode can continue.
    assert 'still-alive' in shell.execute_cmd('echo still-alive')
