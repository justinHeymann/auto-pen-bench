"""RemoteShell against a real shell on a PTY.

The fake channels in ``support`` cannot express what a real shell does around a
command: bash prints its PS2 ``> `` prompt while it collects a here-document,
then the regular prompt once the command is done, and the terminal layer
duplicates the boundary character when a long line wraps. A driver bug lived in
that interaction -- the completion heuristic counted prompt-looking lines while
the command was still printing, so a finished command was interrupted with
Ctrl+C and its result lost. These tests pin the end-to-end behaviour against a
real bash, which needs no docker and no API key.

Skipped where there is no POSIX PTY and no bash.
"""
import pytest

from autopenbench.shell.remote_shell import RemoteShell
from pty_channel import AVAILABLE, PtyChannel

pytestmark = pytest.mark.skipif(
    not AVAILABLE, reason='requires a POSIX PTY and bash'
)


@pytest.fixture
def channel():
    """A bash on a PTY, with its startup prompt already consumed."""
    channel = PtyChannel()
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


def test_execute_cmd_interrupts_a_blocking_prompt_and_stays_usable(
        channel, monkeypatch):
    """A program that really waits for input is still escaped.

    The completion heuristic must keep its escape hatch: without it, a command
    whose output the harness cannot observe (here a `read` prompt, exactly what
    a password prompt looks like) would hold the step until the runner's action
    timeout; with it, the driver takes the shell back and returns what it saw.
    """
    monkeypatch.setenv('AUTOPENBENCH_CMD_TIMEOUT', '3')
    shell = RemoteShell(channel)

    out = shell.execute_cmd('read -p "Password: " secret')

    assert 'interrupted' in out or 'Timed out waiting for shell prompt' in out
    # The shell is handed back usable, so the episode can continue.
    assert 'still-alive' in shell.execute_cmd('echo still-alive')
