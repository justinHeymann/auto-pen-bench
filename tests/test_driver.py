"""PentestDriver: tool routing, session handling and flag submission."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from autopenbench.driver import pentest_driver
from autopenbench.driver.pentest_driver import PentestDriver
from autopenbench.shell.remote_shell import RemoteShell
from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect, WriteFile
from support import FakeShell, MarkerShell


class _ActionTimeout(TimeoutError):
    """Stands in for the harness's ActionTimeoutError (a TimeoutError)."""

# --- Routing ----------------------------------------------------------------


def test_driver_reports_unknown_tool():
    class MysteryTool:
        pass

    out, done = PentestDriver("task", "flag", "target").step(MysteryTool())

    assert out == "Unknown tool: MysteryTool"
    assert done is False


def test_driver_requires_ssh_before_remote_commands():
    driver = PentestDriver("task", "flag", "target")

    output, done = driver.step(
        ExecuteBash(machine_ipaddr="192.168.1.10", cmd="id")
    )

    assert "need to" in output
    assert done is False


def test_driver_routes_commands_to_registered_remote():
    driver = PentestDriver("task", "flag", "target")
    shell = Mock()
    shell.execute_cmd.return_value = "uid=0(root)"
    driver.remotes["192.168.1.10"] = shell

    output, done = driver.step(
        ExecuteBash(machine_ipaddr="192.168.1.10", cmd="id")
    )

    shell.execute_cmd.assert_called_once_with("id")
    assert output == "uid=0(root)"
    assert done is False


def test_driver_routes_write_file(monkeypatch):
    monkeypatch.setattr(WriteFile, "run", lambda self: "saved")

    out, done = PentestDriver("task", "flag", "target").step(
        WriteFile(content="x", file_name="x.sh")
    )

    assert out == "saved"
    assert done is False


# --- Failures reach the agent as observations --------------------------------


def test_driver_reports_a_raising_tool_as_an_observation(monkeypatch):
    """A raising tool must not abort the run.

    The MCP server wraps driver.step() for its own callers, but
    benchmark/tests/machine_test.py and the example notebooks call it bare --
    a dropped SSH session there used to end the whole test run with a
    traceback instead of letting the agent re-connect.
    """
    driver = PentestDriver("task", "flag", "target")

    def _boom(_self, _ssh_kali):
        raise RuntimeError("kex failed")

    monkeypatch.setattr(SSHConnect, "run", _boom)

    out, done = driver.step(SSHConnect(
        ssh_ipaddr="192.168.1.10", ssh_port=22,
        ssh_username="student", ssh_password="password",
    ))

    assert done is False
    assert "Error while running SSHConnect" in out
    assert "kex failed" in out


def test_driver_reports_a_failed_kali_reconnect(monkeypatch):
    """Rebuilding the controller shell can fail too, and that must be an
    observation as well."""
    driver = PentestDriver("task", "flag", "target")
    monkeypatch.setattr(
        driver, "_connect_to_kali",
        Mock(side_effect=OSError("connection refused")),
    )

    out, done = driver.step(
        ExecuteBash(machine_ipaddr="192.168.0.5", cmd="id")
    )

    assert done is False
    assert "connection refused" in out


# --- Sessions ---------------------------------------------------------------


def test_driver_only_registers_successful_ssh_connections(monkeypatch):
    driver = PentestDriver("task", "flag", "target")
    ssh_tool = SSHConnect(
        ssh_ipaddr="192.168.1.10",
        ssh_port=22,
        ssh_username="student",
        ssh_password="password",
    )
    monkeypatch.setattr(
        SSHConnect, "run", lambda _self, _ssh_kali: (None, "connection refused")
    )

    output, _ = driver.step(ssh_tool)

    assert output == "connection refused"
    assert "192.168.1.10" not in driver.remotes


def test_driver_closes_the_session_it_replaces(monkeypatch):
    driver = PentestDriver("task", "flag", "target")
    previous = Mock()
    previous.is_alive.return_value = True
    driver.remotes["192.168.1.10"] = previous
    monkeypatch.setattr(
        SSHConnect, "run", lambda _self, _ssh_kali: (FakeShell(), "connected")
    )

    driver.step(SSHConnect(
        ssh_ipaddr="192.168.1.10", ssh_port=22,
        ssh_username="student", ssh_password="password",
    ))

    previous.close.assert_called_once()


def test_driver_reopens_kali_shell_when_the_channel_died(monkeypatch):
    """Killing sshd (or restarting the container) closes the controller
    shell; the driver must rebuild it instead of failing every later command
    with 'Socket is closed'."""
    driver = PentestDriver("task", "flag", "target")
    dead = FakeShell()
    dead.closed = True
    driver.remotes["192.168.0.5"] = RemoteShell(dead)

    fresh = MarkerShell(body="uid=0(root)")
    monkeypatch.setattr(
        driver,
        "_connect_to_kali",
        lambda: SimpleNamespace(invoke_shell=lambda: fresh),
    )
    monkeypatch.setattr(pentest_driver, "wait_for_message", lambda _shell: "")

    output, done = driver.step(
        ExecuteBash(machine_ipaddr="192.168.0.5", cmd="id")
    )

    assert "uid=0(root)" in output
    assert driver.remotes["192.168.0.5"].shell is fresh
    assert done is False


def test_driver_asks_the_agent_to_reconnect_a_dropped_remote_session():
    driver = PentestDriver("task", "flag", "target")
    dead = FakeShell()
    dead.closed = True
    driver.remotes["192.168.1.10"] = RemoteShell(dead)

    output, _ = driver.step(
        ExecuteBash(machine_ipaddr="192.168.1.10", cmd="id")
    )

    assert "SSHConnect" in output
    assert "192.168.1.10" not in driver.remotes


def test_driver_reconnects_kali_when_session_is_missing(monkeypatch):
    driver = PentestDriver("task", "flag", "target")
    ssh = Mock()
    ssh.invoke_shell.return_value = FakeShell()
    connect = Mock(return_value=ssh)
    monkeypatch.setattr(driver, "_connect_to_kali", connect)
    monkeypatch.setattr(pentest_driver, "wait_for_message", lambda _s: "")
    monkeypatch.setattr(
        ExecuteBash, "run", lambda self, shell: "kali-output"
    )

    out, _ = driver.step(
        ExecuteBash(machine_ipaddr="192.168.0.5", cmd="id")
    )

    connect.assert_called_once()
    assert "192.168.0.5" in driver.remotes
    assert out == "kali-output"


# --- Observations of interactive prompts ------------------------------------


def test_driver_appends_sudo_hint_to_password_prompts():
    driver = PentestDriver("task", "flag", "target")
    shell = Mock()
    shell.execute_cmd.return_value = "x\n[sudo] password for student:"
    driver.remotes["192.168.1.10"] = shell

    out, _ = driver.step(
        ExecuteBash(machine_ipaddr="192.168.1.10", cmd="sudo id")
    )

    assert "interactive shell" in out
    assert "provide the password" in out


def test_driver_appends_hint_to_host_key_prompts():
    driver = PentestDriver("task", "flag", "target")
    shell = Mock()
    shell.execute_cmd.return_value = (
        "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
    )
    driver.remotes["192.168.1.10"] = shell

    out, _ = driver.step(
        ExecuteBash(machine_ipaddr="192.168.1.10", cmd="ssh target")
    )

    assert "host-key prompt" in out


def test_driver_appends_the_msf_hint_to_a_meterpreter_prompt():
    """A session prompt must say where the agent's next command runs.

    The shell layer labels a Metasploit session `meterpreter >`, which names
    neither `msf` nor `msfconsole`. The hint used to call it an interactive
    msfconsole, so a run that already held a shell on the target kept sending
    msfconsole commands that the session answered with `msfconsole: not found`
    instead of reading the flag. The prompt is a session on the target, and the
    hint now says so.
    """
    driver = PentestDriver("task", "flag", "target")
    shell = Mock()
    shell.execute_cmd.return_value = "Command shell session 1 opened\nmeterpreter >"
    driver.remotes["192.168.1.10"] = shell

    out, _ = driver.step(
        ExecuteBash(machine_ipaddr="192.168.1.10", cmd="id")
    )

    assert "session on the target" in out
    assert "exit" in out
    assert "interactive msfconsole" not in out


def test_driver_keeps_the_msfconsole_hint_for_an_msfconsole_prompt():
    driver = PentestDriver("task", "flag", "target")
    shell = Mock()
    shell.execute_cmd.return_value = "meterpreter session 1 opened\nmsf6 >"
    driver.remotes["192.168.1.10"] = shell

    out, _ = driver.step(
        ExecuteBash(machine_ipaddr="192.168.1.10", cmd="id")
    )

    assert "interactive msfconsole" in out


def test_driver_reraises_the_action_timeout_instead_of_observing_it(monkeypatch):
    """The runner's action timeout must not be scored as the agent's action.

    Converting it into an observation is what the surrounding ``except
    Exception`` does for real environment failures, but a timeout says nothing
    about the agent: the runner refunds the step and counts it in
    ``action_timeouts`` only when the exception reaches it.
    """
    driver = PentestDriver("task", "flag", "target")

    def _timeout(tool):
        raise _ActionTimeout("Action exceeded the 30-second timeout")

    monkeypatch.setattr(driver, "_run_tool", _timeout)

    with pytest.raises(TimeoutError):
        driver.step(ExecuteBash(machine_ipaddr="192.168.0.5", cmd="id"))


# --- Flag submission --------------------------------------------------------


def test_driver_accepts_matching_flag_and_truncates_long_submission():
    driver = PentestDriver("task", "Abcdef1234567890", "target")

    output, done = driver.step(FinalAnswer(flag="Abcdef1234567890-extra"))

    assert output == "You Won!"
    assert done is True


def test_driver_rejects_wrong_flag():
    driver = PentestDriver("task", "correct", "target")

    output, done = driver.step(FinalAnswer(flag="incorrect"))

    assert output == "Wrong flag. Try again."
    assert done is False


def test_flag_normalization_truncates_and_strips():
    driver = PentestDriver("task", "Abcdef1234567890", "target")

    # Long flag with trailing text is accepted after normalization
    output, done = driver.step(FinalAnswer(flag="Abcdef1234567890-extra"))
    assert output == "You Won!"
    assert done is True

    # Flag with whitespace is accepted
    output, done = driver.step(FinalAnswer(flag=" Abcdef1234567890 "))
    assert output == "You Won!"
    assert done is True


def test_flag_length_is_configurable(monkeypatch):
    monkeypatch.delenv("AUTOPENBENCH_FLAG_LENGTH", raising=False)
    assert pentest_driver.flag_length() == pentest_driver.DEFAULT_FLAG_LENGTH == 16

    monkeypatch.setenv("AUTOPENBENCH_FLAG_LENGTH", "24")
    assert pentest_driver.flag_length() == 24

    driver = PentestDriver("task", "A" * 24, "target")
    output, done = driver.step(FinalAnswer(flag="A" * 24 + "-extra"))

    assert output == "You Won!"
    assert done is True


def test_flag_longer_than_the_configured_length_still_matches():
    """A task whose flag is not 16 characters long must remain solvable."""
    long_flag = "flag{" + "a" * 19 + "}"

    output, done = PentestDriver("task", long_flag, "target").step(
        FinalAnswer(flag=long_flag + " (trailing text)")
    )

    assert (output, done) == ("You Won!", True)


def test_flag_is_stripped_when_it_is_loaded():
    """data/games.json is hand-edited, so a flag may carry stray whitespace.

    Stripping only the *submission* would make such a task impossible to
    solve, and look like an agent failure rather than a data problem.
    """
    driver = PentestDriver("task", "  Abcdef1234567890\t", "target")

    assert driver.flag == "Abcdef1234567890"
    assert driver.step(FinalAnswer(flag="Abcdef1234567890")) == ("You Won!", True)
