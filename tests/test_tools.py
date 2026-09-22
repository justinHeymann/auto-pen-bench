"""The tool models the agent acts through: ExecuteBash, WriteFile, ..."""
import os
from unittest.mock import Mock

import paramiko
import paramiko.ssh_exception
import pytest
from pydantic import ValidationError

from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect, WriteFile


class _ActionTimeout(TimeoutError):
    """Stands in for the harness's ActionTimeoutError (a TimeoutError)."""


def test_tool_models_require_their_inputs():
    with pytest.raises(ValidationError):
        FinalAnswer()
    with pytest.raises(ValidationError):
        SSHConnect(ssh_ipaddr="127.0.0.1", ssh_port=22, ssh_username="root")


def test_execute_bash_converts_shell_errors_to_observations():
    shell = Mock()
    shell.execute_cmd.side_effect = RuntimeError("broken channel")

    result = ExecuteBash(machine_ipaddr="192.168.0.5", cmd="id").run(shell)

    assert result == "Error executing command on the remote shell: broken channel"


def test_execute_bash_reraises_the_harness_action_timeout():
    """A TimeoutError here is the caller's own action timeout, not a failure.

    The harness bounds each action with a SIGALRM and expects the exception to
    reach it, so it can record a timeout: the step then costs no budget and is
    not judged. Turned into an observation instead (the old behaviour), the
    step was charged as a normal one and scored against the agent, and
    ``action_timeouts`` could never count anything.
    """
    shell = Mock()
    shell.execute_cmd.side_effect = _ActionTimeout(
        "Action exceeded the 30-second timeout"
    )

    with pytest.raises(TimeoutError):
        ExecuteBash(machine_ipaddr="192.168.0.5", cmd="nmap -sV 10.0.0.1").run(shell)


# --- SSHConnect: failure cleanup --------------------------------------------


def test_ssh_connect_failure_releases_the_tunnel(monkeypatch):
    """A failed connect must not leave a channel open on the Kali transport:
    the driver retries connections, so leaked channels would pile up."""
    tunnel = Mock()
    transport = Mock()
    transport.open_channel.return_value = tunnel
    ssh_kali = Mock()
    ssh_kali.get_transport.return_value = transport

    def _fail(*_args, **_kwargs):
        raise paramiko.ssh_exception.SSHException("auth failed")

    monkeypatch.setattr(paramiko.SSHClient, "connect", _fail)

    tool = SSHConnect(
        ssh_ipaddr="192.168.1.10", ssh_port=22,
        ssh_username="student", ssh_password="password",
    )
    shell, msg = tool.run(ssh_kali)

    assert shell is None
    assert "auth failed" in msg
    tunnel.close.assert_called_once()


# --- WriteFile: containment and permissions ---------------------------------


def test_write_file_sanitizes_name_and_preserves_content(tmp_path, monkeypatch):
    monkeypatch.setenv("KALISCRIPTS", str(tmp_path))

    result = WriteFile(content="echo $HOME\n", file_name="../run me.sh").run()

    assert result == "File /root/scripts/runme.sh correctly saved."
    assert (tmp_path / "runme.sh").read_text() == "echo $HOME\n"
    assert not (tmp_path.parent / "run me.sh").exists()


def test_write_file_reports_missing_scripts_directory(monkeypatch):
    monkeypatch.delenv("KALISCRIPTS", raising=False)

    assert WriteFile(content="x", file_name="x").run() == (
        "Error: KALISCRIPTS environment variable is not set."
    )


def test_write_file_rejects_symlink_escaping_scripts_directory(tmp_path, monkeypatch):
    """A symlink inside KALISCRIPTS must not be followed out of it."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (scripts / "escape.sh").symlink_to(outside / "target.sh")

    monkeypatch.setenv("KALISCRIPTS", str(scripts))

    result = WriteFile(content="pwned", file_name="escape.sh").run()

    assert result.startswith("Error: Invalid filename")
    assert not (outside / "target.sh").exists()


def test_write_file_marks_written_script_executable(tmp_path, monkeypatch):
    monkeypatch.setenv("KALISCRIPTS", str(tmp_path))

    WriteFile(content="#!/bin/sh\n", file_name="run.sh").run()

    assert os.stat(tmp_path / "run.sh").st_mode & 0o111
