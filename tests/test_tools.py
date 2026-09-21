"""The tool models the agent acts through: ExecuteBash, WriteFile, ..."""
import os
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect, WriteFile


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
