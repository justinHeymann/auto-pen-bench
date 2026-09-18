import itertools
import json
import re
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

try:
    import yaml
except ImportError:
    yaml = None

import pytest

from autopenbench.driver import pentest_driver
from autopenbench.driver.pentest_driver import PentestDriver
from autopenbench.evaluation.evaluator import Evaluator
from autopenbench.shell import remote_shell as remote_shell_mod
from autopenbench.shell.remote_shell import RemoteShell, receive_data
from autopenbench.tools import (
    ExecuteBash,
    FinalAnswer,
    SSHConnect,
    WriteFile,
    wait_for_message,
)
from autopenbench.utils import utils


class FakeShell:
    """Minimal paramiko.Channel stand-in with a single canned output."""

    def __init__(self, output=b"ready\n"):
        self.output = output
        self.sent = []
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def send(self, value):
        self.sent.append(value)

    def recv_ready(self):
        return bool(self.output)

    def recv(self, _size):
        output, self.output = self.output, b""
        return output


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


def test_write_file_sanitizes_name_and_preserves_content(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "autopenbench.tools.write_file.SCRIPTS", str(tmp_path)
    )

    result = WriteFile(content="echo $HOME\n", file_name="../run me.sh").run()

    assert result == "File /root/scripts/runme.sh correctly saved."
    assert (tmp_path / "runme.sh").read_text() == "echo $HOME\n"
    assert not (tmp_path.parent / "run me.sh").exists()


def test_write_file_reports_missing_scripts_directory(monkeypatch):
    monkeypatch.setattr("autopenbench.tools.write_file.SCRIPTS", None)

    assert WriteFile(content="x", file_name="x").run() == (
        "Error: KALISCRIPTS environment variable is not set."
    )


def test_execute_bash_converts_shell_errors_to_observations():
    shell = Mock()
    shell.execute_cmd.side_effect = RuntimeError("broken channel")

    result = ExecuteBash(machine_ipaddr="192.168.0.5", cmd="id").run(shell)

    assert result == "Error executing command on the remote shell: broken channel"


def test_tool_models_require_their_inputs():
    with pytest.raises(Exception):
        FinalAnswer()
    with pytest.raises(Exception):
        SSHConnect(ssh_ipaddr="127.0.0.1", ssh_port=22, ssh_username="root")


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


def test_remote_shell_blocks_forbidden_network_tools():
    shell = FakeShell()
    remote_shell = RemoteShell(shell)

    assert remote_shell.execute_cmd("nc -lvnp 4444") == "Don't use netcat or socat!"
    assert shell.sent == []


def test_remote_shell_tracks_metasploit_session_state():
    remote_shell = RemoteShell(FakeShell())

    assert remote_shell.check_metasploit_shell(
        "Command shell session 1 opened"
    ) is True
    remote_shell.msfshell = True
    assert remote_shell.check_metasploit_shell(
        "Command shell session 1 closed"
    ) is False


def test_evaluator_removes_reached_commands_and_unlocks_stages(monkeypatch):
    fake_client = Mock()
    monkeypatch.setattr("autopenbench.evaluation.evaluator.OpenAI", lambda **_: fake_client)
    monkeypatch.setattr(
        "autopenbench.evaluation.evaluator.instructor.from_openai",
        lambda _client: Mock(),
    )
    evaluator = Evaluator(
        api_key="test",
        command_milestones=["discover", "exploit"],
        stage_milestones=["Discovery,1", "Exploitation,2"],
    )
    evaluator._evaluate = Mock(side_effect=[True, False, False])

    first = evaluator.evaluate_step("first step")
    second = evaluator.evaluate_step("second step")

    assert first == {"command": ["discover"], "stage": ["Discovery"]}
    assert second == {"command": [], "stage": []}
    assert evaluator.reached_milestones == 1
    assert evaluator.command_milestones == ["exploit"]
    assert evaluator.stage_milestones == ["Exploitation,2"]


def test_evaluator_supports_commas_in_stage_names(monkeypatch):
    monkeypatch.setattr("autopenbench.evaluation.evaluator.OpenAI", lambda **_: Mock())
    monkeypatch.setattr(
        "autopenbench.evaluation.evaluator.instructor.from_openai",
        lambda _client: Mock(),
    )
    evaluator = Evaluator("test", [], ["Discovery, passive,1"])
    evaluator.reached_milestones = 1

    assert evaluator.evaluate_step("step") == {
        "command": [],
        "stage": ["Discovery, passive"],
    }


def test_evaluator_fails_closed_after_retries(monkeypatch):
    monkeypatch.setattr("autopenbench.evaluation.evaluator.OpenAI", lambda **_: Mock())
    fake_instructor = Mock()
    fake_instructor.chat.completions.create.side_effect = RuntimeError("offline")
    monkeypatch.setattr(
        "autopenbench.evaluation.evaluator.instructor.from_openai",
        lambda _client: fake_instructor,
    )
    evaluator = Evaluator("test", [], [])

    assert evaluator._evaluate("step", "milestone", max_retries=2, retry_delay=0) is False
    assert fake_instructor.chat.completions.create.call_count == 2


def test_load_milestones_ignores_blank_lines(tmp_path, monkeypatch):
    project = tmp_path / "project"
    milestone_file = project / "milestones" / "command_milestones" / "level" / "category"
    milestone_file.mkdir(parents=True)
    (milestone_file / "vm0.txt").write_text("one\n\n two\n")
    monkeypatch.setattr(utils, "PROJECT", str(project))

    assert utils.load_milestones("command", "level", "category", 0) == [
        "one",
        " two",
    ]


def test_load_data_reads_games_json(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "games.json").write_text(
        json.dumps({"level": {"category": [{"target": "vm0"}]}})
    )
    monkeypatch.setattr(utils, "PROJECT", str(project))

    assert utils.load_data("level")["category"][0]["target"] == "vm0"


def test_compose_command_preserves_file_order():
    assert pentest_driver._compose_command(["base.yml", "target.yml"]) == [
        "docker",
        "compose",
        "-f",
        "base.yml",
        "-f",
        "target.yml",
    ]


# --- RemoteShell.execute_cmd: completion-marker protocol ---------------------


def test_execute_cmd_uses_marker_and_strips_it_from_output():
    shell = MarkerShell(body="uid=0(root)")

    out = RemoteShell(shell).execute_cmd("id")

    assert "uid=0(root)" in out
    assert "AUTOPENBENCH_DONE" not in out
    assert "printf" in shell.sent[0]


def test_execute_cmd_drains_stale_output_before_running_command():
    shell = MarkerShell(body="fresh output", stale=b"stale-leftover\n")

    out = RemoteShell(shell).execute_cmd("whoami")

    assert "fresh output" in out
    assert "stale-leftover" not in out


def test_execute_cmd_times_out_when_marker_never_arrives(monkeypatch):
    shell = FakeShell(output=b"")
    ticks = itertools.count(0, 20)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    out = RemoteShell(shell).execute_cmd("sleepy-command")

    assert "Timed out waiting for shell prompt" in out


def test_execute_cmd_sudo_uses_password_heuristic_without_marker():
    shell = FakeShell(output=b"[sudo] password for student:")

    out = RemoteShell(shell).execute_cmd("sudo id")

    # No completion marker is sent for sudo/su (it could be consumed as the
    # password), and the password prompt is surfaced to the agent.
    assert shell.sent == ["sudo id\n"]
    assert "password" in out.lower()
    assert "AUTOPENBENCH_DONE" not in out


# --- Shell receive helpers ---------------------------------------------------


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


def test_receive_data_times_out(monkeypatch):
    shell = FakeShell(output=b"")
    shell.recv = Mock(side_effect=socket.timeout)
    ticks = itertools.count(0, 5)
    monkeypatch.setattr(
        remote_shell_mod.time, "monotonic", lambda: next(ticks)
    )

    assert receive_data(shell) == ""


# --- PentestDriver routing: reconnect, hints, unknown tools ------------------


def test_driver_reports_unknown_tool():
    class MysteryTool:
        pass

    out, done = PentestDriver("task", "flag", "target").step(MysteryTool())

    assert out == "Unknown tool: MysteryTool"
    assert done is False


def test_driver_routes_write_file(monkeypatch):
    monkeypatch.setattr(WriteFile, "run", lambda self: "saved")

    out, done = PentestDriver("task", "flag", "target").step(
        WriteFile(content="x", file_name="x.sh")
    )

    assert out == "saved"
    assert done is False


def test_driver_reconnects_kali_when_session_is_missing(monkeypatch):
    driver = PentestDriver("task", "flag", "target")
    ssh = Mock()
    ssh.invoke_shell.return_value = FakeShell()
    connect = Mock(return_value=ssh)
    monkeypatch.setattr(driver, "_connect_to_kali", connect)
    monkeypatch.setattr(
        "autopenbench.driver.pentest_driver.wait_for_message", lambda _s: ""
    )
    monkeypatch.setattr(
        ExecuteBash, "run", lambda self, shell: "kali-output"
    )

    out, _ = driver.step(
        ExecuteBash(machine_ipaddr="192.168.0.5", cmd="id")
    )

    connect.assert_called_once()
    assert "192.168.0.5" in driver.remotes
    assert out == "kali-output"


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


# --- Docker compose orchestration (subprocess mocked) ------------------------


def test_restart_requires_environment_variables(monkeypatch):
    monkeypatch.setattr(pentest_driver, "PROJECT", None)
    monkeypatch.setattr(pentest_driver, "SCRIPTS", None)

    with pytest.raises(EnvironmentError):
        pentest_driver.restart_docker_compose_service(
            "in-vitro_access_control_vm0"
        )


def _stub_compose_env(monkeypatch, tmp_path):
    project = tmp_path / "project"
    scripts = tmp_path / "scripts"
    (project / "machines").mkdir(parents=True)
    scripts.mkdir()
    (scripts / "payload.py").write_text("x")
    (scripts / "leave_me_here").write_text("")
    (scripts / "junk").mkdir()
    monkeypatch.setattr(pentest_driver, "PROJECT", str(project))
    monkeypatch.setattr(pentest_driver, "SCRIPTS", str(scripts))
    monkeypatch.setattr(pentest_driver, "_all_compose_files", lambda: ["base.yml"])
    run = Mock()
    monkeypatch.setattr(pentest_driver.subprocess, "run", run)
    return project, scripts, run


def test_restart_parses_service_and_cleans_scripts(monkeypatch, tmp_path):
    project, scripts, run = _stub_compose_env(monkeypatch, tmp_path)

    pentest_driver.restart_docker_compose_service("real-world_cve_vm5")

    # down -> kali up -> target up
    assert run.call_count == 3
    down_cmd = run.call_args_list[0].args[0]
    up_cmd = run.call_args_list[2].args[0]
    assert "down" in down_cmd
    assert "kali_master" in run.call_args_list[1].args[0]
    assert up_cmd[-1] == "real-world_cve_vm5"
    assert str(project / "machines" / "real-world" / "cve") in " ".join(up_cmd)
    # Scripts dir cleaned but the marker file survives
    assert sorted(p.name for p in scripts.iterdir()) == ["leave_me_here"]


def test_restart_starts_sidecar_services(monkeypatch, tmp_path):
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)

    pentest_driver.restart_docker_compose_service("in-vitro_web_security_vm3")

    assert run.call_count == 4
    assert run.call_args_list[3].args[0][-1] == (
        "in-vitro_web_security_vm3_database"
    )


def test_all_compose_files_covers_every_category(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "games.json").write_text(
        json.dumps({"lvl": {"cat": [{"target": "x"}]}})
    )
    monkeypatch.setattr(pentest_driver, "PROJECT", str(project))

    files = pentest_driver._all_compose_files()

    assert files == [
        str(project / "machines" / "docker-compose.yml"),
        str(project / "machines" / "lvl" / "cat" / "docker-compose.yml"),
    ]


# --- Evaluator: real _evaluate path with mocked LLM --------------------------


def _make_evaluator(monkeypatch, fake_instructor, commands=None, stages=None):
    monkeypatch.setattr(
        "autopenbench.evaluation.evaluator.OpenAI", lambda **_: Mock()
    )
    monkeypatch.setattr(
        "autopenbench.evaluation.evaluator.instructor.from_openai",
        lambda _client: fake_instructor,
    )
    return Evaluator("test", commands or [], stages or [])


def test_evaluate_returns_llm_judgment_and_builds_prompt(monkeypatch):
    fake = Mock()
    fake.chat.completions.create.return_value = SimpleNamespace(
        agent_succeed=True
    )
    evaluator = _make_evaluator(monkeypatch, fake)

    assert evaluator._evaluate("ran nmap", "discover hosts") is True
    prompt = fake.chat.completions.create.call_args.kwargs[
        "messages"
    ][0]["content"]
    assert "ran nmap" in prompt
    assert "discover hosts" in prompt


def test_evaluate_retries_transient_errors(monkeypatch):
    fake = Mock()
    fake.chat.completions.create.side_effect = [
        RuntimeError("boom"),
        SimpleNamespace(agent_succeed=True),
    ]
    evaluator = _make_evaluator(monkeypatch, fake)

    assert evaluator._evaluate(
        "step", "milestone", max_retries=3, retry_delay=0
    ) is True
    assert fake.chat.completions.create.call_count == 2


def test_load_data_missing_category_raises_key_error(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "games.json").write_text('{"in-vitro": {}}')
    monkeypatch.setattr(utils, "PROJECT", str(project))

    with pytest.raises(KeyError):
        utils.load_data("real-world")


# --- MCP server initialization ----------------------------------------------


def test_mcp_server_initializes_driver(monkeypatch):
    from autopenbench.mcp_server import mcp_server as mcp_mod

    driver = Mock()
    monkeypatch.setattr(mcp_mod, "PentestDriver", Mock(return_value=driver))
    monkeypatch.setattr(mcp_mod, "_pentest_driver", None)

    server = mcp_mod.create_mcp_server("task", "flag", "target")

    assert server is not None
    assert mcp_mod._pentest_driver is driver
    driver.reset.assert_called_once()  # reset() starts containers and connects to Kali


def test_mcp_server_survives_driver_init_failure(monkeypatch):
    from autopenbench.mcp_server import mcp_server as mcp_mod

    monkeypatch.setattr(
        mcp_mod, "PentestDriver", Mock(side_effect=RuntimeError("no docker"))
    )

    server = mcp_mod.create_mcp_server("task", "flag", "target")

    assert server is not None
    assert mcp_mod._pentest_driver is None


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


def _load_manage_docker_compose():
    """Load setup/manage_docker_compose.py by file path.

    Importing it as ``setup.manage_docker_compose`` would shadow onto the
    top-level ``setup.py`` module, so load it explicitly.
    """
    import importlib.util
    path = Path(__file__).resolve().parent.parent / "setup" / "manage_docker_compose.py"
    spec = importlib.util.spec_from_file_location("manage_docker_compose", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_create_service_includes_security_opt():
    """Generated services must disable AppArmor like the hand-written ones."""
    mdc = _load_manage_docker_compose()

    _, service = mdc.create_service("level", "cat", 0, 6, 0)

    assert service["security_opt"] == ["label:disable"]


def test_generate_compose_assigns_next_free_octet(tmp_path):
    """A new category gets the next free IP third octet (no collisions)."""
    if yaml is None:
        pytest.skip("PyYAML not installed")

    mdc = _load_manage_docker_compose()

    # 4 existing in-vitro categories + 1 real-world category, and the
    # new category dir already exists (the Makefile creates it first).
    for cat in ("access_control", "cryptography", "network_security", "web_security"):
        (tmp_path / "machines" / "in-vitro" / cat).mkdir(parents=True)
    (tmp_path / "machines" / "in-vitro" / "software").mkdir(parents=True)
    (tmp_path / "machines" / "real-world" / "cve").mkdir(parents=True)
    (tmp_path / "machines" / "kali").mkdir(parents=True)

    mdc.generate_docker_compose(str(tmp_path), "in-vitro", "software", 0)

    compose_path = tmp_path / "machines" / "in-vitro" / "software" / "docker-compose.yml"
    data = yaml.safe_load(compose_path.read_text())
    ip = data["services"]["in-vitro_software_vm0"]["networks"]["net-main_network"]["ipv4_address"]

    # 5 in-vitro categories (incl. the new one) + 1 real-world = 6
    assert ip == "192.168.6.0"
