"""Container orchestration: restarting services and building compose paths."""
import json
from unittest.mock import Mock

import pytest

from autopenbench.driver import pentest_driver
from autopenbench.utils import utils


def test_compose_command_preserves_file_order():
    assert pentest_driver._compose_command(["base.yml", "target.yml"]) == [
        "docker",
        "compose",
        "-f",
        "base.yml",
        "-f",
        "target.yml",
    ]


def test_all_compose_files_covers_every_category(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "games.json").write_text(
        json.dumps({"lvl": {"cat": [{"target": "x"}]}})
    )
    # The compose paths come from the driver's own copy of the setting, while
    # games.json is read through the shared loader.
    monkeypatch.setattr(pentest_driver, "PROJECT", str(project))
    monkeypatch.setattr(utils, "PROJECT", str(project))

    files = pentest_driver._all_compose_files()

    assert files == [
        str(project / "machines" / "docker-compose.yml"),
        str(project / "machines" / "lvl" / "cat" / "docker-compose.yml"),
    ]


def test_restart_requires_environment_variables(monkeypatch):
    monkeypatch.setattr(pentest_driver, "PROJECT", None)
    monkeypatch.setattr(pentest_driver, "SCRIPTS", None)

    with pytest.raises(EnvironmentError):
        pentest_driver.restart_docker_compose_service(
            "in-vitro_access_control_vm0"
        )


def test_restart_reports_missing_scripts_directory(monkeypatch, tmp_path):
    project = tmp_path / "project"
    (project / "machines").mkdir(parents=True)
    monkeypatch.setattr(pentest_driver, "PROJECT", str(project))
    monkeypatch.setattr(pentest_driver, "SCRIPTS", str(tmp_path / "nope"))

    with pytest.raises(EnvironmentError, match="KALISCRIPTS directory"):
        pentest_driver.restart_docker_compose_service("in-vitro_access_control_vm0")


def test_restart_refuses_scripts_dir_without_sentinel(monkeypatch, tmp_path):
    """The scripts dir is emptied on every reset, so it must be the right one."""
    project = tmp_path / "project"
    scripts = tmp_path / "scripts"
    (project / "machines").mkdir(parents=True)
    scripts.mkdir()
    (scripts / "unrelated.py").write_text("x")
    monkeypatch.setattr(pentest_driver, "PROJECT", str(project))
    monkeypatch.setattr(pentest_driver, "SCRIPTS", str(scripts))

    with pytest.raises(EnvironmentError, match="leave_me_here"):
        pentest_driver.restart_docker_compose_service("in-vitro_access_control_vm0")

    assert (scripts / "unrelated.py").exists()


def _stub_compose_env(monkeypatch, tmp_path):
    """A prepared benchmark tree, with the compose calls recorded."""
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
