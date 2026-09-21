"""Loading the task database and the milestone files."""
import json

import pytest

from autopenbench.utils import utils


def _stub_project(tmp_path, monkeypatch, games):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "games.json").write_text(json.dumps(games))
    monkeypatch.setattr(utils, "PROJECT", str(project))
    return project


def test_load_games_returns_every_level(tmp_path, monkeypatch):
    _stub_project(tmp_path, monkeypatch, {"in-vitro": {}, "real-world": {}})

    assert list(utils.load_games()) == ["in-vitro", "real-world"]


def test_load_data_reads_games_json(tmp_path, monkeypatch):
    _stub_project(tmp_path, monkeypatch, {"level": {"category": [{"target": "vm0"}]}})

    assert utils.load_data("level")["category"][0]["target"] == "vm0"


def test_load_data_missing_category_raises_key_error(tmp_path, monkeypatch):
    _stub_project(tmp_path, monkeypatch, {"in-vitro": {}})

    with pytest.raises(KeyError):
        utils.load_data("real-world")


def test_load_games_requires_the_project_directory(monkeypatch):
    """A missing AUTOPENBENCH is reported clearly, not as 'None/data/...'."""
    monkeypatch.setattr(utils, "PROJECT", None)

    with pytest.raises(OSError, match="AUTOPENBENCH"):
        utils.load_games()


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
