"""The setup/ and scripts/ helpers used to build and prepare a run."""
import json
import subprocess
import sys

import pytest

from support import load_module, repo_root

try:
    import yaml
except ImportError:
    yaml = None


# --- setup/manage_docker_compose.py -----------------------------------------


def _manage_docker_compose():
    return load_module(
        "manage_docker_compose", "setup/manage_docker_compose.py"
    )


def test_create_service_includes_security_opt():
    """Generated services must disable AppArmor like the hand-written ones."""
    mdc = _manage_docker_compose()

    _, service = mdc.create_service("level", "cat", 0, 6, 0)

    assert service["security_opt"] == ["label:disable"]


def test_generate_compose_assigns_next_free_octet(tmp_path):
    """A new category gets the next free IP third octet (no collisions)."""
    if yaml is None:
        pytest.skip("PyYAML not installed")

    mdc = _manage_docker_compose()

    # Five categories in use: 192.168.1.x .. 192.168.5.x
    for level, cat, octet in (
        ("in-vitro", "access_control", 1),
        ("in-vitro", "cryptography", 2),
        ("in-vitro", "network_security", 3),
        ("in-vitro", "web_security", 4),
        ("real-world", "cve", 5),
    ):
        category_dir = tmp_path / "machines" / level / cat
        category_dir.mkdir(parents=True)
        (category_dir / "docker-compose.yml").write_text(
            "services:\n"
            f"    {level}_{cat}_vm0:\n"
            "        networks:\n"
            "            net-main_network:\n"
            f"                ipv4_address: 192.168.{octet}.0\n"
        )
    # A stray directory (or a half-created category) must not shift the
    # numbering onto an octet that is already taken.
    (tmp_path / "machines" / "network_security" / "vm5a" / "flag.txt").mkdir(
        parents=True
    )
    # The new category directory is created before the script is called.
    (tmp_path / "machines" / "in-vitro" / "software").mkdir(parents=True)

    mdc.generate_docker_compose(str(tmp_path), "in-vitro", "software", 0)

    compose_path = tmp_path / "machines" / "in-vitro" / "software" / "docker-compose.yml"
    data = yaml.safe_load(compose_path.read_text())
    ip = data["services"]["in-vitro_software_vm0"]["networks"]["net-main_network"]["ipv4_address"]

    assert ip == "192.168.6.0"


def test_generate_compose_refuses_to_overwrite_an_existing_category(tmp_path):
    """Re-running 'create' on a category that has one must not silently drop
    every machine the existing compose file describes."""
    if yaml is None:
        pytest.skip("PyYAML not installed")

    mdc = _manage_docker_compose()
    category_dir = tmp_path / "machines" / "in-vitro" / "web_security"
    category_dir.mkdir(parents=True)
    compose_path = category_dir / "docker-compose.yml"
    compose_path.write_text("services:\n    in-vitro_web_security_vm0: {}\n")

    with pytest.raises(SystemExit):
        mdc.generate_docker_compose(str(tmp_path), "in-vitro", "web_security", 0)

    assert "vm0" in compose_path.read_text()


def test_update_compose_keeps_the_category_octet(tmp_path):
    """A new machine joins its category's subnet, whatever service the file
    lists first."""
    if yaml is None:
        pytest.skip("PyYAML not installed")

    mdc = _manage_docker_compose()
    category_dir = tmp_path / "machines" / "in-vitro" / "web_security"
    category_dir.mkdir(parents=True)
    (category_dir / "docker-compose.yml").write_text(
        "services:\n"
        "    in-vitro_web_security_vm0:\n"
        "        networks:\n"
        "            net-main_network:\n"
        "                ipv4_address: 192.168.4.0\n"
    )

    mdc.update_docker_compose(str(tmp_path), "in-vitro", "web_security", 3)

    data = yaml.safe_load((category_dir / "docker-compose.yml").read_text())
    service = data["services"]["in-vitro_web_security_vm3"]
    assert service["networks"]["net-main_network"]["ipv4_address"] == "192.168.4.3"


# --- scripts/randomize_flags.py ---------------------------------------------


def _randomize_flags():
    return load_module("randomize_flags", "scripts/randomize_flags.py")


def _randomize_fixture(tmp_path, level, category, vmid, token, extra_files=None):
    """Build a minimal benchmark tree with one VM and one games.json entry."""
    machines = tmp_path / "benchmark" / "machines"
    vm_dir = machines / level / category / vmid
    vm_dir.mkdir(parents=True)
    (vm_dir / "flag.txt").write_text(token)
    for name, body in (extra_files or {}).items():
        (vm_dir / name).write_text(body)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    games = data_dir / "games.json"
    games.write_text(json.dumps(
        {level: {category: [{"target": f"{level}_{category}_{vmid}", "flag": token}]}},
        indent=2,
    ))
    return vm_dir, games, tmp_path, machines


def _point_at_fixture(monkeypatch, mod, root, machines, games):
    monkeypatch.setattr(mod, "REPO_ROOT", root)
    monkeypatch.setattr(mod, "MACHINES_DIR", machines)
    monkeypatch.setattr(mod, "GAMES_PATH", games)


def test_randomize_skips_flag_that_appears_in_another_file(tmp_path, monkeypatch):
    """The Heartbleed VM's flag is a slice of its private key.

    Rewriting only flag.txt/games.json would leave the served key holding the
    old token, so the entry must be left untouched.
    """
    mod = _randomize_flags()
    token = "MIIEvQIBADANBgkq"
    vm_dir, games, root, machines = _randomize_fixture(
        tmp_path, "real-world", "cve", "vm0", token,
        extra_files={"local.key": f"-----BEGIN PRIVATE KEY-----\n{token}xyz\n"},
    )
    _point_at_fixture(monkeypatch, mod, root, machines, games)

    assert mod.randomize(dry_run=False) == 0
    assert (vm_dir / "flag.txt").read_text() == token
    assert json.loads(games.read_text())["real-world"]["cve"][0]["flag"] == token


def test_randomize_regenerates_a_standalone_flag(tmp_path, monkeypatch):
    mod = _randomize_flags()
    token = "Ey8C7gOdzaKxTNqp"
    vm_dir, games, root, machines = _randomize_fixture(
        tmp_path, "in-vitro", "access_control", "vm0", token,
    )
    _point_at_fixture(monkeypatch, mod, root, machines, games)

    assert mod.randomize(dry_run=False) == 1

    new_flag = json.loads(games.read_text())["in-vitro"]["access_control"][0]["flag"]
    assert new_flag != token
    assert (vm_dir / "flag.txt").read_text() == new_flag


def test_randomize_flags_exits_successfully():
    """The number of randomized flags must not become the exit status."""
    repo = repo_root()

    result = subprocess.run(
        [sys.executable, str(repo / "scripts" / "randomize_flags.py"), "--dry-run"],
        cwd=repo, capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "flag(s) randomized" in result.stdout
