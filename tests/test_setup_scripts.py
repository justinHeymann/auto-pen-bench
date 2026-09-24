"""The setup/ and scripts/ helpers used to build and prepare a run."""
import itertools
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


def test_update_compose_keeps_the_files_comments(tmp_path):
    """A hand-written compose file must not be reformatted by `make create`.

    The prompt-injection contract lives in the comments of that file, so a
    yaml round-trip deletes the documentation along with the services it
    describes.
    """
    if yaml is None:
        pytest.skip("PyYAML not installed")
    mdc = _manage_docker_compose()
    category_dir = tmp_path / "machines" / "in-vitro" / "web_security"
    category_dir.mkdir(parents=True)
    compose_path = category_dir / "docker-compose.yml"
    compose_path.write_text(
        "services:\n"
        "    # the original machine: keep this note\n"
        "    in-vitro_web_security_vm0:\n"
        "        networks:\n"
        "            net-main_network:\n"
        "                ipv4_address: 192.168.4.0\n"
        "\n"
        "# Network definition\n"
        "networks:\n"
        "    net-main_network:\n"
        "        internal: true\n"
    )

    mdc.update_docker_compose(str(tmp_path), "in-vitro", "web_security", 3)

    text = compose_path.read_text()
    assert "# the original machine: keep this note" in text
    assert "# Network definition" in text
    data = yaml.safe_load(text)
    # The new service belongs to services:, not after networks:.
    assert list(data["services"]) == [
        "in-vitro_web_security_vm0", "in-vitro_web_security_vm3"
    ]
    assert data["services"]["in-vitro_web_security_vm3"]["networks"][
        "net-main_network"]["ipv4_address"] == "192.168.4.3"
    assert data["networks"]["net-main_network"]["internal"] is True


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


def _randomize_variant_fixture(tmp_path, token, extra_entries=()):
    """A VM whose flag is repeated by its injection variant entries."""
    level, category, vmid = "in-vitro", "web_security", "vm0"
    machines = tmp_path / "benchmark" / "machines"
    vm_dir = machines / level / category / vmid
    vm_dir.mkdir(parents=True)
    (vm_dir / "flag.txt").write_text(token)

    base_target = f"{level}_{category}_{vmid}"
    entries = [{"target": base_target, "flag": token}]
    for suffix, condition in (("sham", "sham"), ("inj", "injected")):
        entries.append({
            "target": f"{base_target}{suffix}",
            "flag": token,
            "variant_of": base_target,
            "condition": condition,
        })
    entries.extend(extra_entries)

    games = tmp_path / "data" / "games.json"
    games.parent.mkdir()
    games.write_text(json.dumps({level: {category: entries}}, indent=2))
    return vm_dir, games, tmp_path, machines


def test_randomize_updates_variants_together_with_their_original(tmp_path, monkeypatch):
    """A variant deliberately repeats its original's flag.

    Regression guard: that duplicate used to trip the "flag must appear
    exactly once in games.json" check, so the original could no longer be
    randomized at all. All three entries and the mounted flag file must move
    together.
    """
    mod = _randomize_flags()
    token = "QnwieQY7t7MoxguK"
    vm_dir, games, root, machines = _randomize_variant_fixture(tmp_path, token)
    _point_at_fixture(monkeypatch, mod, root, machines, games)

    assert mod.randomize(dry_run=False) == 1

    entries = json.loads(games.read_text())["in-vitro"]["web_security"]
    flags = {entry["flag"] for entry in entries}
    assert len(flags) == 1, f"entries disagree on the flag: {flags}"
    new_flag = flags.pop()
    assert new_flag != token
    assert len(new_flag) == len(token)
    # Both the original and every variant now serve the new flag.
    assert (vm_dir / "flag.txt").read_text() == new_flag


def test_randomize_skips_a_variant_entry_as_derived(tmp_path, monkeypatch, capsys):
    """A variant on its own is recognized, not reported as a bad target."""
    mod = _randomize_flags()
    token = "QnwieQY7t7MoxguK"
    vm_dir, games, root, machines = _randomize_variant_fixture(tmp_path, token)
    # Only the variant entries remain: randomizing one alone would desync it
    # from the flag file it mounts.
    data = json.loads(games.read_text())
    data["in-vitro"]["web_security"] = [
        entry for entry in data["in-vitro"]["web_security"]
        if entry.get("variant_of")
    ]
    games.write_text(json.dumps(data, indent=2))
    _point_at_fixture(monkeypatch, mod, root, machines, games)

    assert mod.randomize(dry_run=False) == 0

    output = capsys.readouterr().out
    assert "unrecognized target format" not in output
    assert "injection variant of in-vitro_web_security_vm0" in output
    assert (vm_dir / "flag.txt").read_text() == token


def test_randomize_still_refuses_a_duplicate_from_an_unrelated_entry(
        tmp_path, monkeypatch):
    """The occurrence count must not become a licence to rewrite anything
    that happens to share the token: only declared variants are expected."""
    mod = _randomize_flags()
    token = "QnwieQY7t7MoxguK"
    vm_dir, games, root, machines = _randomize_variant_fixture(
        tmp_path, token,
        extra_entries=[{"target": "in-vitro_web_security_vm9", "flag": token}],
    )
    _point_at_fixture(monkeypatch, mod, root, machines, games)

    assert mod.randomize(dry_run=False) == 0
    assert (vm_dir / "flag.txt").read_text() == token


def test_a_variant_without_variant_of_does_not_freeze_its_original(
        tmp_path, monkeypatch):
    """The target suffix alone identifies a derived entry.

    Counting only the `variant_of` key left the occurrence count mismatched
    when a variant lost it, so the original was skipped on every run -- the
    task could never be randomized again, silently.
    """
    mod = _randomize_flags()
    token = "QnwieQY7t7MoxguK"
    vm_dir, games, root, machines = _randomize_variant_fixture(tmp_path, token)
    data = json.loads(games.read_text())
    for entry in data["in-vitro"]["web_security"]:
        entry.pop("variant_of", None)
    games.write_text(json.dumps(data, indent=2))
    _point_at_fixture(monkeypatch, mod, root, machines, games)

    assert mod.randomize(dry_run=False) == 1

    entries = json.loads(games.read_text())["in-vitro"]["web_security"]
    flags = {entry["flag"] for entry in entries}
    assert len(flags) == 1
    assert (vm_dir / "flag.txt").read_text() == flags.pop()


def test_randomize_writes_nothing_when_a_later_entry_fails(
        tmp_path, monkeypatch):
    """Flag files are staged, so an interrupted run leaves no half-state.

    Written as it went, a run that died on a later entry left the first flag
    files holding a token that games.json still called stale: the container
    serves a flag the runner rejects, and the task is unsolvable.
    """
    mod = _randomize_flags()
    machines = tmp_path / "benchmark" / "machines"
    entries = []
    for vmid, token in (("vm0", "A" * 16), ("vm1", "B" * 16)):
        vm_dir = machines / "in-vitro" / "web_security" / vmid
        vm_dir.mkdir(parents=True)
        (vm_dir / "flag.txt").write_text(token)
        entries.append(
            {"target": f"in-vitro_web_security_{vmid}", "flag": token}
        )
    games = tmp_path / "data" / "games.json"
    games.parent.mkdir()
    games.write_text(json.dumps({"in-vitro": {"web_security": entries}}, indent=2))
    _point_at_fixture(monkeypatch, mod, tmp_path, machines, games)

    calls = itertools.count(1)

    def _token(length):
        if next(calls) > 1:
            raise RuntimeError("disk on fire")
        return "N" * length

    monkeypatch.setattr(mod, "random_token", _token)

    with pytest.raises(RuntimeError):
        mod.randomize(dry_run=False)

    assert (machines / "in-vitro" / "web_security" / "vm0" / "flag.txt").read_text() == "A" * 16
    assert "A" * 16 in games.read_text()


def test_randomize_rolls_back_when_the_games_commit_fails(tmp_path, monkeypatch):
    """A failed final replacement cannot leave live flags out of sync."""
    mod = _randomize_flags()
    token = "QnwieQY7t7MoxguK"
    vm_dir, games, root, machines = _randomize_variant_fixture(tmp_path, token)
    _point_at_fixture(monkeypatch, mod, root, machines, games)
    original_replace = mod.os.replace

    def fail_games_replace(source, destination):
        if destination == games:
            raise OSError("simulated full disk")
        return original_replace(source, destination)

    monkeypatch.setattr(mod.os, "replace", fail_games_replace)

    with pytest.raises(OSError):
        mod.randomize(dry_run=False)

    assert (vm_dir / "flag.txt").read_text() == token
    assert token in games.read_text()
    assert not (games.parent / ".randomize_flags-journal.json").exists()


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
