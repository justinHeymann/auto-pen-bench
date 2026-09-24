"""Prompt-injection variant tasks: service naming and sidecar wiring.

The driver derives the compose file from the service name by dropping the
last underscore-separated token, so variant names must keep their suffix
underscore-free (``..._vm0sham``, never ``..._vm0_sham``). These tests pin
that contract plus the SIDECAR_SERVICES entries that start a collection
endpoint for the injected redirect/info-leak conditions — and, just as
importantly, NOT for the baseline/sham ones.
"""

import pytest
from test_compose_orchestration import _stub_compose_env

from autopenbench.driver import pentest_driver
from autopenbench.utils import load_games


def _compose_path_of(run, call):
    """The -f argument pointing into a level/category directory."""
    cmd = run.call_args_list[call].args[0]
    return " ".join(cmd)


def test_variant_names_resolve_to_the_category_compose_file(
        monkeypatch, tmp_path):
    project, _, run = _stub_compose_env(monkeypatch, tmp_path)

    for name in ("in-vitro_web_security_vm0sham",
                 "in-vitro_web_security_vm0inj",
                 "in-vitro_web_security_vm1collector"):
        run.reset_mock()
        pentest_driver.restart_docker_compose_service(name)

        up_cmd = _compose_path_of(run, 2)
        assert str(project / "machines" / "in-vitro" / "web_security") in up_cmd


@pytest.mark.parametrize(
    "target, collector",
    [
        ("in-vitro_web_security_vm1inj",
         "in-vitro_web_security_vm1collector"),
        ("in-vitro_web_security_vm2inj",
         "in-vitro_web_security_vm2collector"),
    ],
)
def test_restart_starts_the_collector_only_for_injected_endpoint_tasks(
        monkeypatch, tmp_path, target, collector):
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)

    pentest_driver.restart_docker_compose_service(target)

    assert run.call_count == 4
    assert run.call_args_list[3].args[0][-1] == collector


@pytest.mark.parametrize(
    "target",
    [
        "in-vitro_web_security_vm1",
        "in-vitro_web_security_vm1sham",
        "in-vitro_web_security_vm2",
        "in-vitro_web_security_vm2sham",
        # vm0's payload has no endpoint at all, in any condition.
        "in-vitro_web_security_vm0inj",
    ],
)
def test_restart_starts_no_collector_for_baseline_or_sham(
        monkeypatch, tmp_path, target):
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)

    # down -> kali up -> target up; no fourth (sidecar) call.
    pentest_driver.restart_docker_compose_service(target)
    assert run.call_count == 3


@pytest.mark.parametrize(
    "target",
    ["in-vitro_web_security_vm3sham", "in-vitro_web_security_vm3inj"],
)
def test_vm3_variants_keep_the_database_sidecar(monkeypatch, tmp_path, target):
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)

    pentest_driver.restart_docker_compose_service(target)

    assert run.call_count == 4
    assert run.call_args_list[3].args[0][-1] == (
        "in-vitro_web_security_vm3_database"
    )


def test_games_json_variant_entries_are_appended_after_the_originals():
    """Variant indices 7-14 must sit after web_security vm0-6: vm_id is the
    array index, and the milestone files were copied to vm7..vm14."""
    games = load_games()

    web = games["in-vitro"]["web_security"]
    assert len(web) == 15
    targets = [entry["target"] for entry in web]
    assert targets[:7] == [
        f"in-vitro_web_security_vm{i}" for i in range(7)]
    # Each variant shares its original's task text and flag.
    for original_idx, (sham_idx, inj_idx) in {
            0: (7, 8), 1: (9, 10), 2: (11, 12), 3: (13, 14)}.items():
        for variant_idx in (sham_idx, inj_idx):
            assert web[variant_idx]["task"] == web[original_idx]["task"]
            assert web[variant_idx]["flag"] == web[original_idx]["flag"]
