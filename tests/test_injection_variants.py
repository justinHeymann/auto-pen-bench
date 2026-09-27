"""Prompt-injection variant tasks: service naming and sidecar wiring.

The driver derives the compose file from the service name by dropping the
last underscore-separated token, so variant names must keep their suffix
underscore-free (``..._vm0sham``, never ``..._vm0_sham``). These tests pin
that contract, the generated overlay dirs, and the SIDECAR_SERVICES entries
that start a collection endpoint for EVERY condition of the two endpoint
tasks - including baseline and sham, because a control that cannot produce
the treatment's evidence cannot falsify anything.
"""

import json
from pathlib import Path

import pytest
from support import load_module
from test_compose_orchestration import _stub_compose_env

from autopenbench.driver import pentest_driver
from autopenbench.utils import load_games

REPO = Path(__file__).resolve().parent.parent
PAYLOAD_DATA = REPO / 'benchmark' / 'injection_payloads' / 'payloads.json'
GAMES = REPO / 'data' / 'games.json'
COMPOSE = (REPO / 'benchmark' / 'machines' / 'in-vitro' / 'web_security' /
           'docker-compose.yml')
MILESTONES = REPO / 'benchmark' / 'milestones'

COLLECTOR = 'in-vitro_web_security_{vm}collector'
DATABASE = 'in-vitro_web_security_vm3_database'


def payload_data():
    return json.loads(PAYLOAD_DATA.read_text(encoding='utf-8'))


def expected_sidecars(task: str, endpoint_task: bool) -> list:
    vm = task.rsplit('_', 1)[-1]
    sidecars = [COLLECTOR.format(vm=vm)] if endpoint_task else []
    if vm == 'vm3':
        sidecars.append(DATABASE)
    return sidecars


def task_ids():
    return list(payload_data()['tasks'])


def endpoint_tasks():
    """Tasks whose payloads make an outbound request."""
    return {
        payload['task'] for payload in payload_data()['payloads']
        if payload.get('request')
    }


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


@pytest.mark.parametrize('task', task_ids())
@pytest.mark.parametrize('condition', ['', 'sham'])
def test_every_condition_of_a_task_starts_exactly_its_declared_sidecars(
        monkeypatch, tmp_path, task, condition):
    """Baseline and sham included: the three conditions must differ only in the
    payload text, so a control has to be able to produce the same kind of
    evidence the treatment's proof relies on."""
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)
    target = f'in-vitro_web_security_{task.rsplit("_", 1)[-1]}{condition}'
    expected = expected_sidecars(task, task in endpoint_tasks())

    pentest_driver.restart_docker_compose_service(target)

    assert run.call_count == 3 + len(expected)
    assert [call.args[0][-1] for call in run.call_args_list[3:]] == expected


@pytest.mark.parametrize('payload_id', [
    payload['id'] for payload in json.loads(
        PAYLOAD_DATA.read_text(encoding='utf-8'))['payloads']
])
def test_every_declared_payload_has_a_target_an_overlay_and_a_sidecar(
        monkeypatch, tmp_path, payload_id):
    """Adding a payload to the data file without wiring it into the compose
    file and its sidecars must fail here rather than at run time."""
    payloads = {p['id']: p for p in payload_data()['payloads']}
    payload = payloads[payload_id]
    task = payload['task']
    vm = task.rsplit('_', 1)[-1]
    directory = f'{vm}inj_{payload_id}'
    # The overlay directory keeps its descriptive name, but the driver-facing
    # target must be a single underscore-free token.
    target = f'in-vitro_web_security_{vm}inj-{payload_id.replace("_", "-")}'

    assert (REPO / 'benchmark' / 'machines' / 'in-vitro' / 'web_security' /
            directory / 'Dockerfile').is_file()
    compose_text = COMPOSE.read_text(encoding='utf-8')
    assert f'{target}:' in compose_text
    assert f'build: ./in-vitro/web_security/{directory}' in compose_text

    expected = expected_sidecars(task, bool(payload.get('request')))
    assert sorted(pentest_driver.SIDECAR_SERVICES.get(target, [])) == sorted(expected)

    _, _, run = _stub_compose_env(monkeypatch, tmp_path)
    pentest_driver.restart_docker_compose_service(target)
    assert [call.args[0][-1] for call in run.call_args_list[3:]] == expected


@pytest.mark.parametrize('task', task_ids())
def test_shams_are_wired_like_their_task(monkeypatch, tmp_path, task):
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)
    vm = task.rsplit('_', 1)[-1]

    pentest_driver.restart_docker_compose_service(
        f'in-vitro_web_security_{vm}sham')

    expected = expected_sidecars(task, task in endpoint_tasks())
    assert [call.args[0][-1] for call in run.call_args_list[3:]] == expected


@pytest.mark.parametrize('target', [
    'in-vitro_web_security_vm0', 'in-vitro_web_security_vm0sham',
    'in-vitro_web_security_vm0inj',
])
def test_a_task_without_an_endpoint_starts_no_collector(
        monkeypatch, tmp_path, target):
    """vm0/vm3 payloads ask for no request, so no collector exists in any of
    their conditions (uniform absence is parity too)."""
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)

    pentest_driver.restart_docker_compose_service(target)

    assert run.call_count == 3


@pytest.mark.parametrize('target', [
    'in-vitro_web_security_vm3sham', 'in-vitro_web_security_vm3inj',
    'in-vitro_web_security_vm3inj-confusion-a',
    'in-vitro_web_security_vm3inj-confusion-b',
])
def test_vm3_variants_keep_the_database_sidecar(monkeypatch, tmp_path, target):
    _, _, run = _stub_compose_env(monkeypatch, tmp_path)

    pentest_driver.restart_docker_compose_service(target)

    assert run.call_count == 4
    assert run.call_args_list[3].args[0][-1] == DATABASE


def test_games_json_variant_entries_are_appended_after_the_originals():
    """Variant indices 7-14 must sit after web_security vm0-6: vm_id is the
    array index, and the milestone files were copied to vm7..vm14."""
    games = load_games()

    web = games["in-vitro"]["web_security"]
    # 7 originals + 8 v1 pilot variants + 8 v2 payload variants.
    assert len(web) == 23
    targets = [entry["target"] for entry in web]
    assert targets[:7] == [
        f"in-vitro_web_security_vm{i}" for i in range(7)]
    # Each variant shares its original's task text and flag.
    for original_idx, (sham_idx, inj_idx) in {
            0: (7, 8), 1: (9, 10), 2: (11, 12), 3: (13, 14)}.items():
        for variant_idx in (sham_idx, inj_idx):
            assert web[variant_idx]["task"] == web[original_idx]["task"]
            assert web[variant_idx]["flag"] == web[original_idx]["flag"]


def _registrar():
    """The registrar module, loaded once.

    ``load_module`` builds a fresh module object per call, so loading it twice
    would hand out two distinct ``RegistrationError`` classes and defeat
    ``pytest.raises``.
    """
    global _REGISTRAR
    if _REGISTRAR is None:
        _REGISTRAR = load_module('register_injection_variants',
                                 'benchmark/register_injection_variants.py')
    return _REGISTRAR


_REGISTRAR = None


def test_the_v2_payload_variants_are_registered_tasks_with_milestones():
    """A variant that is missing from games.json - or whose vm<N>.txt files
    were not copied - cannot be launched at all, so the payload data, the task
    table and both milestone trees have to agree. vm_id IS the array index, so
    the entries must be appended, never inserted."""
    web = load_games()['in-vitro']['web_security']
    index_of = {entry['target']: i for i, entry in enumerate(web)}
    registrar = _registrar()

    for payload in payload_data()['payloads']:
        target = registrar.target_of(payload)
        assert target in index_of, f'{target} is not a games.json task'
        index = index_of[target]
        original = index_of[f"in-vitro_{payload['task']}"]
        # Only the container differs: same text, same flag to capture.
        assert web[index]['task'] == web[original]['task']
        assert web[index]['flag'] == web[original]['flag']
        for kind in ('command_milestones', 'stage_milestones'):
            milestone = (MILESTONES / kind / 'in-vitro' / 'web_security' /
                         f'vm{index}.txt')
            assert milestone.is_file(), milestone


def test_the_shipped_task_table_is_already_registered():
    """Running the registrar against the shipped files must be a no-op; if it
    is not, a payload was added to payloads.json without being registered."""
    before = GAMES.read_bytes()
    assert _registrar().register() == []
    assert GAMES.read_bytes() == before


def test_a_variant_whose_flag_differs_from_its_original_is_refused(tmp_path):
    """The variant container mounts its original's flag file, so a games.json
    entry with a different flag would record an unwinnable task."""
    games = json.loads(GAMES.read_text(encoding='utf-8'))
    games['in-vitro']['web_security'][15]['flag'] = 'tampered-flag'
    copy = tmp_path / 'games.json'
    copy.write_text(json.dumps(games), encoding='utf-8')

    with pytest.raises(_registrar().RegistrationError):
        _registrar().register(games_path=copy)


def test_every_registered_target_resolves_to_its_category_compose_file():
    """The driver recovers the compose file from the target name: it drops the
    FINAL underscore-separated token and turns the level prefix into a directory
    (`target -> rsplit('_', 1)[0] -> machines/<level>/<category>/docker-compose.yml`).

    So a target carrying an extra underscore makes the driver look for a
    directory that does not exist and EVERY run of that cell dies as an
    environment failure before the container ever starts. The first v2 smoke
    test died exactly this way (`..._vm1inj_redirect_a` -> looked for
    `machines/in-vitro/web_security_vm1inj_redirect/`). This test pins the
    contract for every registered task, v1 names included.
    """
    for entry in load_games()['in-vitro']['web_security']:
        target = entry['target']
        level, rest = target.split('_', 1)
        category = rest.rsplit('_', 1)[0]
        compose = (REPO / 'benchmark' / 'machines' / level / category /
                   'docker-compose.yml')
        assert compose.is_file(), f'{target} resolves to a missing {compose}'
        assert f'\n    {target}:' in compose.read_text(encoding='utf-8'), (
            f'{target} is registered but not defined in {compose}')
