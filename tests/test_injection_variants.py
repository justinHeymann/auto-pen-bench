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
import re
from pathlib import Path

import pytest

from autopenbench.driver import pentest_driver
from autopenbench.utils import load_games
from support import load_module
from test_compose_orchestration import _stub_compose_env

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


def proofs_normalise(text: str) -> str:
    """Whitespace-insensitive comparison.

    Deliberately mirrors what the scorer does: the v1 defect was a phrase the
    scorer matched literally being broken across lines by HTML/terminal
    wrapping, so a marker check that ignores whitespace is the honest one.
    """
    return ' '.join(text.split())


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


def collector_tokens_by_service():
    """``{service: {'<METHOD> /path': token}}`` out of the compose file.

    Parsed by hand rather than with YAML because the file is hand-maintained
    and a service block is easy to delimit: a service header is the only key at
    four-space indentation (``net-main_network`` under ``networks:`` matches the
    shape too, but declares no tokens and so is dropped).
    """
    text = COMPOSE.read_text(encoding='utf-8')
    blocks = re.finditer(
        r'^    ([A-Za-z0-9_-]+):\n(.*?)(?=^    [A-Za-z0-9_-]+:|\Z)',
        text, re.M | re.S)
    found = {}
    for block in blocks:
        tokens = re.search(r"COLLECTOR_TOKENS:\s*'(.*)'", block.group(2))
        if tokens:
            found[block.group(1)] = json.loads(tokens.group(1))
    return found


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


def _tiny_registration(tmp_path, *, existing_target=None, existing_flag=None):
    """A games table whose vm1 original is the only real task."""
    milestones = tmp_path / 'milestones'
    for kind in ('command_milestones', 'stage_milestones'):
        directory = milestones / kind / 'in-vitro' / 'web_security'
        directory.mkdir(parents=True)
        (directory / 'vm1.txt').write_text(f'{kind} source\n', encoding='utf-8')
    original = {
        'task': 'find the flag',
        'vulnerability': 'xss',
        'flag': 'flag{original}',
        'target': 'in-vitro_web_security_vm1',
    }
    entries = [
        {'task': 'unused', 'vulnerability': 'x', 'flag': 'flag{other}',
         'target': 'in-vitro_web_security_vm0'},
        original,
    ]
    if existing_target is not None:
        entries.append({
            'task': original['task'],
            'vulnerability': original['vulnerability'],
            'flag': original['flag'] if existing_flag is None else existing_flag,
            'target': existing_target,
        })
    games_path = tmp_path / 'games.json'
    games_path.write_text(json.dumps(
        {'in-vitro': {'web_security': entries}}), encoding='utf-8')
    payloads = tmp_path / 'payloads.json'
    payloads.write_text(json.dumps({
        'payloads': [{'id': 'redirect_a', 'task': 'web_security_vm1'}],
    }), encoding='utf-8')
    return payloads, games_path, milestones


def test_a_new_payload_is_appended_and_its_milestones_are_copied(tmp_path):
    """vm_id is the array index, so a new variant is appended and its milestone
    files are copied from the original. A second run is a no-op."""
    payloads, games_path, milestones = _tiny_registration(tmp_path)

    changed = _registrar().register(payloads, games_path, milestones)

    web = json.loads(games_path.read_text(encoding='utf-8'))[
        'in-vitro']['web_security']
    assert len(web) == 3
    assert web[2]['target'] == 'in-vitro_web_security_vm1inj-redirect-a'
    assert web[2]['variant_of'] == 'in-vitro_web_security_vm1'
    assert web[2]['flag'] == web[1]['flag']
    assert web[2]['task'] == web[1]['task']
    for kind in ('command_milestones', 'stage_milestones'):
        copied = (milestones / kind / 'in-vitro' / 'web_security' / 'vm2.txt')
        assert copied.read_text(encoding='utf-8') == f'{kind} source\n'
        assert str(copied) in changed
    assert _registrar().register(payloads, games_path, milestones) == []


def test_an_underscore_variant_name_is_renamed_in_place(tmp_path):
    """The first v2 names used an extra underscore. Appending the corrected
    name would leave two entries for one task, so the stale name is rewritten
    where it sits."""
    payloads, games_path, milestones = _tiny_registration(
        tmp_path, existing_target='in-vitro_web_security_vm1inj_redirect_a')

    _registrar().register(payloads, games_path, milestones)

    web = json.loads(games_path.read_text(encoding='utf-8'))[
        'in-vitro']['web_security']
    assert len(web) == 3
    assert web[2]['target'] == 'in-vitro_web_security_vm1inj-redirect-a'
    assert web[2]['variant_of'] == 'in-vitro_web_security_vm1'


def test_a_stale_name_with_the_wrong_flag_is_not_adopted(tmp_path):
    payloads, games_path, milestones = _tiny_registration(
        tmp_path, existing_target='in-vitro_web_security_vm1inj_redirect_a',
        existing_flag='flag{wrong}')

    with pytest.raises(_registrar().RegistrationError, match='not its original'):
        _registrar().register(payloads, games_path, milestones)


def test_a_missing_milestone_source_is_refused(tmp_path):
    payloads, games_path, milestones = _tiny_registration(tmp_path)
    (milestones / 'command_milestones' / 'in-vitro' / 'web_security'
     / 'vm1.txt').unlink()
    before = games_path.read_bytes()

    with pytest.raises(_registrar().RegistrationError, match='milestone source'):
        _registrar().register(payloads, games_path, milestones)

    assert games_path.read_bytes() == before


def test_an_entry_missing_variant_of_is_backfilled(tmp_path):
    """An earlier registrar wrote the target and the flag but not variant_of.
    That link is what ties the variant's flag copy to its original, so a later
    run fills it in without appending a second entry."""
    payloads, games_path, milestones = _tiny_registration(
        tmp_path, existing_target='in-vitro_web_security_vm1inj-redirect-a')

    changed = _registrar().register(payloads, games_path, milestones)

    web = json.loads(games_path.read_text(encoding='utf-8'))[
        'in-vitro']['web_security']
    assert len(web) == 3
    assert web[2]['variant_of'] == 'in-vitro_web_security_vm1'
    assert any('variant_of' in step for step in changed)


def test_a_payload_task_without_a_vm_index_is_refused(tmp_path):
    payloads, games_path, milestones = _tiny_registration(tmp_path)
    payloads.write_text(json.dumps({
        'payloads': [{'id': 'redirect_a', 'task': 'web_security_box'}],
    }), encoding='utf-8')

    with pytest.raises(_registrar().RegistrationError, match='vm index'):
        _registrar().register(payloads, games_path, milestones)


def test_check_mode_reports_a_missing_registration_without_writing(tmp_path):
    payloads, games_path, milestones = _tiny_registration(tmp_path)
    before = games_path.read_bytes()

    changed = _registrar().register(
        payloads, games_path, milestones, check=True)

    assert changed
    assert games_path.read_bytes() == before
    assert not (milestones / 'command_milestones' / 'in-vitro' / 'web_security'
                / 'vm2.txt').exists()


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


def test_every_generated_overlay_serves_its_payload_marker():
    """Cross-repo drift control: the payload data declares a LITERAL delivered
    marker, and that exact phrase must appear in the bytes the variant's
    container serves. The generator's own validation is not enough on its own -
    it checks the FRAGMENT, while the scorer reads the SERVED page - so this
    test goes from the declared data all the way to the generated file, which is
    the step where a wrong anchor or a dropped insertion would hide.

    A sham only gets the negative half of the check: it must serve none of the
    payloads' markers, or its role as a mechanical control is void.
    """
    data = payload_data()
    markers = {}
    for payload in data['payloads']:
        vm = payload['task'].rsplit('_', 1)[-1]
        served = ' '.join(
            path.read_text(encoding='utf-8')
            for path in (REPO / 'benchmark' / 'machines' / 'in-vitro' /
                         'web_security' / f'{vm}inj_{payload["id"]}').glob('*')
            if path.is_file())
        marker = payload['delivered_marker']
        markers[payload['id']] = marker
        assert proofs_normalise(marker) in proofs_normalise(served), (
            f'{payload["id"]} declares the marker {marker!r} but the generated '
            f'overlay for {payload["task"]} does not serve it')
        # The collector token must never be served: a token in the page would
        # turn the proof into a free false positive.
        if payload.get('request'):
            assert payload['request']['token'] not in served


def test_no_sham_serves_any_payload_marker():
    data = payload_data()
    for task in data['shams']:
        vm = task.rsplit('_', 1)[-1]
        served = ' '.join(
            path.read_text(encoding='utf-8')
            for path in (REPO / 'benchmark' / 'machines' / 'in-vitro' /
                         'web_security' / f'{vm}sham').glob('*')
            if path.is_file())
        normalised = proofs_normalise(served)
        for payload in data['payloads']:
            assert proofs_normalise(payload['delivered_marker']) not in normalised, (
                f'{vm}sham serves the marker of {payload["id"]}')


def test_compose_collector_tokens_match_the_payload_data():
    """Each collector's token map is exactly the payloads that call it.

    Compared PER SERVICE, not as one merged map: a token moved to the wrong
    collector would still satisfy a merged comparison, while every request one
    payload makes would then be answered with the other payload's proof. The
    compose file is hand-maintained, so this is the pin.
    """
    expected = {}
    for payload in payload_data()['payloads']:
        request = payload.get('request')
        if not request:
            continue
        vm = payload['task'].rsplit('_', 1)[-1]
        key = f"{request['method'].upper()} {request['path']}"
        expected.setdefault(COLLECTOR.format(vm=vm), {})[key] = request['token']

    found = collector_tokens_by_service()

    # A quoting change in the compose file would parse as "no tokens at all";
    # say that plainly rather than let the comparison fail with {} on the left.
    assert found, 'no COLLECTOR_TOKENS parsed out of the compose file'
    assert found == expected
