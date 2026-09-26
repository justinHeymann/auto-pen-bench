"""The central network layout, and the artefacts that must follow it.

``autopenbench/network.py`` is the one place an address is defined; these
tests pin the two things that make that real: the layout is self-consistent
and overridable, and nothing in the benchmark hard-codes an address that the
layout does not contain.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys

import pytest

from autopenbench.network import (
    BRIDGE_SUBNET,
    CATEGORY_OCTETS,
    KALI_IP,
    KALI_OCTET,
    PREFIX,
    TARGET_SUBNETS,
    compose_env,
    find_octets,
    octet_var,
    target_ip,
    target_subnet,
)
from support import repo_root, resolve_compose

BRIDGE = ipaddress.ip_network(BRIDGE_SUBNET)
KALI_ADDRESS = ipaddress.ip_address(KALI_IP)
TARGET_NETWORKS = {
    category: ipaddress.ip_network(subnet)
    for category, subnet in TARGET_SUBNETS.items()
}

# Addresses the benchmark names but deliberately does not own: the host's own
# libvirt bridge, which the big-network tasks tell the agent to ignore. It is a
# property of the machine running the benchmark, not of the layout, so it does
# not move with BENCHMARK_PREFIX.
EXTERNAL_ADDRESSES = {'192.168.122.1'}

ADDRESS_RE = re.compile(re.escape(PREFIX) + r'\.\d+\.\d+')
CIDR_RE = re.compile(r'\d+\.\d+\.\d+\.\d+/\d+')


def _addresses(text: str):
    return ADDRESS_RE.findall(text)


def _is_in_layout(address: str) -> bool:
    """True when ``address`` belongs to the configured layout."""
    if address in EXTERNAL_ADDRESSES:
        return True
    ip = ipaddress.ip_address(address)
    if ip == KALI_ADDRESS:
        return True
    # The network address of the bridge itself, named by the tasks that ask
    # the agent to sweep a whole /16.
    if ip == BRIDGE.network_address:
        return True
    return any(ip in subnet for subnet in TARGET_NETWORKS.values())


# --- The layout -------------------------------------------------------------


def test_every_category_owns_a_distinct_subnet():
    """A category that shared a /24 with another would hide its neighbour's
    machines from a scan of its own."""
    octets = list(CATEGORY_OCTETS.values())

    assert len(set(octets)) == len(octets)
    assert KALI_OCTET not in octets
    assert set(TARGET_SUBNETS) == set(CATEGORY_OCTETS)


def test_target_ip_is_inside_its_category_subnet():
    for category, subnet in TARGET_SUBNETS.items():
        assert ipaddress.ip_address(target_ip(category, 3)) in (
            ipaddress.ip_network(subnet))
        assert target_subnet(category) == subnet


def test_the_controller_is_on_the_bridge_and_off_every_target_subnet():
    """Traffic reaches Kali through the host, targets only through Kali; a
    target on the controller's own address would break both."""
    assert KALI_ADDRESS in BRIDGE
    assert all(KALI_ADDRESS not in subnet for subnet in TARGET_NETWORKS.values())


def test_compose_env_reports_the_resolved_layout():
    env = compose_env()

    assert env['KALI_IP'] == KALI_IP
    assert env['BENCHMARK_PREFIX'] == PREFIX
    for category, octet in CATEGORY_OCTETS.items():
        assert env[octet_var(category)] == str(octet)


@pytest.mark.parametrize('override', [
    # A category cannot take the controller's /24 ...
    {'ACCESS_CONTROL_OCTET': str(KALI_OCTET)},
    # ... and two categories cannot share one.
    {'WEB_SECURITY_OCTET': '240'},
    # An octet has to be an octet.
    {'CVE_OCTET': '300'},
])
def test_a_colliding_layout_is_rejected(override):
    """Checked where it is cheap, and before anything is started.

    Run in a subprocess: reloading the module in-process would rebind the
    layout every other test module has already imported.
    """
    env = {**os.environ, **override}

    result = subprocess.run(
        [sys.executable, '-c', 'import autopenbench.network'],
        env=env, capture_output=True, text=True, cwd=repo_root(),
    )

    assert result.returncode != 0
    assert 'ValueError' in result.stderr


def test_a_bad_prefix_is_rejected():
    env = {**os.environ, 'BENCHMARK_PREFIX': '192.168.1'}

    result = subprocess.run(
        [sys.executable, '-c', 'import autopenbench.network'],
        env=env, capture_output=True, text=True, cwd=repo_root(),
    )

    assert result.returncode != 0
    assert 'BENCHMARK_PREFIX' in result.stderr


def test_the_layout_can_be_moved_by_the_environment():
    """The whole point of the module: one variable moves the benchmark."""
    env = {
        **os.environ,
        'BENCHMARK_PREFIX': '10.99',
        'KALI_IP': '10.99.7.9',
        'ACCESS_CONTROL_OCTET': '7',
    }
    probe = (
        'from autopenbench.network import KALI_IP, target_subnet;'
        'print(KALI_IP, target_subnet("access_control"))'
    )

    result = subprocess.run(
        [sys.executable, '-c', probe],
        env=env, capture_output=True, text=True, cwd=repo_root(),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ['10.99.7.9', '10.99.7.0/24']


def test_octet_re_reads_both_spellings_of_an_address():
    """The generator numbers a new category by reading existing files, which
    may be parameterised (today) or literal (an older revision)."""
    assert find_octets(f'{PREFIX}.241.5') == [241]
    assert find_octets(
        '${BENCHMARK_PREFIX:-192.168}.${WEB_SECURITY_OCTET:-241}.5'
    ) == [241]
    assert find_octets(f'{PREFIX}.242.0 {PREFIX}.242.250') == [242, 242]


# --- The artefacts ----------------------------------------------------------


def test_compose_files_are_parameterised_and_resolve_into_the_layout():
    """A compose file must not freeze an address, or an override would move
    the harness but not the containers."""
    machines = repo_root() / 'benchmark' / 'machines'
    compose_files = sorted(machines.rglob('docker-compose.yml'))
    assert compose_files

    for compose_file in compose_files:
        text = compose_file.read_text(encoding='utf-8')
        for raw in re.findall(r'ipv4_address:\s*(\S+)', text):
            assert raw.startswith('${'), (
                f'{compose_file} pins an address: {raw}')
            address = resolve_compose(raw)
            assert _is_in_layout(address), (
                f'{compose_file} resolves to {address}, which is outside the '
                'layout')
        for raw in re.findall(r'subnet:\s*(\S+)', text):
            assert ipaddress.ip_network(resolve_compose(raw)) == BRIDGE, (
                f'{compose_file} declares {raw}, which is not the bridge')


def test_the_startup_scripts_name_the_layout():
    """The scripts that prepare Kali talk about the controller by name."""
    scripts = repo_root() / 'setup'
    for script in sorted(scripts.rglob('*.sh')):
        for address in _addresses(script.read_text(encoding='utf-8')):
            assert _is_in_layout(address), f'{script}: {address}'


def test_no_benchmark_content_address_is_outside_the_layout():
    """The task texts, milestones and solutions name addresses literally.

    They are benchmark *content*, not configuration, so they are not
    parameterised -- this test is what turns "the range moved and a file was
    forgotten" into a failure instead of a run that cannot find its target.
    """
    root = repo_root()
    content = [root / 'data' / 'games.json']
    content += sorted((root / 'benchmark' / 'milestones').rglob('*.txt'))
    content += sorted((root / 'benchmark' / 'solutions').rglob('*.txt'))

    stale = {
        str(path.relative_to(root)): sorted(
            {address for address in _addresses(path.read_text(encoding='utf-8'))
             if not _is_in_layout(address)}
        )
        for path in content
    }
    stale = {path: found for path, found in stale.items() if found}

    assert not stale, (
        'These files name addresses the layout does not contain; re-run the '
        f'remap or fix the layout: {stale}'
    )


def test_every_task_names_its_own_category_subnet():
    """The task text is what the agent reads to find its target."""
    games = json.loads(
        (repo_root() / 'data' / 'games.json').read_text(encoding='utf-8'))

    for level, categories in games.items():
        for category, entries in categories.items():
            allowed = {target_subnet(category), BRIDGE_SUBNET}
            for index, entry in enumerate(entries):
                for cidr in CIDR_RE.findall(entry['task']):
                    assert cidr in allowed, (
                        f'{level}/{category}/vm{index} points the agent at '
                        f'{cidr}, which is not {sorted(allowed)}')
