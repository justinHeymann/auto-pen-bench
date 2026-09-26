import argparse
import os
from glob import glob

import yaml

from autopenbench.network import (
    CATEGORY_OCTETS,
    FIRST_CATEGORY_OCTET,
    KALI_OCTET,
    PREFIX,
    find_octets,
    octet_var,
)

# The generator writes the same ``${VAR:-default}`` expression the checked-in
# compose files carry, never a resolved literal. A generated machine therefore
# follows the central layout (and any override of it) exactly like a
# hand-written one, and the spelling of an address stays in one file.
PREFIX_EXPR = f'${{BENCHMARK_PREFIX:-{PREFIX}}}'
SUBNET_EXPR = f'{PREFIX_EXPR}.0.0/16'


def address_expr(category: str, machine_id, octet=None) -> str:
    """One machine's ``ipv4_address``, as the compose file spells it.

    ``octet`` is the category's third octet; it defaults to the central
    layout's entry for ``category``, and a category that is not part of the
    layout yet is passed the octet :func:`next_free_octet` assigned it.
    """
    if octet is None:
        octet = CATEGORY_OCTETS[category]
    return (
        f'{PREFIX_EXPR}.'
        f'${{{octet_var(category)}:-{octet}}}.{int(machine_id)}'
    )


def empty_compose() -> dict:
    """A fresh skeleton for a category's docker-compose file.

    Built on every call: a module-level dict that ``generate_docker_compose``
    mutated would carry one call's service into the next file if the module
    were used twice in the same process. The obsolete top-level ``version``
    key is not written -- Compose v2 warns that it is ignored.
    """
    return {
        'networks': {
            'net-main_network': {
                'internal': True,
                'ipam': {'config': [{'subnet': SUBNET_EXPR}]},
            },
        },
    }


def next_free_octet(benchmark):
    """Third octet of the next category: one above the highest one in use.

    What counts is the layout plus the addresses of the existing compose
    files, not the directories on disk: a configured category whose file is
    not written yet, or a stray half-created directory, would otherwise shift
    the numbering onto an octet that is already taken. Kali's reserved octet
    is ignored so it can never be handed to a category.
    """
    in_use = set(CATEGORY_OCTETS.values())
    for compose_file in glob(f'{benchmark}/machines/*/*/docker-compose.yml'):
        with open(compose_file, encoding='utf-8') as file:
            in_use.update(find_octets(file.read()))
    in_use.discard(KALI_OCTET)
    return max(in_use, default=FIRST_CATEGORY_OCTET - 1) + 1


def category_octet(benchmark: str, category: str) -> int:
    """Third octet to give ``category``.

    An explicitly exported ``<CATEGORY>_OCTET`` wins, so a category added to
    the benchmark outside :mod:`autopenbench.network` can still be placed
    deliberately; otherwise the category takes the next free octet.
    """
    exported = os.environ.get(octet_var(category))
    if exported:
        return int(exported)
    return next_free_octet(benchmark)


def create_service(level, category, machine_id, oct3, oct4):
    service_name = f'{level}_{category}_vm{machine_id}'
    service = {
        'build': f'./{level}/{category}/vm{machine_id}',
        'command': 'bash -c "tail -f /dev/null"',
        'container_name': service_name,
        'image': service_name,
        'init': True,
        'restart': 'unless-stopped',
        'security_opt': ['label:disable'],
        'tty': True,
        'volumes': [f'./{level}/{category}/vm{machine_id}/flag.txt:/root/flag.txt'],
        'networks': {'net-main_network': {
            'ipv4_address': address_expr(category, oct4, oct3)
        }}
    }
    return service_name, service


def generate_docker_compose(benchmark, level, category, machine_id):
    machine_id = int(machine_id)
    compose_path = os.path.join(
        benchmark, 'machines', level, category, 'docker-compose.yml')
    if os.path.exists(compose_path):
        # Creating a category that already has one would silently drop every
        # machine the existing file describes.
        raise SystemExit(
            f'{compose_path} already exists; use "update" to add a machine '
            'to it.')

    # Kali keeps its reserved octet; categories start at FIRST_CATEGORY_OCTET
    # and a new one gets the next free third octet.
    oct_3 = category_octet(benchmark, category)

    service_name, service = create_service(
        level, category, machine_id, oct_3, machine_id)

    compose_data = empty_compose()
    compose_data['services'] = {service_name: service}

    with open(compose_path, 'w', encoding='utf-8') as file:
        yaml.dump(compose_data, file, default_flow_style=False)


def _service_block(service_name: str, service: dict) -> str:
    """One service as a compose file block, indented for the services mapping."""
    dumped = yaml.dump(
        {service_name: service}, default_flow_style=False, sort_keys=False
    )
    return '\n'.join(
        ('    ' + line) if line.strip() else line
        for line in dumped.splitlines()
    )


def _insert_service(compose_text: str, block: str) -> str:
    """Append ``block`` to the ``services:`` mapping of ``compose_text``.

    The block is inserted as text instead of re-serializing the document: these
    files are hand-written and their comments document each machine (the
    prompt-injection contract among them), so a yaml round-trip would silently
    delete all of it.
    """
    lines = compose_text.splitlines()
    start = next(
        (index for index, line in enumerate(lines)
         if line.startswith('services:')),
        None,
    )
    if start is None:
        raise SystemExit('the compose file has no "services:" section')
    # The service mapping ends at the next top-level key (usually `networks:`).
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index] and not lines[index][0].isspace():
            end = index
            break
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    merged = (
        lines[:start + 1] + lines[start + 1:end]
        + [''] + block.splitlines() + ['']
        + lines[end:]
    )
    return '\n'.join(merged) + '\n'


def update_docker_compose(benchmark, level, category, machine_id):
    machine_id = int(machine_id)
    compose_path = os.path.join(
        benchmark, 'machines', level, category, 'docker-compose.yml')
    with open(compose_path, encoding='utf-8') as file:
        raw = file.read()
    # The category's third octet comes from the addresses already in the
    # file -- any of them, not just whatever service happens to be first.
    octets = find_octets(raw)
    if not octets:
        raise SystemExit(
            f'{compose_path} has no {PREFIX}.x.y addresses; cannot derive '
            'the category octet.')
    oct_3 = octets[0]

    service_name, service = create_service(
        level, category, machine_id, oct_3, machine_id)

    with open(compose_path, 'w', encoding='utf-8') as file:
        file.write(_insert_service(
            raw, _service_block(service_name, service)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Create or update a category docker-compose.yml.')
    parser.add_argument('function', type=str,
                        help='create or update')
    parser.add_argument('benchmark', type=str, help='The benchmark directory')
    parser.add_argument('level', type=str,
                        help='The level of the service (e.g. in-vitro)')
    parser.add_argument('category', type=str,
                        help='The category of the service (e.g. web_security)')
    parser.add_argument('machine_id', type=str, help='The ID of the machine')

    args = parser.parse_args()

    if args.function == 'create':
        generate_docker_compose(args.benchmark, args.level, args.category,
                                args.machine_id)

    elif args.function == 'update':
        update_docker_compose(args.benchmark, args.level, args.category,
                              args.machine_id)
