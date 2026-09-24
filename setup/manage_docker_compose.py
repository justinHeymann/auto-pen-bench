import argparse
import os
import re
from glob import glob

import yaml


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
                'ipam': {'config': [{'subnet': '192.168.0.0/16'}]},
            },
        },
    }

# Addresses look like `ipv4_address: 192.168.3.5`: the third octet identifies
# the category, the fourth the machine inside it.
IPV4_RE = re.compile(r'192\.168\.(\d+)\.\d+')


def next_free_octet(benchmark):
    """Third octet of the next category: one above the highest one in use.

    What counts is the addresses of the existing compose files, not the
    directories on disk: a stray or half-created directory would otherwise
    shift the numbering onto an octet another category already uses.
    """
    in_use = set()
    for compose_file in glob(f'{benchmark}/machines/*/*/docker-compose.yml'):
        with open(compose_file, encoding='utf-8') as file:
            in_use.update(
                int(octet) for octet in IPV4_RE.findall(file.read())
            )
    return max(in_use, default=0) + 1


def create_service(category, task_type, machine_id, oct3, oct4):
    service_name = f'{category}_{task_type}_vm{machine_id}'
    service = {
        'build': f'./{category}/{task_type}/vm{machine_id}',
        'command': 'bash -c "tail -f /dev/null"',
        'container_name': service_name,
        'image': service_name,
        'init': True,
        'restart': 'unless-stopped',
        'security_opt': ['label:disable'],
        'tty': True,
        'volumes': [f'./{category}/{task_type}/vm{machine_id}/flag.txt:/root/flag.txt'],
        'networks': {'net-main_network': {'ipv4_address': f'192.168.{oct3}.{oct4}'}}
    }
    return service_name, service


def generate_docker_compose(benchmark, category, task_type, machine_id):
    machine_id = int(machine_id)
    compose_path = os.path.join(
        benchmark, 'machines', category, task_type, 'docker-compose.yml')
    if os.path.exists(compose_path):
        # Creating a category that already has one would silently drop every
        # machine the existing file describes.
        raise SystemExit(
            f'{compose_path} already exists; use "update" to add a machine '
            'to it.')

    # Kali keeps the addresses 192.168.0.x, so the categories are numbered
    # from 1 and a new one gets the next free third octet (e.g. a 6th
    # category gets 192.168.6.x).
    oct_3 = next_free_octet(benchmark)

    # Create a new service using the actual category and task_type
    service_name, service = create_service(
        category, task_type, machine_id, oct_3, machine_id)

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


def update_docker_compose(benchmark, category, task_type, machine_id):
    machine_id = int(machine_id)
    compose_path = os.path.join(
        benchmark, 'machines', category, task_type, 'docker-compose.yml')
    with open(compose_path, encoding='utf-8') as file:
        raw = file.read()
    # The category's third octet comes from the addresses already in the
    # file -- any of them, not just whatever service happens to be first.
    octets = IPV4_RE.findall(raw)
    if not octets:
        raise SystemExit(
            f'{compose_path} has no 192.168.x.y addresses; cannot derive '
            'the category octet.')
    oct_3 = octets[0]

    # Create a new service using the actual category and task_type
    service_name, service = create_service(
        category, task_type, machine_id, oct_3, machine_id)

    with open(compose_path, 'w', encoding='utf-8') as file:
        file.write(_insert_service(
            raw, _service_block(service_name, service)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generate a Docker Compose file.')
    parser.add_argument('function', type=str,
                        help='Create or update docker-compose')
    parser.add_argument('benchmark', type=str, help='The benchmark directory')
    parser.add_argument('category', type=str,
                        help='The category of the service')
    parser.add_argument('task_type', type=str,
                        help='The task type of the service')
    parser.add_argument('machine_id', type=str, help='The ID of the machine')

    args = parser.parse_args()

    # Create a new docker-compose
    if args.function == 'create':
        generate_docker_compose(args.benchmark, args.category,
                                args.task_type, args.machine_id)

    # Update a new docker-compose
    elif args.function == 'update':
        update_docker_compose(args.benchmark, args.category,
                              args.task_type, args.machine_id)
