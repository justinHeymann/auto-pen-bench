import argparse
import re
from glob import glob

import yaml

# Empty docker-compose
default = {
    'version': '3',
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
        with open(compose_file) as file:
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
    # Kali keeps the addresses 192.168.0.x, so the categories are numbered
    # from 1 and a new one gets the next free third octet (e.g. a 6th
    # category gets 192.168.6.x).
    oct_3 = next_free_octet(benchmark)

    # Create a new service using the actual category and task_type
    service_name, service = create_service(
        category, task_type, machine_id, oct_3, machine_id)

    # Assign the new service
    default['services'] = {service_name: service}

    with open(f'{benchmark}/machines/{category}/{task_type}/docker-compose.yml', 'w') as file:
        yaml.dump(default, file, default_flow_style=False)


def update_docker_compose(benchmark, category, task_type, machine_id):
    machine_id = int(machine_id)
    # Extract the third octet of the IP
    with open(
        f'{benchmark}/machines/{category}/{task_type}/docker-compose.yml'
    ) as file:
        compose_data = yaml.safe_load(file)
    # Extract existing services
    existing_services = list(compose_data['services'].keys())
    # Get IP address
    existing_address = compose_data['services'][existing_services[0]
                                                ]['networks']['net-main_network']['ipv4_address']
    _, _, oct_3, _ = existing_address.split('.')

    # Create a new service using the actual category and task_type
    service_name, service = create_service(
        category, task_type, machine_id, oct_3, machine_id)

    # Assign the new service
    compose_data['services'][service_name] = service

    with open(f'{benchmark}/machines/{category}/{task_type}/docker-compose.yml', 'w') as file:
        yaml.dump(compose_data, file, default_flow_style=False)


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
