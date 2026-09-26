"""The benchmark's network layout: the single source of truth for addresses.

Three knobs define every address of the benchmark:

``BENCHMARK_PREFIX``
    The first two octets, e.g. ``192.168``. The internal bridge every machine
    lives on is this prefix plus ``.0.0/16``.
``BENCHMARK_KALI_OCTET`` / ``BENCHMARK_KALI_HOST_OCTET`` / ``KALI_IP``
    The Kali controller's own /24 and its address inside it.
``<CATEGORY>_OCTET``
    One third octet per category, e.g. ``WEB_SECURITY_OCTET``; a machine of
    that category is ``<prefix>.<octet>.<machine id>``.

Each knob has the value the benchmark ships with as its default and can be
overridden through the environment (an exported variable or the benchmark's
``.env``). :func:`compose_env` exports the *resolved* values into every
``docker compose`` the driver runs, and the compose files declare the same
variables as ``${VAR:-default}``, so one override reaches the containers, a
hand-run ``docker compose`` and the harness at once.

The defaults stay out of the /24s consumer routers hand out
(``192.168.0.0/24``, ``192.168.1.0/24``, ``192.168.2.0/24``,
``192.168.178.0/24``): a host LAN on one of them installs a more specific
route that beats the bridge's /16, after which the host cannot reach the
container at all and every run fails in ``reset()`` with
``NoValidConnectionsError``.

This module is deliberately dependency-free (no dotenv, no ``AUTOPENBENCH``
lookup) so both the benchmark package and the paper harness can import it
without side effects.
"""
import os
import re

# First two octets of every benchmark address, i.e. the bridge's /16 prefix.
PREFIX = os.environ.get('BENCHMARK_PREFIX', '192.168')

# The internal bridge that holds the controller and every target. Derived from
# the prefix rather than overridden separately, so the bridge can never end up
# outside the range the addresses are taken from.
BRIDGE_SUBNET = f'{PREFIX}.0.0/16'

# Third octet of the controller's own /24. Reserved: a category that took it
# would put a target on the machine the agent runs its commands from.
KALI_OCTET = int(os.environ.get('BENCHMARK_KALI_OCTET', '254'))

# Host part of the controller's address.
KALI_HOST_OCTET = int(os.environ.get('BENCHMARK_KALI_HOST_OCTET', '5'))

# Controller machine: the harness reaches every other machine through it and
# serves the interactive shell the agent works in. The full address can be
# overridden directly (``KALI_IP``, the knob the compose file names) instead
# of going through the two octets above.
KALI_IP = os.environ.get(
    'KALI_IP', f'{PREFIX}.{KALI_OCTET}.{KALI_HOST_OCTET}')

# Third octet a category is first given. A new category is numbered above the
# highest one in use, starting here.
FIRST_CATEGORY_OCTET = int(
    os.environ.get('BENCHMARK_FIRST_CATEGORY_OCTET', '240'))

# One /24 per category, keyed by the directory name under
# ``benchmark/machines/<level>/``. The controller keeps its own /24, so a scan
# of a category never turns up the machine the agent is working from.
CATEGORY_OCTETS = {
    'access_control': int(os.environ.get('ACCESS_CONTROL_OCTET', '240')),
    'web_security': int(os.environ.get('WEB_SECURITY_OCTET', '241')),
    'network_security': int(os.environ.get('NETWORK_SECURITY_OCTET', '242')),
    'cryptography': int(os.environ.get('CRYPTOGRAPHY_OCTET', '243')),
    'cve': int(os.environ.get('CVE_OCTET', '244')),
}

# The /24 of each category, e.g. ``192.168.241.0/24``.
TARGET_SUBNETS = {
    category: f'{PREFIX}.{octet}.0/24'
    for category, octet in CATEGORY_OCTETS.items()
}

# Third octet of an address, in either the literal form (``192.168.241.5``)
# or the compose-interpolated one
# (``${BENCHMARK_PREFIX:-192.168}.${WEB_SECURITY_OCTET:-241}.5``). Reading
# back both forms lets ``setup/manage_docker_compose.py`` number a new
# category above the ones an existing file declares, whatever revision of the
# file it was written by.
OCTET_RE = re.compile(
    rf'(?:\$\{{[A-Z_]+_OCTET:-(\d+)\}}|{re.escape(PREFIX)}\.(\d+))\.'
)


def find_octets(text: str) -> list:
    """The third octets of every address of ``text``, in the order read."""
    return [
        int(octet)
        for match in OCTET_RE.finditer(text)
        for octet in match.groups()
        if octet is not None
    ]


def octet_var(category: str) -> str:
    """Environment variable that holds ``category``'s third octet."""
    return f'{category.upper()}_OCTET'


def target_subnet(category: str) -> str:
    """Return the /24 that holds one category's machines."""
    return TARGET_SUBNETS[category]


def target_ip(category: str, machine_id: int) -> str:
    """Return the address of one machine, e.g. ``target_ip('cve', 3)``."""
    prefix = target_subnet(category).rsplit('.', 1)[0]
    return f'{prefix}.{machine_id}'


def compose_env() -> dict:
    """The resolved layout as environment variables for ``docker compose``.

    Passing these to the compose subprocess makes the files' ``${VAR:-default}
    `` fall back to the central values rather than to their own defaults --
    which is what keeps a range change a one-line edit even when the value
    never reaches the shell that started the run.
    """
    env = {
        'KALI_IP': KALI_IP,
        'BENCHMARK_PREFIX': PREFIX,
    }
    env.update(
        {octet_var(category): str(octet)
         for category, octet in CATEGORY_OCTETS.items()}
    )
    return env


def _validate() -> None:
    """Reject a layout that would collide or be unaddressable.

    Checked at import so a typo in an override fails immediately with the
    variable's name, instead of as an unreachable container or a Docker error
    during ``reset()``.
    """
    if not re.fullmatch(r'(\d{1,3})\.(\d{1,3})', PREFIX):
        raise ValueError(
            'BENCHMARK_PREFIX must be two octets, e.g. 192.168; got '
            f'{PREFIX!r}'
        )
    for octet in PREFIX.split('.'):
        if int(octet) > 255:
            raise ValueError(
                f'BENCHMARK_PREFIX has an octet above 255: {PREFIX!r}'
            )
    octets = {
        'BENCHMARK_KALI_OCTET': KALI_OCTET,
        'BENCHMARK_KALI_HOST_OCTET': KALI_HOST_OCTET,
        'BENCHMARK_FIRST_CATEGORY_OCTET': FIRST_CATEGORY_OCTET,
        **{octet_var(name): value for name, value in CATEGORY_OCTETS.items()},
    }
    for name, value in octets.items():
        if not 0 <= value <= 255:
            raise ValueError(f'{name} must be an octet (0-255); got {value}')
    if KALI_OCTET in CATEGORY_OCTETS.values():
        raise ValueError(
            f'The controller already owns the .{KALI_OCTET}.0/24 '
            '(BENCHMARK_KALI_OCTET); a category cannot share it '
            f'(BENCHMARK_KALI_OCTET=254 default, categories: '
            f'{CATEGORY_OCTETS})'
        )
    duplicates = {
        octet for octet in CATEGORY_OCTETS.values()
        if list(CATEGORY_OCTETS.values()).count(octet) > 1
    }
    if duplicates:
        raise ValueError(
            'Every category needs its own /24; these octets are used twice: '
            f'{sorted(duplicates)}'
        )


_validate()
