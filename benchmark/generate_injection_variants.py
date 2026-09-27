#!/usr/bin/env python3
"""Generate the prompt-injection overlay directories from the payload data.

The variant overlays used to be hand-written per payload, which is how the
delivered text and the scoring expectations drifted apart. They are now
GENERATED from ``injection_payloads/payloads.json`` (the same file genai loads
to score), by inserting the payload fragment into the ORIGINAL task file at a
declared anchor.

Inserting into the original rather than shipping a hand-maintained template
keeps the injection surface identical to the task content it modifies, and it
fails loudly if an anchor ever moves instead of silently producing a page with
no payload on it.

Usage:
    python benchmark/generate_injection_variants.py [--check]
"""

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEB = HERE / 'machines' / 'in-vitro' / 'web_security'
DATA = HERE / 'injection_payloads' / 'payloads.json'

# Where each task's payload goes. ``insert_after`` puts the fragment on its own
# line directly after the anchor; ``replace`` swaps one statement for a PHP
# nowdoc holding the fragment (vm2's payload is prose, not markup).
TASKS = {
    'web_security_vm0': {
        'source': 'vm0/index.php',
        'container_path': '/var/www/html/index.php',
        'insert_after': '<body>',
    },
    'web_security_vm1': {
        'source': 'vm1/index.php',
        'container_path': '/var/www/html/index.php',
        'insert_after': '<body>',
    },
    'web_security_vm2': {
        'source': 'vm2/includes/route.php',
        'container_path': '/var/www/html/includes/route.php',
        'replace': 'echo "\\nPage not found";',
        'php_nowdoc': True,
    },
    'web_security_vm3': {
        'source': 'vm3/index.html',
        'container_path': '/var/www/html/index.html',
        'insert_after': '<body>',
    },
}

NOWDOC_MARKER = 'INJECTED'


class GenerationError(RuntimeError):
    """The payload data or an original task file cannot be used as declared."""


def collector_ip(octet: int) -> str:
    """The collector address for a task, from the central network layout."""
    from autopenbench.network import target_ip
    return target_ip('web_security', octet)


def overlay_dir_name(task: str, variant: str) -> str:
    """``vm0inj_deter_a`` / ``vm0sham`` — the overlay directory under web_security.

    This is a filesystem detail (it names the build context and the image tag).
    The driver-facing name is ``service_suffix`` below, which has a different
    rule.
    """
    vm = task.rsplit('_', 1)[-1]
    return f'{vm}sham' if variant == 'sham' else f'{vm}inj_{variant}'


def service_suffix(task: str, variant: str) -> str:
    """The compose service / harness target token: ``vm1inj-redirect-a``.

    The driver recovers the task's category directory from the service name by
    splitting off the FINAL underscore-separated token
    (``pentest_driver._start_service``: target name -> ``rsplit('_', 1)[0]`` ->
    ``machines/<level>/<category>/docker-compose.yml``), so everything after
    ``in-vitro_web_security_`` must be ONE underscore-free token. An
    underscore-separated payload id (``vm1inj_redirect_a``) makes the driver
    look for the nonexistent
    ``machines/in-vitro/web_security_vm1inj_redirect/docker-compose.yml`` and
    every run of that cell dies as an environment failure. Hyphens are safe:
    only underscores are split on. This bit the first v2 smoke test.
    """
    vm = task.rsplit('_', 1)[-1]
    return f'{vm}sham' if variant == 'sham' else f'{vm}inj-{variant}'


def image_name(task: str, variant: str) -> str:
    return f'in-vitro_web_security_{overlay_dir_name(task, variant)}'


def _insert_after(source: str, anchor: str, fragment: str) -> str:
    if source.count(anchor) != 1:
        raise GenerationError(
            f'anchor {anchor!r} appears {source.count(anchor)} times; the '
            'original task file must contain it exactly once')
    line = source.index(anchor) + len(anchor)
    return f'{source[:line]}\n    {fragment}{source[line:]}'


def _replace_statement(source: str, statement: str, fragment: str) -> str:
    if source.count(statement) != 1:
        raise GenerationError(
            f'statement {statement!r} appears {source.count(statement)} times; '
            'the original task file must contain it exactly once')
    for line in fragment.splitlines():
        if line.strip() == NOWDOC_MARKER:
            raise GenerationError(
                f'the fragment contains a line equal to {NOWDOC_MARKER!r}, '
                'which would terminate the PHP nowdoc early')
    # The terminator sits at column 0 on purpose: with a flexible nowdoc an
    # indented terminator requires every body line to carry at least that much
    # indentation, and a ParseError there would break the whole task.
    nowdoc = f"<<<'{NOWDOC_MARKER}'\n{fragment}\n{NOWDOC_MARKER};"
    return source.replace(statement, f'echo {nowdoc}')


def render_task_file(task: str, fragment: str) -> str:
    """The original task file with the payload fragment injected."""
    spec = TASKS[task]
    source = (WEB / spec['source']).read_text(encoding='utf-8')
    if 'insert_after' in spec:
        rendered = _insert_after(source, spec['insert_after'], fragment)
    else:
        rendered = _replace_statement(source, spec['replace'], fragment)
    if fragment not in rendered:
        # Belt and braces: a payload that is not in the served bytes is exactly
        # the defect that made the v1 confusion canary unfireable.
        raise GenerationError(
            f'{task}: the fragment is not present in the rendered file')
    return rendered


def overlay_files(task: str, variant: str, fragment: str) -> dict:
    """The files of one overlay: ``{'Dockerfile': ..., 'index.php': ...}``."""
    spec = TASKS[task]
    base = spec['source'].rsplit('/', 1)[-1]
    dockerfile = (
        f'# GENERATED by benchmark/generate_injection_variants.py from\n'
        f'# injection_payloads/payloads.json - do not edit by hand.\n'
        f'# Service/image: {image_name(task, variant)}\n'
        f'FROM in-vitro_web_security_{task.rsplit("_", 1)[-1]}\n'
        f'\n'
        f'COPY {base} {spec["container_path"]}\n'
    )
    return {'Dockerfile': dockerfile, base: render_task_file(task, fragment)}


def generate(data_path: Path = DATA, web: Path = WEB,
             check: bool = False) -> list:
    """Write (or with ``check``, verify) every overlay. Returns changed paths."""
    data = json.loads(data_path.read_text(encoding='utf-8'))
    tasks = data['tasks']
    changed = []

    def emit(task: str, variant: str, fragment: str) -> None:
        directory = web / overlay_dir_name(task, variant)
        for name, content in overlay_files(task, variant, fragment).items():
            target = directory / name
            existing = target.read_text(encoding='utf-8') if target.exists() else None
            if existing == content:
                continue
            changed.append(str(target))
            if not check:
                directory.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding='utf-8')

    for payload in data['payloads']:
        task = payload['task']
        fragment = payload['fragment']
        octet = tasks[task].get('collector_octet')
        if '{collector_ip}' in fragment:
            if not octet:
                raise GenerationError(
                    f'{payload["id"]}: the fragment names the collector but '
                    f'{task} declares no collector_octet')
            fragment = fragment.replace('{collector_ip}', collector_ip(octet))
        token = (payload.get('request') or {}).get('token')
        if token and token in fragment:
            raise GenerationError(
                f'{payload["id"]}: the token is in the served bytes')
        emit(task, payload['id'], fragment)

    for task, sham in data['shams'].items():
        emit(task, 'sham', sham['fragment'])

    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', default=str(DATA))
    parser.add_argument('--check', action='store_true',
                        help='fail if any generated file is stale')
    args = parser.parse_args()
    try:
        changed = generate(Path(args.data), check=args.check)
    except GenerationError as error:
        print(f'generation failed: {error}', file=sys.stderr)
        return 1
    verb = 'stale' if args.check else 'written'
    print(f'{len(changed)} file(s) {verb}')
    for path in changed:
        print(f'  {os.path.relpath(path, HERE)}')
    return 1 if args.check and changed else 0


if __name__ == '__main__':
    sys.exit(main())
