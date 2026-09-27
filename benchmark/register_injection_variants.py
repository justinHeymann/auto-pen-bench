#!/usr/bin/env python3
"""Register the v2 injection payload variants as harness tasks.

The harness selects a task by **array index** into
``games.json[level][category]`` (that index IS ``vm_id``) and reads its
milestone files as ``milestones/{command,stage}_milestones/<level>/<category>/
vm<N>.txt`` by the same index. So one payload variant needs four things to line
up, or it cannot run at all:

1. an appended ``games.json`` entry (task text, vulnerability and flag copied
   from the original task, so only the container differs),
2. ``vm<N>.txt`` in both milestone trees,
3. a compose service (``generate_injection_variants.py`` + the compose file),
4. a ``SIDECAR_SERVICES`` entry (``tests/test_injection_variants.py``).

This script does 1 and 2 from ``injection_payloads/payloads.json``, append-only
and idempotent: existing indices keep their meaning, so every already-recorded
run's ``vm_id`` stays valid. It is a *generator* in the same sense as the
overlay one -- the payload data is the source of truth, these are derived.

Usage:
    python benchmark/register_injection_variants.py [--check]
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PAYLOAD_DATA = HERE / 'injection_payloads' / 'payloads.json'
GAMES = REPO / 'data' / 'games.json'
MILESTONES = HERE / 'milestones'
LEVEL = 'in-vitro'
CATEGORY = 'web_security'
KINDS = ('command_milestones', 'stage_milestones')


class RegistrationError(RuntimeError):
    """The payload data and the harness task tables disagree."""


def target_of(payload: dict) -> str:
    """The harness target / compose service name for a payload cell.

    Hyphens, not underscores, inside the variant suffix: the driver recovers
    the category directory by dropping the target's final underscore-separated
    token, so the suffix has to be a single token (see
    ``generate_injection_variants.service_suffix``).
    """
    vm = payload['task'].rsplit('_', 1)[-1]
    return f'in-vitro_web_security_{vm}inj-{payload["id"].replace("_", "-")}'


def original_index(payload: dict) -> int:
    """Index of the original task whose text/flag this variant reuses."""
    vm = payload['task'].rsplit('_', 1)[-1]
    if not vm.startswith('vm') or not vm[2:].isdigit():
        raise RegistrationError(f'cannot read a vm index from {payload["task"]!r}')
    return int(vm[2:])


def _milestone_paths(index: int, milestones: Path = MILESTONES):
    suffix = f'{LEVEL}/{CATEGORY}/vm{index}.txt'
    return [milestones / kind / suffix for kind in KINDS]


def register(payload_data: Path = PAYLOAD_DATA, games_path: Path = GAMES,
             milestones: Path = MILESTONES, check: bool = False) -> list:
    """Append the entries and copy the milestone files. Returns changed paths."""
    data = json.loads(payload_data.read_text(encoding='utf-8'))
    games = json.loads(games_path.read_text(encoding='utf-8'))
    entries = games[LEVEL][CATEGORY]
    changed = []

    for payload in data['payloads']:
        target = target_of(payload)
        source_index = original_index(payload)
        vm = payload['task'].rsplit('_', 1)[-1]
        existing = next(
            (i for i, entry in enumerate(entries) if entry['target'] == target),
            None)
        if existing is None:
            # A name from an earlier naming scheme is corrected IN PLACE, never
            # re-appended: these entries sit at the indices recorded runs use as
            # vm_id, so appending would leave two entries for one task and
            # silently renumber nothing but the meaning. (v2 first shipped
            # `..._vm1inj_redirect_a`; the driver needs a single underscore-free
            # suffix token.)
            stale = f'in-vitro_web_security_{vm}inj_'
            existing = next(
                (i for i, entry in enumerate(entries)
                 if entry['target'].startswith(stale)), None)
            if existing is not None:
                # Same guard as the in-place path below: the variant mounts its
                # original's flag file, so a mismatched flag means the entry was
                # not written by this script and must not be silently adopted.
                if entries[existing]['flag'] != entries[source_index]['flag']:
                    raise RegistrationError(
                        f'{target}: the entry it replaces carries flag '
                        f'{entries[existing]["flag"]!r}, not its original '
                        f'{entries[source_index]["flag"]!r}')
                entries[existing]['target'] = target
                changed.append(f'{games_path}: ~[{existing}] {target}')
                index = existing
            else:
                # Append-only: the new index must not disturb any existing
                # vm_id.
                original = entries[source_index]
                new_index = len(entries)
                entries.append({
                    'task': original['task'],
                    'vulnerability': original['vulnerability'],
                    'flag': original['flag'],
                    'target': target,
                })
                changed.append(f'{games_path}: +[{new_index}] {target}')
                index = new_index
        else:
            index = existing
            if entries[index]['flag'] != entries[source_index]['flag']:
                raise RegistrationError(
                    f'{target}: flag {entries[index]["flag"]!r} differs from its '
                    f'original {entries[source_index]["flag"]!r}; the variant '
                    'mounts the original flag file, so they must match')

        for kind in KINDS:
            destination = _milestone_paths(index, milestones)[
                KINDS.index(kind)]
            source = _milestone_paths(source_index, milestones)[
                KINDS.index(kind)]
            if destination.exists():
                continue
            if not source.exists():
                raise RegistrationError(
                    f'{target}: milestone source {source} is missing')
            changed.append(str(destination))
            if not check:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)

    if changed and not check:
        games_path.write_text(
            json.dumps(games, indent=2) + '\n', encoding='utf-8')

    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payloads', default=str(PAYLOAD_DATA))
    parser.add_argument('--games', default=str(GAMES))
    parser.add_argument('--milestones', default=str(MILESTONES))
    parser.add_argument('--check', action='store_true',
                        help='fail if any registration is missing')
    args = parser.parse_args()
    try:
        changed = register(Path(args.payloads), Path(args.games),
                           Path(args.milestones), check=args.check)
    except (OSError, ValueError, RegistrationError) as error:
        print(f'registration failed: {error}', file=sys.stderr)
        return 1
    verb = 'missing' if args.check else 'registered'
    print(f'{len(changed)} registration step(s) {verb}')
    for path in changed:
        print(f'  {os.path.relpath(path, REPO)}')
    return 1 if args.check and changed else 0


if __name__ == '__main__':
    sys.exit(main())
