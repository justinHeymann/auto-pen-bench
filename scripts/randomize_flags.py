#!/usr/bin/env python3
"""Randomize the per-VM CTF flags used by the benchmark.

Every flag is a plain text file *bind-mounted* into its container (see the
``volumes:`` entries in ``benchmark/machines/**/docker-compose.yml``), not
baked into a Docker image. That means a fresh random flag can be written to
the host-side file and picked up by the next ``docker compose up`` for that
VM without rebuilding any image.

This script:
  1. Finds each VM's flag file on disk from its ``target`` in
     ``data/games.json`` (e.g. "in-vitro_access_control_vm0").
  2. Generates a new random token of the same length/charset as the
     current flag.
  3. Replaces the old token with the new one in the flag file (some flag
     files are just the bare token, others embed it in boilerplate text,
     e.g. an ``/etc/motd`` banner or an SNMP config line) and updates
     ``data/games.json`` to match.

Entries whose current flag doesn't look like a simple random token are left
untouched, since those would need bespoke handling to regenerate safely.

Run this before a benchmark session to avoid reusing flags that may already
be memorized by a model from public benchmark data:

    python scripts/randomize_flags.py [--dry-run]
"""
import json
import re
import secrets
import string
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MACHINES_DIR = REPO_ROOT / 'benchmark' / 'machines'
GAMES_PATH = REPO_ROOT / 'data' / 'games.json'

# Only regenerate flags that already look like a plain random token.
SIMPLE_TOKEN_RE = re.compile(r'^[A-Za-z0-9]{8,64}$')
# e.g. "in-vitro_access_control_vm0" -> level, category, vmid
TARGET_RE = re.compile(r'^(in-vitro|real-world)_(.+)_(vm\d+[ab]?)$')
FLAG_FILENAMES = ('flag', 'flag.txt')


def find_flag_file(level: str, category: str, vmid: str) -> Path | None:
    """Locate the on-disk flag file for a VM, tolerating vm5 -> vm5a/vm5b."""
    for candidate_vmid in (vmid, vmid + 'a', vmid + 'b'):
        vm_dir = MACHINES_DIR / level / category / candidate_vmid
        for name in FLAG_FILENAMES:
            path = vm_dir / name
            if path.is_file():
                return path
    return None


def random_token(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def randomize(dry_run: bool = False) -> int:
    raw_games_text = GAMES_PATH.read_text()
    games = json.loads(raw_games_text)
    changed = 0
    skipped = 0
    new_games_text = raw_games_text

    for level, categories in games.items():
        for category, entries in categories.items():
            for entry in entries:
                target = entry['target']
                match = TARGET_RE.match(target)
                if not match:
                    print(f'[skip] {target}: unrecognized target format')
                    skipped += 1
                    continue

                _, parsed_category, vmid = match.groups()
                flag_path = find_flag_file(level, parsed_category, vmid)
                old_flag = entry['flag']

                if flag_path is None:
                    print(f'[skip] {target}: no flag file found on disk')
                    skipped += 1
                    continue
                if not SIMPLE_TOKEN_RE.match(old_flag):
                    print(f'[skip] {target}: flag is not a simple token, leaving untouched')
                    skipped += 1
                    continue

                raw_flag_file = flag_path.read_text()
                if raw_flag_file.count(old_flag) != 1:
                    print(f'[skip] {target}: flag not found exactly once in {flag_path}, leaving untouched')
                    skipped += 1
                    continue

                # games.json is hand-formatted (not indent-uniform JSON), so
                # it's edited as text below instead of via json.dumps, which
                # would reformat the whole file and bury the real change.
                old_kv = f'"flag":"{old_flag}"'
                new_flag = random_token(len(old_flag))
                new_kv = f'"flag":"{new_flag}"'
                if new_games_text.count(old_kv) != 1:
                    print(f'[skip] {target}: could not find {old_kv!r} exactly once in games.json, leaving untouched')
                    skipped += 1
                    continue

                relpath = flag_path.relative_to(REPO_ROOT)
                print(f'[ok]   {target}: {old_flag} -> {new_flag} ({relpath})')
                if not dry_run:
                    flag_path.write_text(raw_flag_file.replace(old_flag, new_flag))
                    new_games_text = new_games_text.replace(old_kv, new_kv, 1)
                changed += 1

    if not dry_run and changed:
        GAMES_PATH.write_text(new_games_text)

    print(f'\n{changed} flag(s) randomized, {skipped} skipped.'
          + (' (dry run, nothing written)' if dry_run else ''))
    return 0


if __name__ == '__main__':
    sys.exit(randomize(dry_run='--dry-run' in sys.argv))
