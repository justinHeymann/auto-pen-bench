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

The prompt-injection variants (``benchmark/injection_payloads/``) are
*derived* tasks: ``in-vitro_web_security_vm0inj`` mounts the same flag file
as ``in-vitro_web_security_vm0`` and its games.json entry intentionally
repeats that flag, so a variant is never randomized on its own -- it is
rewritten together with the original it declares in ``variant_of``. That is
also why the ``exactly once`` guard counts the expected occurrences (the
original plus its variants) instead of assuming a single one.

Run this before a benchmark session to avoid reusing flags that may already
be memorized by a model from public benchmark data:

    python scripts/randomize_flags.py [--dry-run]
"""
import contextlib
import json
import os
import re
import secrets
import stat
import string
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MACHINES_DIR = REPO_ROOT / 'benchmark' / 'machines'
GAMES_PATH = REPO_ROOT / 'data' / 'games.json'

# Only regenerate flags that already look like a plain random token.
SIMPLE_TOKEN_RE = re.compile(r'^[A-Za-z0-9]{8,64}$')
# e.g. "in-vitro_access_control_vm0" -> level, category, vmid. The injection
# variants append a suffix without an underscore (vm0sham/vm0inj) so the
# driver's own name parser still resolves their category compose file.
TARGET_RE = re.compile(r'^(in-vitro|real-world)_(.+)_(vm\d+[ab]?)(sham|inj)?$')
# Suffix that marks a derived (injection variant) target.
VARIANT_SUFFIXES = ('sham', 'inj')
FLAG_FILENAMES = ('flag', 'flag.txt')

# Files larger than this are not scanned for a duplicate flag token.
MAX_SCAN_BYTES = 5 * 1024 * 1024


def find_flag_file(level: str, category: str, vmid: str) -> Path | None:
    """Locate the on-disk flag file for a VM, tolerating vm5 -> vm5a/vm5b."""
    for candidate_vmid in (vmid, vmid + 'a', vmid + 'b'):
        vm_dir = MACHINES_DIR / level / category / candidate_vmid
        for name in FLAG_FILENAMES:
            path = vm_dir / name
            if path.is_file():
                return path
    return None


def flag_referenced_elsewhere(flag_path: Path, token: str) -> str | None:
    """Name of another file in the VM directory that also contains ``token``.

    A few tasks derive their flag from an artifact the target serves rather
    than from the flag file itself -- the Heartbleed VM leaks its TLS private
    key and the flag is a slice of that key, so the token also appears in
    ``local.key``. Rewriting only the flag file (and games.json) would leave
    the task internally inconsistent, so such entries must be left untouched.
    """
    needle = token.encode()
    for sibling in sorted(flag_path.parent.rglob('*')):
        if not sibling.is_file() or sibling == flag_path:
            continue
        try:
            if sibling.stat().st_size > MAX_SCAN_BYTES:
                continue
            if needle in sibling.read_bytes():
                return str(sibling.relative_to(flag_path.parent))
        except OSError:
            continue
    return None


def random_token(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def variant_counts(games: dict) -> dict:
    """How many entries each target has repeating its flag.

    A derived entry repeats its original's flag by design, so the number of
    occurrences of a flag in games.json is ``1 + variants`` rather than 1.
    ``variant_of`` is what a well-formed entry declares, but the target's own
    suffix counts as well: an entry that lost the key (or names it wrongly)
    still repeats the flag, and recognizing only the key would leave the
    occurrence count permanently mismatched -- so the original would be
    skipped on every run, silently and for good.
    """
    counts = {}
    for categories in games.values():
        for entries in categories.values():
            for entry in entries:
                original = entry.get('variant_of')
                if original:
                    counts[original] = counts.get(original, 0) + 1
                    continue
                match = TARGET_RE.match(entry.get('target', ''))
                if match and match.group(4):
                    base = entry['target'][: -len(match.group(4))]
                    counts[base] = counts.get(base, 0) + 1
    return counts


def _write_text_atomically(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` through a temporary file and a rename.

    Both ``games.json`` and the flag files are read back by the benchmark, so
    a crash mid-write must not leave a truncated file behind: the rename is
    atomic, the truncation is not.
    """
    previous_mode = None
    with contextlib.suppress(FileNotFoundError):
        previous_mode = stat.S_IMODE(path.stat().st_mode)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(text, encoding='utf-8')
    if previous_mode is not None:
        os.chmod(temporary, previous_mode)
    os.replace(temporary, path)


def _journal_path() -> Path:
    """Path of the recovery record beside the benchmark's games file."""
    return GAMES_PATH.with_name('.randomize_flags-journal.json')


def _write_journal(journal: dict) -> None:
    _write_text_atomically(
        _journal_path(), json.dumps(journal, ensure_ascii=False),
    )


def _recover_pending_transaction() -> None:
    """Finish or roll back an interrupted flag-update transaction.

    Replacing individual files is atomic, but replacing a flag set and
    ``games.json`` cannot be. The journal records both versions before the
    first replacement; a later invocation can therefore restore a partial
    update, or retain a fully committed one after a crash during cleanup.
    """
    path = _journal_path()
    if not path.exists():
        return
    try:
        journal = json.loads(path.read_text(encoding='utf-8'))
        committed = bool(journal['committed'])
        writes = journal['writes']
        for item in writes:
            target = Path(item['path'])
            before, after = item['before'], item['after']
            current = target.read_text(encoding='utf-8')
            if current not in (before, after):
                raise RuntimeError(
                    f'{target} changed outside the pending flag transaction; '
                    'refusing to overwrite it'
                )
            desired = after if committed else before
            if current != desired:
                _write_text_atomically(target, desired)
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f'cannot recover flag transaction recorded in {path}: {error}'
        ) from error
    path.unlink()


def _apply_transaction(writes: list[tuple[Path, str, str]]) -> None:
    """Apply related file replacements with durable rollback information."""
    journal = {
        'committed': False,
        'writes': [
            {'path': str(path), 'before': before, 'after': after}
            for path, before, after in writes
        ],
    }
    _write_journal(journal)
    try:
        for path, _before, after in writes:
            _write_text_atomically(path, after)
        journal['committed'] = True
        _write_journal(journal)
    except Exception:
        # The journal remains if rollback itself is interrupted, so the next
        # run can complete it instead of leaving games.json and flags apart.
        _recover_pending_transaction()
        raise
    _journal_path().unlink()


def randomize(dry_run: bool = False) -> int:
    # A dry run must remain read-only, even when a previous interrupted commit
    # is waiting for recovery. A normal run repairs that state before deciding
    # which flags to randomize.
    if not dry_run:
        _recover_pending_transaction()
    # Parse existing file (preserve hand-formatted spacing if present)
    raw_games_text = GAMES_PATH.read_text(encoding='utf-8')
    original_games_text = raw_games_text
    try:
        games = json.loads(raw_games_text)
    except json.JSONDecodeError:
        print(f'[skip] {GAMES_PATH}: could not parse as JSON, skipping')
        return 0

    changed = 0
    skipped = 0
    variants = variant_counts(games)
    # (path, old text, new text) of every file the run decided to rewrite. Staged rather
    # than written as we go: an entry that aborts the run halfway (Ctrl-C, a
    # later entry failing) must not leave the first flag files holding a token
    # that games.json still calls stale.
    pending = []

    for level, categories in list(games.items()):
        for entries in list(categories.values()):
            for entry in list(entries):
                target = entry.get('target')
                if not target:
                    skipped += 1
                    continue

                match = TARGET_RE.match(target)
                if not match:
                    print(f'[skip] {target}: unrecognized target format')
                    skipped += 1
                    continue

                _, parsed_category, vmid, variant_suffix = match.groups()
                if variant_suffix or entry.get('variant_of'):
                    # Derived entries share their original's flag: randomizing
                    # one on its own would desync it from the flag file it
                    # mounts and from its sibling conditions.
                    original = entry.get('variant_of', '(no variant_of)')
                    print(f'[skip] {target}: injection variant of {original}; '
                          'updated together with its original')
                    skipped += 1
                    continue

                flag_path = find_flag_file(level, parsed_category, vmid)
                old_flag = entry.get('flag', '')

                if flag_path is None:
                    print(f'[skip] {target}: no flag file found on disk')
                    skipped += 1
                    continue
                if not SIMPLE_TOKEN_RE.match(old_flag):
                    print(f'[skip] {target}: flag is not a simple token, leaving untouched')
                    skipped += 1
                    continue

                referenced_in = flag_referenced_elsewhere(flag_path, old_flag)
                if referenced_in is not None:
                    print(f'[skip] {target}: flag also appears in {referenced_in}; '
                          'regenerating it would desync the task, leaving untouched')
                    skipped += 1
                    continue

                raw_flag_file = flag_path.read_text(encoding='utf-8')
                if raw_flag_file.count(old_flag) != 1:
                    print(f'[skip] {target}: flag not found exactly once in '
                          f'{flag_path}, leaving untouched')
                    skipped += 1
                    continue

                # Find and replace in the raw JSON text to preserve the
                # file's existing formatting. Match the flag value in a
                # format-agnostic way (tolerates whitespace after ':') so
                # the script works on both hand-formatted and json.dump-ed
                # games.json files. The expected count includes the derived
                # entries that repeat this flag (the original + its variants),
                # so a stray duplicate still aborts.
                expected = 1 + variants.get(target, 0)
                new_flag = random_token(len(old_flag))
                flag_re = re.compile(
                    r'("flag"\s*:\s*")' + re.escape(old_flag) + r'(")'
                )
                new_games_text, n_replaced = flag_re.subn(
                    lambda m, new_flag=new_flag: m.group(1) + new_flag + m.group(2),
                    raw_games_text,
                )
                if n_replaced != expected:
                    print(f'[skip] {target}: flag appears {n_replaced} time(s) '
                          f'in games.json, expected {expected}; leaving untouched')
                    skipped += 1
                    continue
                raw_games_text = new_games_text

                relpath = flag_path.relative_to(REPO_ROOT)
                derived = expected - 1
                print(f'[ok]   {target}: {old_flag} -> {new_flag} ({relpath})'
                      + (f' + {derived} derived entr'
                         f'{"y" if derived == 1 else "ies"}' if derived else ''))
                pending.append(
                    (flag_path, raw_flag_file,
                     raw_flag_file.replace(old_flag, new_flag))
                )
                changed += 1

    if not dry_run and changed:
        # Every entry has been checked by now, so the set of files still
        # agrees with itself. A durable journal preserves that agreement if
        # this process or a replacement fails during the multi-file commit.
        _apply_transaction(
            [*pending, (GAMES_PATH, original_games_text, raw_games_text)]
        )

    print(f'\n{changed} flag(s) randomized, {skipped} skipped.'
          + (' (dry run, nothing written)' if dry_run else ''))
    return changed


if __name__ == '__main__':
    # The number of randomized flags is reported in the output, not through
    # the exit status, so a successful run does not look like a failure to the
    # shell or to CI.
    randomize(dry_run='--dry-run' in sys.argv)
