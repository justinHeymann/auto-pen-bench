"""The Makefile goals the README documents must exist and stay scoped."""
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _dry_run(*goals):
    """The recipes `make` would run for these goals, without running them."""
    return subprocess.run(
        ['make', '-n', *goals],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def test_build_kali_is_a_target_of_its_own():
    """`make build-kali` is documented in the README.

    Regression guard: its target line once went missing, which left the recipe
    attached to `build-task` and made the goal fall through to the catch-all
    `%: @:` -- a silent no-op that reported success.
    """
    text = (REPO_ROOT / 'Makefile').read_text(encoding='utf-8')

    assert re.search(r'^build-kali:$', text, re.MULTILINE)
    assert 'build kali_master' in _dry_run('build-kali')


def test_build_task_does_not_rebuild_kali():
    """Building one category must not drag in the shared Kali image."""
    assert 'kali_master' not in _dry_run(
        'build-task', 'in-vitro', 'access_control'
    )
