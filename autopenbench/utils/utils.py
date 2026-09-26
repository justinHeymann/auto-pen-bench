import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# The layout is imported *after* load_dotenv() so that a KALI_IP or
# BENCHMARK_* override in the benchmark's .env is in the environment when
# autopenbench.network resolves it. Importing the names rather than rebuilding
# the dict here keeps one definition for the driver, the setup scripts, the
# tests and the paper harness.
from ..network import (  # noqa: E402
    BRIDGE_SUBNET,
    CATEGORY_OCTETS,
    KALI_IP,
    PREFIX,
    TARGET_SUBNETS,
    compose_env,
    find_octets,
    octet_var,
    target_ip,
    target_subnet,
)

__all__ = [
    'BRIDGE_SUBNET',
    'CATEGORY_OCTETS',
    'KALI_IP',
    'PREFIX',
    'TARGET_SUBNETS',
    'compose_env',
    'find_octets',
    'load_data',
    'load_games',
    'load_milestones',
    'octet_var',
    'target_ip',
    'target_subnet',
]

# Benchmark root (set by setup/setup.sh into .env).
PROJECT = os.environ.get("AUTOPENBENCH")


def _require_project() -> str:
    """Return the AUTOPENBENCH benchmark directory or raise a clear error.

    Without this check a missing environment variable surfaces as a cryptic
    ``FileNotFoundError: 'None/milestones/...'``
    """
    if not PROJECT:
        raise OSError(
            "The AUTOPENBENCH environment variable is not set. Run "
            "setup/setup.sh (or set AUTOPENBENCH to the benchmark "
            "directory, e.g. /path/to/auto-pen-bench/benchmark)."
        )
    return PROJECT


def load_games() -> dict:
    """Load the whole task database (``data/games.json``).

    Returns:
        dict: The tasks of every level, keyed by level and category.
    """
    project = _require_project()
    # data/games.json lives beside the benchmark directory (PROJECT points at
    # .../auto-pen-bench/benchmark), so resolve it as a sibling rather than
    # relying on a '..' string join.
    games_path = Path(project).parent / 'data' / 'games.json'
    with open(games_path, encoding='utf-8') as file:
        return json.loads(file.read())


def load_data(category: str):
    """Load task entries for one level (``in-vitro`` or ``real-world``).

    Args:
        category (str): Difficulty level key in ``games.json``.

    Returns:
        dict: Tasks keyed by category name.
    """
    return load_games()[category]


def load_milestones(milestone_type: str, level: str, category: str, id: int):
    """Load command or stage milestones for one task.

    Args:
        milestone_type (str): ``command`` or ``stage``.
        level (str): Difficulty level (e.g. ``in-vitro``).
        category (str): Task category.
        id (int): Machine id.

    Returns:
        list: Milestone lines (empty lines dropped).
    """
    project = _require_project()
    with open(
        f'{project}/milestones/{milestone_type}_milestones/{level}/{category}/vm{id}.txt',
        encoding='utf-8',
    ) as file:
        # Drop empties so blank lines are never sent to the evaluator LLM.
        return [line for line in file.read().split('\n') if line.strip()]
