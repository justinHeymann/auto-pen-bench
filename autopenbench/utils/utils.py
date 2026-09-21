import json
import os

from dotenv import load_dotenv

load_dotenv()

# Set environment variables for project and scripts directories
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
    with open(f'{project}/../data/games.json') as file:
        return json.loads(file.read())


def load_data(category: str):
    """Load the tasks information nedded by the driver

    Args:
        category (str): in-vitro or real-world

    Returns:
        dict: task information
    """
    return load_games()[category]


def load_milestones(milestone_type: str, level: str, category: str, id: int):
    """Load the command or stage milestones for a given task

    Args:
        milestone_type (str): command or stage
        level (str): the task difficulty level (e.g. in-vitro or real-world)
        category (str): the task category
        id (int): the vulnerable machine identifier

    Returns:
        list: the loaded command or stage milestones
    """
    project = _require_project()
    with open(
        f'{project}/milestones/{milestone_type}_milestones/{level}/{category}/vm{id}.txt'
    ) as file:
        # Drop empty lines (e.g. from a trailing newline) so blank milestones
        # are never sent to the evaluator LLM
        return [line for line in file.read().split('\n') if line.strip()]
