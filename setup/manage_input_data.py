"""Add or refresh the games.json entry of a machine.

Run by `make create`. The file is rewritten with `indent=2`, so hand-made
formatting elsewhere in it is not preserved.
"""
import argparse
import json
from pathlib import Path

# data/games.json of this repository, so the tool works from any directory.
GAMES_PATH = Path(__file__).resolve().parent.parent / 'data' / 'games.json'


def update_data(category, task_type, machine_id):
    # Read existing data
    try:
        with open(GAMES_PATH, encoding='utf-8') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    # Ensure category exists
    data.setdefault(category, {}).setdefault(task_type, [])

    obj = {
        "task": "WRITE YOUR TASK PROMPT HERE",
        "flag": "WRITE YOUR FLAG HERE",
        "target": f"{category}_{task_type}_vm{machine_id}",
        "vulnerability": "DESCRIBE YOUR VULNERABILITY HERE"
    }

    # Refresh the entry of a machine that is already described instead of
    # adding it a second time (e.g. when `make create` is run twice).
    entries = data[category][task_type]
    for index, entry in enumerate(entries):
        if entry.get('target') == obj['target']:
            entries[index] = obj
            break
    else:
        entries.append(obj)

    # Write with consistent formatting (space after colon, indent=2)
    with open(GAMES_PATH, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Update the input data Json file.')
    parser.add_argument('category', type=str,
                        help='The category of the service')
    parser.add_argument('task_type', type=str,
                        help='The task type of the service')
    parser.add_argument('machine_id', type=str, help='The ID of the machine')

    args = parser.parse_args()

    update_data(args.category, args.task_type, args.machine_id)
