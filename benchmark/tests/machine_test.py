import ast
import re
import sys
import time
from pathlib import Path

from termcolor import cprint

from autopenbench.driver import PentestDriver
from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect, WriteFile
from autopenbench.utils import load_data

# Absolute, so the script also runs from outside the repository root.
REPO_ROOT = Path(__file__).resolve().parents[2]
INVITRO = REPO_ROOT / 'benchmark' / 'machines' / 'in-vitro'

# A solution line is an expression that builds one of the benchmark's tool
# objects. Only those classes (plus the dynamically extracted ``fname``) are
# exposed to the evaluated expression, and builtins are disabled, so a
# solution file can never reach the rest of this process.
SOLUTION_NAMESPACE = {
    'ExecuteBash': ExecuteBash,
    'FinalAnswer': FinalAnswer,
    'SSHConnect': SSHConnect,
    'WriteFile': WriteFile,
}


def extract_content(target: str, cmd: str = ''):
    """Extract the content of the solutions from the provided action.

    Args:
        target (str): task name
        cmd (str, optional): command pointing to the content to extract.
        Defaults to ''.

    Returns:
        str or None: the extracted content, or None if it cannot be extracted
    """
    content = None
    if target == 'real-world_cve_vm4':
        pattern = r"/root/\.msf4/loot/(.*)\.bin"
        match = re.search(pattern, cmd)
        content = match.group(1) if match else None
    elif target == 'real-world_cve_vm5':
        pattern = r"/root/\.msf4/loot/(.*)\.txt"
        match = re.search(pattern, cmd)
        content = match.group(1) if match else None
    elif target == 'in-vitro_network_security_vm4':
        content = (INVITRO / 'network_security/vm4/solution.py').read_text(
            encoding='utf-8')
    elif target == 'in-vitro_network_security_vm5':
        content = (INVITRO / 'network_security/vm5a/solution.py').read_text(
            encoding='utf-8')
    elif target == 'in-vitro_cryptography_vm2':
        content = (INVITRO / 'cryptography/vm2/solution.py').read_text(
            encoding='utf-8')
    elif target == 'in-vitro_cryptography_vm3':
        content = (INVITRO / 'cryptography/vm3/solution.py').read_text(
            encoding='utf-8')
    return content


# Steps (per target) at which `fname` must be extracted *before* evaluating
# the solution line, and steps at which it is extracted *after* (from the
# observation)
PRE_EXTRACT_STEPS = {
    'in-vitro_network_security_vm4': [0],
    'in-vitro_network_security_vm5': [0],
    'in-vitro_cryptography_vm2': [5],
    'in-vitro_cryptography_vm3': [5],
}
POST_EXTRACT_STEPS = {
    'real-world_cve_vm4': [11],
    'real-world_cve_vm5': [8],
}


# Check if all the parameters are provided as command-line arguments
if len(sys.argv) != 4:
    print("Usage: python3 machine_test.py <LEVEL> <CATEGORY> <GAME_ID>")
    sys.exit(1)

# Get arguments from command-line argument
LEVEL = sys.argv[1]  # in-vitro or real-world
CATEGORY = sys.argv[2]  # task category
GAME_ID = int(sys.argv[3])  # vm identifier
SOLUTIONS = REPO_ROOT / 'benchmark' / 'solutions' / LEVEL / CATEGORY

# Load the vulnerable machine to test. Looked up by `target` rather than by
# list position: `data/games.json` is hand-edited and appended to by
# `make create`, so an inserted entry would otherwise silently run a
# different game than the one this vm number names. The prompt-injection
# variants are the exception -- `vm7` names the entry at index 7, whose target
# is `in-vitro_web_security_vm0sham` -- so a vm number that matches no target
# falls back to the entry at that index.
TARGET = f'{LEVEL}_{CATEGORY}_vm{GAME_ID}'
ENTRIES = load_data(LEVEL)[CATEGORY]
game = next(
    (entry for entry in ENTRIES if entry.get('target') == TARGET), None
)
if game is None and 0 <= GAME_ID < len(ENTRIES):
    game = ENTRIES[GAME_ID]
if game is None:
    print(f"No entry with target '{TARGET}' in data/games.json")
    sys.exit(1)

# A variant is solved by its original's reference solution: the challenge is
# unchanged, only the injection surface differs (`vm7` -> vm0sham -> vm0).
solution_target = game.get('variant_of', game['target'])
SOLUTION_VM = solution_target.rsplit('_', 1)[-1].removeprefix('vm')

# Load solutions
with open(SOLUTIONS / f'vm{SOLUTION_VM}.txt', encoding='utf-8') as file:
    solutions = file.readlines()

# Initialize the driver and reset
driver = PentestDriver(game['task'], game['flag'], game['target'])
driver.reset()

# Perform the solutions in sequence
fname = None  # Dynamically extracted content available to eval'd solutions
for step, solution in enumerate(solutions):
    # Extract the dynamically created file name for network_security_vm4 and
    # vm5 and cryptography vm2 and vm3
    if step in PRE_EXTRACT_STEPS.get(game['target'], []):
        content = extract_content(game['target'])
        if content is not None:
            fname = content

    # Create the action (`fname` is injected into the namespace so solutions
    # can reference the extracted content). Parse first so a malformed
    # solution reports its step instead of raising deep inside eval().
    try:
        code = compile(ast.parse(solution, mode='eval'), '<solution>', 'eval')
    except SyntaxError as error:
        cprint(f'INVALID SOLUTION at step {step + 1}: {error}', 'red')
        sys.exit(1)
    action = eval(
        code,
        {'__builtins__': {}},
        {**SOLUTION_NAMESPACE, 'fname': fname},
    )
    time.sleep(.5)
    cprint(f'ACTION: {solution}', 'yellow')

    # Perform the step
    observation, done = driver.step(action)
    time.sleep(.5)

    # Extract the dynamically created file name for real-world_cve_vm4 and vm5
    if step in POST_EXTRACT_STEPS.get(game['target'], []):
        content = extract_content(game['target'], observation)
        if content is not None:
            fname = content

    # Print the observation
    cprint(f'OBSERVATION: {observation}\n', 'cyan')

    # Verify the benchmark succeeded
    if done:
        cprint(f'BENCHMARK PASSED: Flag captured in step {step + 1}', 'green')
        sys.exit(0)

# If we reach here, the benchmark never completed successfully
cprint('BENCHMARK FAILED: Flag was never captured', 'red')
sys.exit(1)
