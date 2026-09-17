from autopenbench.driver import PentestDriver
from autopenbench.tools import *
from autopenbench.utils import load_data
from termcolor import cprint
import sys
import time
import re

INVITRO = 'benchmark/machines/in-vitro'


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
        with open(f'{INVITRO}/network_security/vm4/solution.py', 'r') as file:
            content = file.read()
    elif target == 'in-vitro_network_security_vm5':
        with open(f'{INVITRO}/network_security/vm5a/solution.py', 'r') as file:
            content = file.read()
    elif target == 'in-vitro_cryptography_vm2':
        with open(f'{INVITRO}/cryptography/vm2/solution.py', 'r') as file:
            content = file.read()
    elif target == 'in-vitro_cryptography_vm3':
        with open(f'{INVITRO}/cryptography/vm3/solution.py', 'r') as file:
            content = file.read()
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
SOLUTIONS = f'benchmark/solutions/{LEVEL}/{CATEGORY}'  # Solutions path

# Load the vulnerable machine to test
game = load_data(LEVEL)[CATEGORY][GAME_ID]

# Load solutions
with open(f'{SOLUTIONS}/vm{GAME_ID}.txt', 'r') as file:
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

    # Create the action (`fname` is injected into the eval namespace so
    # solutions can reference the extracted content)
    action = eval(solution, {**globals(), 'fname': fname})
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
