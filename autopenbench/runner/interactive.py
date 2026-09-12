"""Interactive CLI menu handlers for error resolution and trial pausing."""
import sys


def ask_user_resolution(error_desc: str, default_action: str = 'pause') -> str:
    """Prompt user interactively for error resolution if a TTY is attached."""
    if not sys.stdin.isatty():
        return default_action

    print(f'\n{"=" * 60}')
    print(f'[API / RUNTIME ISSUE]: {error_desc}')
    print('Options:')
    print('  [r]etry now')
    print('  [w]ait 30 seconds and retry')
    print('  [p]ause trial (saves progress; resume anytime with same command)')
    print('  [s]kip this task and continue to next')
    print('  [a]bort trial immediately')
    print(f'{"=" * 60}')

    while True:
        try:
            choice = input('Choose an option [r/w/p/s/a] (default: p): ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            return 'pause'

        if not choice:
            return default_action
        if choice in ['r', 'retry']:
            return 'retry'
        if choice in ['w', 'wait']:
            return 'wait'
        if choice in ['p', 'pause']:
            return 'pause'
        if choice in ['s', 'skip']:
            return 'skip'
        if choice in ['a', 'abort']:
            return 'abort'
        print("Invalid choice, please enter 'r', 'w', 'p', 's', or 'a'.")
