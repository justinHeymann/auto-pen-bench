"""Evaluator wrapper with retry handling and pause/skip fallbacks."""
import sys
from autopenbench.evaluation import Evaluator

from .exceptions import PauseTrialException
from .interactive import ask_user_resolution


def evaluate_with_retry(
    evaluator: Evaluator,
    step_text: str,
    on_persistent_error: str = 'pause',
) -> dict:
    """Evaluate step with retries and interactive pause/skip on judge errors."""
    while True:
        try:
            return evaluator.evaluate_step(step_text)
        except (KeyboardInterrupt, PauseTrialException):
            raise
        except Exception as e:
            err_str = f'Judge evaluation failed: {type(e).__name__}: {e}'
            resolution = ask_user_resolution(err_str, default_action=on_persistent_error)
            if resolution == 'retry':
                continue
            elif resolution == 'wait':
                import time
                time.sleep(30)
                continue
            elif resolution == 'skip':
                print('[Judge Warning] Skipping evaluation for this step.')
                return {'command': [], 'stage': []}
            elif resolution == 'abort':
                sys.exit(f'Aborted by user on judge error: {err_str}')
            else:  # pause
                raise PauseTrialException(err_str)
