"""Agent client invocation with retry handling and thought extraction."""
import random
import sys
import time
from typing import Any, Optional, Tuple

import instructor

from .exceptions import PauseTrialException, SkipTaskException
from .interactive import ask_user_resolution
from .models import RESPONSE_MODEL


def call_agent_with_retry(
    agent_client: instructor.client.Instructor,
    model: str,
    prompt: list,
    response_model: Any = RESPONSE_MODEL,
    max_retries: int = 5,
    initial_delay: float = 3.0,
    on_persistent_error: str = 'pause',
) -> Tuple[Any, Optional[str]]:
    """Call agent with exponential backoff retries and interactive fallback.

    Returns:
        tuple of (llm_out, native_reasoning_str)
    """
    attempt = 0
    while True:
        try:
            # Capture structured model and raw tokens
            llm_out, raw_completion = agent_client.chat.completions.create_with_completion(
                model=model,
                response_model=response_model,
                messages=prompt,
            )

            native_reasoning = None
            try:
                msg = raw_completion.choices[0].message
                native_reasoning = (
                    getattr(msg, 'reasoning_content', None)
                    or getattr(msg, 'reasoning', None)
                )
            except Exception:
                pass

            return llm_out, native_reasoning

        except (KeyboardInterrupt, PauseTrialException):
            raise
        except Exception as e:
            attempt += 1
            err_str = f'{type(e).__name__}: {e}'

            if attempt <= max_retries:
                sleep_time = initial_delay * (2 ** (attempt - 1)) + random.uniform(0.5, 1.5)
                print(f'\n[Agent Warning] API call failed ({err_str}). Retrying in {sleep_time:.1f}s (attempt {attempt}/{max_retries})...')
                time.sleep(sleep_time)
                continue

            # Retries exhausted: ask user or follow default policy
            print(f'\n[Agent Error] Persistent failure after {max_retries} retries: {err_str}')
            resolution = ask_user_resolution(err_str, default_action=on_persistent_error)

            if resolution == 'retry':
                attempt = 0
                continue
            elif resolution == 'wait':
                print('Waiting 30 seconds before retrying...')
                time.sleep(30)
                attempt = 0
                continue
            elif resolution == 'skip':
                raise SkipTaskException(f'Task skipped by user after API error: {err_str}')
            elif resolution == 'abort':
                sys.exit(f'Aborted by user on API error: {err_str}')
            else:  # pause
                raise PauseTrialException(f'Trial paused due to API error: {err_str}')
