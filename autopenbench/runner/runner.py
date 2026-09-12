"""Orchestrator for running individual tasks and batch trials."""
from datetime import datetime, timezone
import time
import traceback
from typing import Any, List, Optional

import instructor

from autopenbench.driver import PentestDriver
from autopenbench.evaluation import Evaluator
from autopenbench.utils import load_data, load_milestones

from .agent import call_agent_with_retry
from .exceptions import PauseTrialException, SkipTaskException
from .interactive import ask_user_resolution
from .judge import evaluate_with_retry
from .models import RESPONSE_MODEL, SYSTEM_PROMPT
from .storage import load_task_result, save_task_result, write_summary


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def list_tasks(level: str, categories: Optional[List[str]] = None):
    """Return a flat list of (category, vm_id, game_dict) for a given level."""
    data = load_data(level)
    tasks = []
    for category, games in data.items():
        if categories and category not in categories:
            continue
        for vm_id, game in enumerate(games):
            tasks.append((category, vm_id, game))
    return tasks


def run_task(
    level: str,
    category: str,
    vm_id: int,
    game: dict,
    agent_client: instructor.client.Instructor,
    agent_model: str,
    judge_api_key: str,
    judge_base_url: str,
    judge_model: str,
    max_steps: int = 30,
    max_retries: int = 5,
    retry_delay: float = 3.0,
    on_persistent_error: str = 'pause',
) -> dict:
    """Run a single task end-to-end and return a full result record."""
    command_milestones = load_milestones('command', level, category, vm_id)
    stage_milestones = load_milestones('stage', level, category, vm_id)
    n_command_milestones = len(command_milestones)
    n_stage_milestones = len(stage_milestones)

    evaluator = Evaluator(
        judge_api_key,
        command_milestones,
        stage_milestones,
        base_url=judge_base_url,
        model=judge_model,
    )

    driver = PentestDriver(game['task'], game['flag'], game['target'])

    result = {
        'level': level,
        'category': category,
        'vm_id': vm_id,
        'target': game['target'],
        'vulnerability': game.get('vulnerability'),
        'agent_model': agent_model,
        'judge_model': judge_model,
        'n_command_milestones': n_command_milestones,
        'n_stage_milestones': n_stage_milestones,
        'started_at': now_iso(),
        'transcript': [],
        'success': False,
        'error': None,
        'steps_taken': 0,
    }

    start_time = time.monotonic()

    try:
        observation, done = driver.reset()
    except Exception as e:
        result['error'] = f'reset failed: {e}\n{traceback.format_exc()}'
        result['finished_at'] = now_iso()
        result['wall_clock_seconds'] = time.monotonic() - start_time
        return result

    prompt = [
        {'role': 'system', 'content': SYSTEM_PROMPT},
        {'role': 'user', 'content': game['task']},
    ]
    result['transcript'].append({
        'type': 'reset',
        'timestamp': now_iso(),
        'observation': observation,
    })

    reached_command = []
    reached_stage = []

    for step_idx in range(max_steps):
        step_record = {'step': step_idx, 'timestamp': now_iso()}

        # 1. Call agent with retries and pause/resume capability
        t0 = time.monotonic()
        try:
            llm_out, native_reasoning = call_agent_with_retry(
                agent_client=agent_client,
                model=agent_model,
                prompt=prompt,
                response_model=RESPONSE_MODEL,
                max_retries=max_retries,
                initial_delay=retry_delay,
                on_persistent_error=on_persistent_error,
            )
            step_record['agent_latency_seconds'] = time.monotonic() - t0
        except SkipTaskException as e:
            step_record['error'] = str(e)
            result['transcript'].append(step_record)
            result['error'] = str(e)
            break
        except Exception as e:
            step_record['error'] = f'agent call failed: {e}\n{traceback.format_exc()}'
            result['transcript'].append(step_record)
            result['error'] = step_record['error']
            break

        # 2. Extract and record internal thoughts + action
        thought = getattr(llm_out, 'thought', None)
        step_record['thought'] = thought
        if native_reasoning:
            step_record['native_reasoning'] = native_reasoning

        action = llm_out.action
        step_record['action_type'] = action.__class__.__name__
        step_record['action'] = action.model_dump()

        # 3. Execute action via PentestDriver
        try:
            observation, done = driver.step(action)
        except Exception as e:
            step_record['error'] = f'driver step failed: {e}\n{traceback.format_exc()}'
            result['transcript'].append(step_record)
            result['error'] = step_record['error']
            break

        step_record['observation'] = observation
        step_record['done'] = done

        # 4. Evaluate milestone progress with judge model
        step_text = f'Action:{action}\nObservation: {observation}'
        try:
            newly_reached = evaluate_with_retry(
                evaluator=evaluator,
                step_text=step_text,
                on_persistent_error=on_persistent_error,
            )
        except SkipTaskException:
            newly_reached = {'command': [], 'stage': []}

        step_record['command_milestones_reached'] = newly_reached['command']
        step_record['stage_milestones_reached'] = newly_reached['stage']
        reached_command.extend(newly_reached['command'])
        reached_stage.extend(newly_reached['stage'])

        result['transcript'].append(step_record)
        result['steps_taken'] = step_idx + 1

        prompt.append({'role': 'user', 'content': step_text})

        if done:
            result['success'] = True
            break

    result['reached_command_milestones'] = reached_command
    result['reached_stage_milestones'] = reached_stage
    result['n_command_milestones_reached'] = len(reached_command)
    result['n_stage_milestones_reached'] = len(reached_stage)
    result['full_conversation'] = prompt
    result['finished_at'] = now_iso()
    result['wall_clock_seconds'] = time.monotonic() - start_time

    return result


def run_trial(
    agent_client: instructor.client.Instructor,
    agent_model: str,
    judge_api_key: str,
    judge_base_url: str,
    judge_model: str,
    output_dir: str,
    level: str = 'in-vitro',
    categories: Optional[List[str]] = None,
    max_steps: int = 30,
    max_retries: int = 5,
    retry_delay: float = 3.0,
    on_persistent_error: str = 'pause',
    overwrite: bool = False,
    retry_failed: bool = False,
) -> List[dict]:
    """Orchestrate an entire benchmark trial across multiple tasks."""
    tasks = list_tasks(level, categories)
    print(f'Found {len(tasks)} tasks for level={level} categories={categories or "all"}')

    summary: List[dict] = []
    paused = False

    try:
        for idx, (category, vm_id, game) in enumerate(tasks):
            task_name = f'{category}_vm{vm_id}'

            # Check for existing results
            if not overwrite:
                prev_res = load_task_result(output_dir, task_name)
                if prev_res is not None:
                    is_failed = (not prev_res.get('success')) or bool(prev_res.get('error'))
                    if not (retry_failed and is_failed):
                        print(f'[{idx+1}/{len(tasks)}] [skip] {task_name} (already exists; use --overwrite or --retry-failed)')
                        summary.append(prev_res)
                        continue

            print(f'\n{"=" * 70}')
            print(f'[{idx+1}/{len(tasks)}] Running {task_name} (target={game["target"]})')
            print(f'{"=" * 70}')

            try:
                result = run_task(
                    level=level,
                    category=category,
                    vm_id=vm_id,
                    game=game,
                    agent_client=agent_client,
                    agent_model=agent_model,
                    judge_api_key=judge_api_key,
                    judge_base_url=judge_base_url,
                    judge_model=judge_model,
                    max_steps=max_steps,
                    max_retries=max_retries,
                    retry_delay=retry_delay,
                    on_persistent_error=on_persistent_error,
                )
            except PauseTrialException as pe:
                print(f'\n[Trial Paused]: {pe}')
                paused = True
                break
            except KeyboardInterrupt:
                print('\n[Interrupt Received]')
                res = ask_user_resolution('Keyboard interrupt received during task', default_action='pause')
                if res in ['pause', 'abort']:
                    paused = True
                    break
                else:
                    print(f'Skipping current task {task_name}...')
                    continue

            # Save task transcript immediately
            save_task_result(output_dir, task_name, result)

            status = 'SUCCESS' if result.get('success') else ('ERROR' if result.get('error') else 'FAILED')
            print(f'[{status}] {task_name} steps={result.get("steps_taken", 0)} '
                  f'cmd_milestones={result.get("n_command_milestones_reached", 0)}/{result.get("n_command_milestones", 0)} '
                  f'time={result.get("wall_clock_seconds", 0.0):.1f}s')

            summary.append(result)
            write_summary(output_dir, summary)

    except KeyboardInterrupt:
        print('\n[Trial run interrupted by user]')
        paused = True

    write_summary(output_dir, summary)

    n_success = sum(1 for r in summary if r.get('success'))
    total_run = len(summary)

    if paused:
        print(f'\n{"=" * 70}')
        print(f'Trial run PAUSED. Completed {total_run}/{len(tasks)} tasks ({n_success} succeeded).')
        print(f'Progress has been saved to: {output_dir}/')
        print('To resume where you left off, simply run the exact same command again.')
        print(f'{"=" * 70}')
    else:
        print(f'\n=== Completed: {n_success}/{total_run} tasks succeeded. Summary: {output_dir}/_summary.json ===')

    return summary
