"""Storage, persistence, and metrics aggregation for trial runs."""
import json
import os
from typing import Dict, List, Optional


def save_task_result(output_dir: str, task_name: str, result: dict) -> str:
    """Save full task result and transcript to JSON."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f'{task_name}.json')
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    return out_path


def load_task_result(output_dir: str, task_name: str) -> Optional[dict]:
    """Load previously saved task result if it exists."""
    out_path = os.path.join(output_dir, f'{task_name}.json')
    if os.path.exists(out_path):
        try:
            with open(out_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None


def calculate_metrics(summary_list: List[dict]) -> Dict[str, dict]:
    """Calculate category-level and overall benchmark metrics (SR & PR).

    Matches the definitions used in the AutoPenBench paper:
    - Success Rate (SR): Proportion of tasks where the flag was successfully captured.
    - Progress Rate (PR): Average fraction of command milestones achieved per task.
    """
    by_category: Dict[str, List[dict]] = {}
    for r in summary_list:
        cat = r.get('category', 'unknown')
        by_category.setdefault(cat, []).append(r)

    metrics = {}
    for cat, items in by_category.items():
        n = len(items)
        if n == 0:
            continue
        success_count = sum(1 for x in items if x.get('success', False))
        sr = success_count / n

        progress_rates = []
        for x in items:
            total_cmd = x.get('n_command_milestones', 0)
            reached_cmd = x.get('n_command_milestones_reached', 0)
            if total_cmd > 0:
                progress_rates.append(reached_cmd / total_cmd)
            else:
                progress_rates.append(1.0 if x.get('success') else 0.0)

        pr = sum(progress_rates) / len(progress_rates) if progress_rates else 0.0

        metrics[cat] = {
            'total_tasks': n,
            'success_count': success_count,
            'success_rate': round(sr, 4),
            'progress_rate': round(pr, 4),
        }

    total_all = len(summary_list)
    if total_all > 0:
        overall_sr = sum(1 for x in summary_list if x.get('success', False)) / total_all
        all_prs = [
            (x.get('n_command_milestones_reached', 0) / x.get('n_command_milestones', 1))
            if x.get('n_command_milestones', 0) > 0 else (1.0 if x.get('success') else 0.0)
            for x in summary_list
        ]
        overall_pr = sum(all_prs) / len(all_prs) if all_prs else 0.0
        metrics['overall'] = {
            'total_tasks': total_all,
            'success_count': sum(1 for x in summary_list if x.get('success', False)),
            'success_rate': round(overall_sr, 4),
            'progress_rate': round(overall_pr, 4),
        }

    return metrics


def write_summary(output_dir: str, summary_list: List[dict]):
    """Write an updated lightweight summary rollup and metrics to disk."""
    summary_path = os.path.join(output_dir, '_summary.json')
    metrics_path = os.path.join(output_dir, '_metrics.json')

    lightweight_summary = [
        {
            'category': r.get('category'),
            'vm_id': r.get('vm_id'),
            'target': r.get('target'),
            'agent_model': r.get('agent_model'),
            'judge_model': r.get('judge_model'),
            'success': r.get('success', False),
            'error': r.get('error'),
            'steps_taken': r.get('steps_taken', 0),
            'n_command_milestones': r.get('n_command_milestones', 0),
            'n_command_milestones_reached': r.get('n_command_milestones_reached', 0),
            'n_stage_milestones': r.get('n_stage_milestones', 0),
            'n_stage_milestones_reached': r.get('n_stage_milestones_reached', 0),
            'wall_clock_seconds': r.get('wall_clock_seconds', 0.0),
        }
        for r in summary_list
    ]

    with open(summary_path, 'w') as f:
        json.dump(lightweight_summary, f, indent=2, default=str)

    metrics = calculate_metrics(summary_list)
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2, default=str)
