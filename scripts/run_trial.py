#!/usr/bin/env python3
"""Automated trial runner CLI for AutoPenBench.

Runs a given agent model against all (or a subset of) tasks of a benchmark
level (e.g. `in-vitro`), using a separate LLM-as-judge model to evaluate
milestone progress, and records the full transcript (including internal
monologue/thoughts) plus a summary of the run for later analysis.

Example:
    python scripts/run_trial.py \\
        --agent-model qwen3.5-397b-a17b \\
        --judge-model openai-gpt-oss-120b \\
        --base-url https://chat-ai.academiccloud.de/v1 \\
        --api-key-env OPENAI_API_KEY \\
        --level in-vitro \\
        --output-dir results/qwen3.5-397b-a17b

    python scripts/run_trial.py \\
            --agent-model qwen3.5-397b-a17b \\
            --judge-model openai-gpt-oss-120b \\
            --base-url https://chat-ai.academiccloud.de/v1 \\
            --agent-api-key-env OPENAI_API_KEY \\
            --judge-api-key-env OPENAI_API_KEY \\
            --level in-vitro \\
            --output-dir results/qwen3.5-397b-a17b
"""
import argparse
import os
import sys

import instructor
from openai import OpenAI

from autopenbench.runner import run_trial


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--agent-model', required=True, help='Model name to test as the agent (e.g. qwen3.5-397b-a17b)')
    parser.add_argument('--judge-model', required=True, help='Model name used as the LLM judge (e.g. openai-gpt-oss-120b)')
    parser.add_argument('--base-url', default='https://chat-ai.academiccloud.de/v1', help='OpenAI-compatible base URL shared by agent and judge unless overridden')
    parser.add_argument('--agent-base-url', default=None, help='Override base URL for the agent model')
    parser.add_argument('--judge-base-url', default=None, help='Override base URL for the judge model')
    parser.add_argument('--api-key-env', default='OPENAI_API_KEY', help='Env var holding the API key shared by agent and judge unless overridden')
    parser.add_argument('--agent-api-key-env', default=None, help='Override env var for the agent API key')
    parser.add_argument('--judge-api-key-env', default=None, help='Override env var for the judge API key')
    parser.add_argument('--level', default='in-vitro', choices=['in-vitro', 'real-world'], help='Benchmark level to run')
    parser.add_argument('--categories', nargs='*', default=None, help='Restrict to specific categories (default: all)')
    parser.add_argument('--max-steps', type=int, default=30, help='Max agent steps per task before giving up')
    parser.add_argument('--max-retries', type=int, default=5, help='Max retry attempts for transient API errors')
    parser.add_argument('--retry-delay', type=float, default=3.0, help='Initial backoff delay in seconds')
    parser.add_argument('--on-api-error', default='pause', choices=['pause', 'skip', 'abort', 'retry'], help='Default behavior when max API retries are exceeded in non-interactive runs')
    parser.add_argument('--output-dir', required=True, help='Directory to write per-task transcripts and the run summary')
    parser.add_argument('--overwrite', action='store_true', help='Re-run all tasks, overwriting existing saved results')
    parser.add_argument('--retry-failed', action='store_true', help='Re-run previously failed or errored tasks while keeping successful ones')
    args = parser.parse_args()

    agent_api_key_env = args.agent_api_key_env or args.api_key_env
    judge_api_key_env = args.judge_api_key_env or args.api_key_env
    agent_api_key = os.environ.get(agent_api_key_env)
    judge_api_key = os.environ.get(judge_api_key_env)

    if not agent_api_key:
        sys.exit(f'Missing agent API key: set the {agent_api_key_env} environment variable')
    if not judge_api_key:
        sys.exit(f'Missing judge API key: set the {judge_api_key_env} environment variable')

    agent_base_url = args.agent_base_url or args.base_url
    judge_base_url = args.judge_base_url or args.base_url

    agent_client = instructor.from_openai(
        OpenAI(api_key=agent_api_key, base_url=agent_base_url)
    )

    run_trial(
        agent_client=agent_client,
        agent_model=args.agent_model,
        judge_api_key=judge_api_key,
        judge_base_url=judge_base_url,
        judge_model=args.judge_model,
        output_dir=args.output_dir,
        level=args.level,
        categories=args.categories,
        max_steps=args.max_steps,
        max_retries=args.max_retries,
        retry_delay=args.retry_delay,
        on_persistent_error=args.on_api_error,
        overwrite=args.overwrite,
        retry_failed=args.retry_failed,
    )


if __name__ == '__main__':
    main()

