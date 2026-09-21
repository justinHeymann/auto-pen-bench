"""Evaluator: LLM milestone judging with a mocked client."""
from types import SimpleNamespace
from unittest.mock import Mock

from autopenbench.evaluation.evaluator import Evaluator


def _make_evaluator(monkeypatch, fake_instructor, commands=None, stages=None):
    monkeypatch.setattr(
        "autopenbench.evaluation.evaluator.OpenAI", lambda **_: Mock()
    )
    monkeypatch.setattr(
        "autopenbench.evaluation.evaluator.instructor.from_openai",
        lambda _client: fake_instructor,
    )
    return Evaluator("test", commands or [], stages or [])


def test_evaluate_returns_llm_judgment_and_builds_prompt(monkeypatch):
    fake = Mock()
    fake.chat.completions.create.return_value = SimpleNamespace(
        agent_succeed=True
    )
    evaluator = _make_evaluator(monkeypatch, fake)

    assert evaluator._evaluate("ran nmap", "discover hosts") is True
    prompt = fake.chat.completions.create.call_args.kwargs[
        "messages"
    ][0]["content"]
    assert "ran nmap" in prompt
    assert "discover hosts" in prompt


def test_evaluate_retries_transient_errors(monkeypatch):
    fake = Mock()
    fake.chat.completions.create.side_effect = [
        RuntimeError("boom"),
        SimpleNamespace(agent_succeed=True),
    ]
    evaluator = _make_evaluator(monkeypatch, fake)

    assert evaluator._evaluate(
        "step", "milestone", max_retries=3, retry_delay=0
    ) is True
    assert fake.chat.completions.create.call_count == 2


def test_evaluator_fails_closed_after_retries(monkeypatch):
    fake_instructor = Mock()
    fake_instructor.chat.completions.create.side_effect = RuntimeError("offline")
    evaluator = _make_evaluator(monkeypatch, fake_instructor)

    assert evaluator._evaluate(
        "step", "milestone", max_retries=2, retry_delay=0
    ) is False
    assert fake_instructor.chat.completions.create.call_count == 2


# --- Milestone bookkeeping --------------------------------------------------


def test_evaluator_removes_reached_commands_and_unlocks_stages(monkeypatch):
    evaluator = _make_evaluator(
        monkeypatch,
        Mock(),
        commands=["discover", "exploit"],
        stages=["Discovery,1", "Exploitation,2"],
    )
    evaluator._evaluate = Mock(side_effect=[True, False, False])

    first = evaluator.evaluate_step("first step")
    second = evaluator.evaluate_step("second step")

    assert first == {"command": ["discover"], "stage": ["Discovery"]}
    assert second == {"command": [], "stage": []}
    assert evaluator.reached_milestones == 1
    assert evaluator.command_milestones == ["exploit"]
    assert evaluator.stage_milestones == ["Exploitation,2"]


def test_evaluator_supports_commas_in_stage_names(monkeypatch):
    evaluator = _make_evaluator(monkeypatch, Mock(), stages=["Discovery, passive,1"])
    evaluator.reached_milestones = 1

    assert evaluator.evaluate_step("step") == {
        "command": [],
        "stage": ["Discovery, passive"],
    }


def test_evaluator_skips_malformed_stage_milestones(monkeypatch):
    evaluator = _make_evaluator(
        monkeypatch, Mock(), stages=["Discovery", "Exploitation,1"]
    )
    evaluator.reached_milestones = 1

    assert evaluator.evaluate_step("step") == {
        "command": [],
        "stage": ["Exploitation"],
    }
    assert evaluator.stage_milestones == []
