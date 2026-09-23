"""The MCP server that exposes the driver's tools to the agent.

These tests need the `mcp` SDK; they are skipped when it is not installed.
"""
import asyncio
from unittest.mock import Mock

import pytest


def _registered_tool(server, name):
    """Best-effort lookup of a registered FastMCP tool callable."""
    manager = getattr(server, "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if tools and name in tools:
        return tools[name].fn
    return None


def _server_with(monkeypatch, driver):
    mcp_mod = pytest.importorskip("autopenbench.mcp_server.mcp_server")
    monkeypatch.setattr(mcp_mod, "PentestDriver", Mock(return_value=driver))
    return mcp_mod.create_mcp_server("task", "flag", "target")


def test_mcp_server_initializes_driver(monkeypatch, capsys):
    mcp_mod = pytest.importorskip("autopenbench.mcp_server.mcp_server")
    driver = Mock()
    monkeypatch.setattr(mcp_mod, "PentestDriver", Mock(return_value=driver))

    server = mcp_mod.create_mcp_server("task", "flag", "target")

    assert server is not None
    driver.reset.assert_called_once()  # reset() starts containers and connects to Kali
    assert "initialized with target: target" in capsys.readouterr().err


def test_mcp_server_survives_driver_init_failure(monkeypatch, capsys):
    mcp_mod = pytest.importorskip("autopenbench.mcp_server.mcp_server")
    monkeypatch.setattr(
        mcp_mod, "PentestDriver", Mock(side_effect=RuntimeError("no docker"))
    )

    server = mcp_mod.create_mcp_server("task", "flag", "target")

    assert server is not None
    assert "Failed to initialize PentestDriver" in capsys.readouterr().err


def test_mcp_tools_report_a_missing_session(monkeypatch):
    """A driver that could not be initialized answers every tool with it."""
    mcp_mod = pytest.importorskip("autopenbench.mcp_server.mcp_server")
    monkeypatch.setattr(
        mcp_mod, "PentestDriver", Mock(side_effect=RuntimeError("no docker"))
    )

    server = mcp_mod.create_mcp_server("task", "flag", "target")
    tool = _registered_tool(server, "execute_bash")
    if tool is None:
        pytest.skip("FastMCP internals not accessible in this version")

    contents = asyncio.run(tool(machine_ipaddr="192.168.0.5", cmd="id"))

    assert contents[0].text == mcp_mod._NO_SESSION_MESSAGE


def test_mcp_tools_report_driver_failures_as_text(monkeypatch):
    driver = Mock()
    driver.step.side_effect = RuntimeError("channel exploded")

    server = _server_with(monkeypatch, driver)
    tool = _registered_tool(server, "execute_bash")
    if tool is None:
        pytest.skip("FastMCP internals not accessible in this version")

    contents = asyncio.run(tool(machine_ipaddr="192.168.0.5", cmd="id"))

    assert "Error executing command" in contents[0].text
    assert "channel exploded" in contents[0].text


def test_mcp_tools_let_the_action_timeout_reach_the_caller(monkeypatch):
    """The runner's action timeout must not become an observation.

    `TimeoutError` is raised from the runner's SIGALRM handler inside
    ``driver.step()``. Turned into text it would be scored as the agent's own
    action instead of an action timeout, which the runner refunds and does not
    judge.
    """
    driver = Mock()
    driver.step.side_effect = TimeoutError(
        "Action exceeded the 30-second timeout"
    )

    server = _server_with(monkeypatch, driver)
    tool = _registered_tool(server, "execute_bash")
    if tool is None:
        pytest.skip("FastMCP internals not accessible in this version")

    with pytest.raises(TimeoutError):
        asyncio.run(tool(machine_ipaddr="192.168.0.5", cmd="nmap -sn 10.0.0.0/24"))
