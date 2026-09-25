import argparse
import sys

import anyio
from mcp import types
from pydantic import Field

from autopenbench.driver import PentestDriver
from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect, WriteFile

try:
    # mcp >= 2.x: FastMCP was renamed to MCPServer
    from mcp.server.mcpserver import MCPServer
except ImportError:  # mcp 1.x compatibility
    from mcp.server.fastmcp import FastMCP as MCPServer

_NO_SESSION_MESSAGE = "Error: No pentest session initialized."


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Pentest Driver MCP Server')
    parser.add_argument('--task', required=True, help='The pentesting task')
    parser.add_argument('--flag', required=True, help='The flag to find')
    parser.add_argument('--target', required=True, help='The target machine')
    return parser.parse_args()


def _text(message: str) -> list[types.TextContent]:
    """Wrap a message as the single text content an MCP tool returns."""
    return [types.TextContent(type="text", text=message)]


def create_mcp_server(task: str, flag: str, target: str) -> MCPServer:
    mcp: MCPServer = MCPServer("pentest_driver")

    # Keep the driver in a closure (not module-level) so two servers in one
    # process cannot share the newer driver's state. stderr only: stdout is
    # the stdio JSON-RPC stream.
    try:
        driver = PentestDriver(task, flag, target)
        print(f"MCP Server: PentestDriver initialized with target: {target}",
              file=sys.stderr)
        driver.reset()
    except Exception as e:
        print(f"MCP Server: Failed to initialize PentestDriver: {e}",
              file=sys.stderr)
        driver = None

    def run_step(tool, error_label: str) -> tuple:
        """Run a tool through the driver, turning failures into observations.

        Raising here would abort the MCP request and leave the agent with no
        feedback at all, so a failure is reported as text instead.

        Args:
            tool: The tool to execute (SSHConnect, ExecuteBash, ...).
            error_label (str): Prefix of the message reported on failure.

        Returns:
            tuple: The observation and whether the pentest is complete.
        """
        if driver is None:
            return _NO_SESSION_MESSAGE, False
        try:
            return driver.step(tool)
        except TimeoutError:
            # The caller's own action budget expiring (the runner raises it
            # from a SIGALRM handler inside the call). Reported as text it
            # would be scored as the agent's own action instead of an action
            # timeout, so it is passed through for the caller to classify.
            raise
        except Exception as e:
            return f"{error_label}: {e!s}", False

    # driver.step() blocks (docker subprocess calls, socket reads of up to
    # the command timeout), so tools run it in a worker thread to keep the
    # event loop responsive. The lock serializes steps because the driver is
    # stateful (one shared shell per remote).
    step_lock = anyio.Lock()

    @mcp.tool(description="Execute a shell command on a machine")
    async def execute_bash(
        machine_ipaddr: str = Field(..., description="IP address of the target machine"),
        cmd: str = Field(..., description="Bash command to execute")
    ) -> list[types.TextContent]:
        """Execute a shell command on a machine."""
        async with step_lock:
            out, _ = await anyio.to_thread.run_sync(
                run_step,
                ExecuteBash(machine_ipaddr=machine_ipaddr, cmd=cmd),
                "Error executing command",
            )
        return _text(out)

    @mcp.tool(description="Establish SSH connection to a remote machine")
    async def ssh_connect(
        ssh_ipaddr: str = Field(..., description="Remote server IP address"),
        ssh_port: int = Field(..., description="SSH port number"),
        ssh_username: str = Field(..., description="SSH username"),
        ssh_password: str = Field(..., description="SSH password")
    ) -> list[types.TextContent]:
        """Start an SSH session into the target machine"""
        async with step_lock:
            out, _ = await anyio.to_thread.run_sync(
                run_step,
                SSHConnect(
                    ssh_ipaddr=ssh_ipaddr,
                    ssh_port=ssh_port,
                    ssh_username=ssh_username,
                    ssh_password=ssh_password
                ),
                "SSH connection failed",
            )
        return _text(out)

    @mcp.tool(description="Submit the final answer flag")
    async def final_answer(
        flag: str = Field(..., description="The captured flag")
    ) -> list[types.TextContent]:
        """Provide the final flag of the CTF game. The flag is validated
        against the real one and the result reported to the agent."""
        async with step_lock:
            out, done = await anyio.to_thread.run_sync(
                run_step, FinalAnswer(flag=flag), "Error submitting flag")
        if done:
            out += "\nThe pentest is complete."
        return _text(out)

    @mcp.tool(description="Write content to a file")
    async def write_file(
        content: str = Field(..., description="Content to write to the file"),
        file_name: str = Field(..., description="Name of the file to create")
    ) -> list[types.TextContent]:
        """Write a script or a text into a file. The file will be located in
        the /root/scripts folder of Kali machine."""
        async with step_lock:
            out, _ = await anyio.to_thread.run_sync(
                run_step,
                WriteFile(content=content, file_name=file_name),
                "Error writing file",
            )
        return _text(out)

    return mcp


def main() -> None:
    # stderr only: stdout carries the stdio JSON-RPC stream
    print("Starting Pentest Driver MCP Server", file=sys.stderr)

    args = parse_args()
    mcp = create_mcp_server(args.task, args.flag, args.target)
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
