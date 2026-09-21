import argparse
import sys

from mcp import types
from pydantic import Field

from autopenbench.driver import PentestDriver
from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect, WriteFile

try:
    # mcp >= 2.x: FastMCP was renamed to MCPServer
    from mcp.server.mcpserver import MCPServer
except ImportError:  # mcp 1.x compatibility
    from mcp.server.fastmcp import FastMCP as MCPServer

_pentest_driver = None

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


def _no_session() -> list[types.TextContent]:
    return _text(_NO_SESSION_MESSAGE)

def create_mcp_server(task: str, flag: str, target: str) -> MCPServer:
    mcp: MCPServer = MCPServer("pentest_driver")

    # Initialize PentestDriver with the provided arguments
    # Print to stderr only: stdout carries the stdio JSONRPC stream
    global _pentest_driver
    try:
        _pentest_driver = PentestDriver(task, flag, target)
        print(f"MCP Server: PentestDriver initialized with target: {target}",
              file=sys.stderr)
        _pentest_driver.reset()  # reset() starts containers AND connects to Kali
    except Exception as e:
        print(f"MCP Server: Failed to initialize PentestDriver: {e}",
              file=sys.stderr)
        _pentest_driver = None

    @mcp.tool(description="Execute a shell command on a machine")
    async def execute_bash(
        machine_ipaddr: str = Field(..., description="IP address of the target machine"),
        cmd: str = Field(..., description="Bash command to execute")
    ) -> list[types.TextContent]:
        """Execute a shell command on a machine."""
        if _pentest_driver is None:
            return _no_session()

        try:
            out, _ = _pentest_driver.step(
                ExecuteBash(machine_ipaddr=machine_ipaddr, cmd=cmd)
            )
            return _text(out)
        except Exception as e:
            # Surface the failure as an observation: raising here would abort
            # the MCP request and leave the agent with no feedback at all.
            return _text(f"Error executing command: {e!s}")

    @mcp.tool(description="Establish SSH connection to a remote machine")
    async def ssh_connect(
        ssh_ipaddr: str = Field(..., description="Remote server IP address"),
        ssh_port: int = Field(..., description="SSH port number"),
        ssh_username: str = Field(..., description="SSH username"),
        ssh_password: str = Field(..., description="SSH password")
    ) -> list[types.TextContent]:
        """Start an SSH session into the target machine"""
        if _pentest_driver is None:
            return _no_session()

        try:
            out, _ = _pentest_driver.step(
                SSHConnect(
                    ssh_ipaddr=ssh_ipaddr,
                    ssh_port=ssh_port,
                    ssh_username=ssh_username,
                    ssh_password=ssh_password
                )
            )
            return _text(out)
        except Exception as e:
            return _text(f"SSH connection failed: {e!s}")

    @mcp.tool(description="Submit the final answer flag")
    async def final_answer(
        flag: str = Field(..., description="The captured flag")
    ) -> list[types.TextContent]:
        """Provide the final flag of the CTF game. The flag is validated
        against the real one and the result reported to the agent."""
        if _pentest_driver is None:
            return _no_session()

        try:
            out, done = _pentest_driver.step(FinalAnswer(flag=flag))
        except Exception as e:
            return _text(f"Error submitting flag: {e!s}")
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
        if _pentest_driver is None:
            return _no_session()

        try:
            out, _ = _pentest_driver.step(
                WriteFile(content=content, file_name=file_name)
            )
            return _text(out)
        except Exception as e:
            return _text(f"Error writing file: {e!s}")

    return mcp

def main() -> None:
    # Print to stderr only: stdout carries the stdio JSONRPC stream
    print("Starting Pentest Driver MCP Server", file=sys.stderr)

    # Parse command line arguments
    args = parse_args()

    # Create and run the server with the provided arguments
    mcp = create_mcp_server(args.task, args.flag, args.target)
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
