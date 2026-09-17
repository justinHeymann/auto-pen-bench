import argparse
import mcp.types as types
from mcp.server.fastmcp import FastMCP
from pydantic import Field
from autopenbench.tools import SSHConnect, ExecuteBash, WriteFile, FinalAnswer
from autopenbench.driver import PentestDriver

_pentest_driver = None

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Pentest Driver MCP Server')
    parser.add_argument('--task', required=True, help='The pentesting task')
    parser.add_argument('--flag', required=True, help='The flag to find') 
    parser.add_argument('--target', required=True, help='The target machine')
    return parser.parse_args()

def create_mcp_server(task: str, flag: str, target: str) -> FastMCP:
    mcp: FastMCP = FastMCP("pentest_driver")
    
    # Initialize PentestDriver with the provided arguments
    global _pentest_driver
    try:
        _pentest_driver = PentestDriver(task, flag, target)
        print(f"MCP Server: PentestDriver initialized with target: {target}")
        _pentest_driver.start_containers()
    except Exception as e:
        print(f"MCP Server: Failed to initialize PentestDriver: {e}")
        _pentest_driver = None
    
    @mcp.tool(description="Execute a shell command on a machine")
    async def execute_bash(
        machine_ipaddr: str = Field(..., description="IP address of the target machine"),
        cmd: str = Field(..., description="Bash command to execute")
    ) -> list[types.TextContent]:
        """Execute a shell command on a machine."""
        if _pentest_driver is None:
            return [types.TextContent(type="text", text="Error: No pentest session initialized.")]

        out, _ = _pentest_driver.step(
            ExecuteBash(machine_ipaddr=machine_ipaddr, cmd=cmd)
        )
        return [types.TextContent(type="text", text=out)]

    @mcp.tool(description="Establish SSH connection to a remote machine")
    async def ssh_connect(
        ssh_ipaddr: str = Field(..., description="Remote server IP address"),
        ssh_port: int = Field(..., description="SSH port number"),
        ssh_username: str = Field(..., description="SSH username"),
        ssh_password: str = Field(..., description="SSH password")
    ) -> list[types.TextContent]:
        """Start an SSH session into the target machine"""
        if _pentest_driver is None:
            return [types.TextContent(type="text", text="Error: No pentest session initialized.")]

        try:
            out, _ = _pentest_driver.step(
                SSHConnect(
                    ssh_ipaddr=ssh_ipaddr,
                    ssh_port=ssh_port,
                    ssh_username=ssh_username,
                    ssh_password=ssh_password
                )
            )
            return [types.TextContent(type="text", text=out)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"SSH connection failed: {str(e)}")]

    @mcp.tool(description="Submit the final answer flag")
    async def final_answer(
        flag: str = Field(..., description="The captured flag")
    ) -> list[types.TextContent]:
        """Provide the final flag of the CTF game. The flag is validated
        against the real one and the result reported to the agent."""
        if _pentest_driver is None:
            return [types.TextContent(type="text", text="Error: No pentest session initialized.")]

        out, done = _pentest_driver.step(FinalAnswer(flag=flag))
        if done:
            out += "\nThe pentest is complete."
        return [types.TextContent(type="text", text=out)]

    @mcp.tool(description="Write content to a file")
    async def write_file(
        content: str = Field(..., description="Content to write to the file"),
        file_name: str = Field(..., description="Name of the file to create")
    ) -> list[types.TextContent]:
        """Write a script or a text into a file. The file will be located in the /root/scripts folder of Kali machine."""
        if _pentest_driver is None:
            return [types.TextContent(type="text", text="Error: No pentest session initialized.")]

        out, _ = _pentest_driver.step(
            WriteFile(content=content, file_name=file_name)
        )
        return [types.TextContent(type="text", text=out)]

    return mcp

def main() -> None:
    print("Starting Pentest Driver MCP Server")
    
    # Parse command line arguments
    args = parse_args()
    
    # Create and run the server with the provided arguments
    mcp = create_mcp_server(args.task, args.flag, args.target)
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
