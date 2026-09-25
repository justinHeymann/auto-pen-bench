import contextlib
import time

import paramiko
import paramiko.ssh_exception
from pydantic import BaseModel, Field

from autopenbench.shell import clean_output, decode_payload, last_non_empty_line

SSH_TIMEOUT_SECONDS = 10.0


def wait_for_message(shell: paramiko.Channel,
                     timeout: float = SSH_TIMEOUT_SECONDS):
    """Wait until the shell prints a prompt ready for input.

    Args:
        shell (paramiko.Channel): Active shell session.
        timeout (float): Maximum time to wait.

    Returns:
        str: Accumulated output until a prompt is seen (or a timeout notice).
    """
    shell.settimeout(1.0)
    deadline = time.monotonic() + timeout
    out = ''

    while True:
        try:
            chunk = shell.recv(9999)
            if chunk:
                # Same byte-preserving decode as command observations.
                out += decode_payload(chunk)
        except TimeoutError:
            pass
        except (OSError, EOFError):
            break

        # A prompt followed by a newline leaves the final split empty; use the
        # last non-empty line so we do not burn the budget on a ready shell.
        last_line = last_non_empty_line(out)
        if ('@' in last_line and ('$' in last_line or '#' in last_line)) or \
                ('bash' in last_line and ('$' in last_line or '#' in last_line)):
            break

        if time.monotonic() >= deadline:
            return out + '\n[!] Timed out waiting for a shell prompt.'

        time.sleep(.2)

    return out


class SSHConnect(BaseModel):
    """Start an SSH session into the target machine"""
    ssh_ipaddr: str = Field(..., description="Remote server")
    ssh_port: int = Field(...)
    ssh_username: str = Field(...)
    ssh_password: str = Field(...)

    def _open_kali_tunnel(self, ssh_kali: paramiko.SSHClient):
        """Open a TCP tunnel from Kali to the remote machine.

        Args:
            ssh_kali (paramiko.SSHClient): Client connected to Kali.

        Returns:
            paramiko.Channel or str: Tunnel channel, or an error message.
        """
        ssh_kali_transport = ssh_kali.get_transport() if ssh_kali else None
        if ssh_kali_transport is None:
            return 'No active SSH session to the Kali machine'
        local_listen_addr = ('127.0.0.1', 2222)
        remote_addr = (self.ssh_ipaddr, self.ssh_port)

        try:
            return ssh_kali_transport.open_channel(
                "direct-tcpip",
                remote_addr,
                local_listen_addr,
                timeout=10
            )
        except paramiko.ssh_exception.SSHException:
            return f'No SSH service active at {self.ssh_ipaddr}:{self.ssh_port}'

    def _connect_to_remote(self, ssh_kali: paramiko.SSHClient):
        """Connect to the remote host through the Kali tunnel.

        Args:
            ssh_kali (paramiko.SSHClient): Client connected to Kali.

        Returns:
            tuple: ``(shell_channel_or_None, message)``.
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        tunnel = self._open_kali_tunnel(ssh_kali)
        if isinstance(tunnel, str):
            return None, tunnel

        try:
            ssh.connect(
                self.ssh_ipaddr,
                username=self.ssh_username,
                password=self.ssh_password,
                port=int(self.ssh_port),
                sock=tunnel,
                timeout=SSH_TIMEOUT_SECONDS,
                banner_timeout=SSH_TIMEOUT_SECONDS,
                auth_timeout=SSH_TIMEOUT_SECONDS,
            )
            shell = ssh.invoke_shell()
            # Drop login-banner escapes; the agent only needs the prompt.
            msg = clean_output(wait_for_message(shell))
        except Exception as error:
            # Release tunnel and client so failed attempts do not leak channels.
            for closeable in (tunnel, ssh):
                with contextlib.suppress(Exception):
                    closeable.close()
            return None, str(error)

        return shell, msg

    def run(self, ssh_kali: paramiko.SSHClient):
        """Open the SSH connection.

        Args:
            ssh_kali (paramiko.SSHClient): Client connected to Kali.

        Returns:
            tuple: ``(shell_channel_or_None, message)``.
        """
        return self._connect_to_remote(ssh_kali)
