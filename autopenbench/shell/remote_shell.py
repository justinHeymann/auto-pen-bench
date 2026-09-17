import time
import socket
import chardet
import paramiko


def receive_data(shell: paramiko.Channel, timeout: float = 2.0):
    """Receives data from the shell and decodes it using the appropriate
    character encoding.

    Args:
        shell (paramiko.Channel): The active shell session from which to
        receive data.
        timeout (float): Maximum time to wait for any new data before giving up.

    Returns:
        str: Decoded output from the shell session, or an empty string if
        there's a timeout.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            data = shell.recv(65536)
            if not data:
                return ''
            break
        except socket.timeout:
            if time.monotonic() >= deadline:
                return ''
            time.sleep(0.1)
        except (socket.error, OSError, EOFError):
            return ''

    try:
        text_data = data.decode('utf-8')  # Try to decode data using UTF-8
    except UnicodeDecodeError:
        # If UTF-8 decoding fails, use chardet to detect the correct encoding
        # and decode accordingly
        encoding = chardet.detect(data)['encoding']
        # Replace invalid characters
        text_data = data.decode(encoding, errors='replace')

    return text_data  # Return the decoded text data


class RemoteShell():
    """A class to manage an interactive remote shell session.

    Args:
        shell (paramiko.Channel): The shell channel for sending and receiving data.

    Attributes:
        sudo (bool): Indicates whether sudo is in use in the current session.
        shell (paramiko.Channel): The shell session channel.
        msfshell (bool): Indicates whether a Metasploit shell is active.

    Methods:
        check_metasploit_shell(out): Checks if the output is from a Metasploit shell.
        execute_cmd(cmd): Sends a command to the shell and retrieves the output.
    """

    def __init__(self, shell: paramiko.Channel):
        self.sudo = False  # Track if sudo is active
        self.shell = shell  # Store the shell session
        self.msfshell = False  # Track if using a Metasploit shell
        try:
            # Set a timeout for receiving data from the shell
            self.shell.settimeout(5.0)
        except Exception:
            pass

    def check_metasploit_shell(self, out: str):
        """Checks whether the session output indicates a Metasploit shell.

        Args:
            out (str): The shell output to check.

        Returns:
            bool: True if a Metasploit shell is detected and open, False
            otherwise
        """
        # Parse the output line by line
        for l in out.split('\n'):
            if 'Command shell session' in l:
                if 'opened' in l:
                    return True  # If Metasploit shell session is open
                if 'closed' in l:
                    return False  # If Metasploit shell session is closed
        return self.msfshell  # Return the current state of msfshell

    def execute_cmd(self, cmd: str):
        """Sends a command to the remote shell and processes the response.

        Args:
            cmd (str): The command to be executed.

        Returns:
            str: The output from the shell after executing the command.
        """
        # Check if forbidden commands are being used (like netcat or socat)
        for x in cmd.split(' '):
            if x == 'nc' or x == 'socat':
                return "Don't use netcat or socat!"

        # For commands that may prompt for password (sudo, su), use the timeout-based heuristic
        # without the marker, to avoid the marker being consumed as a password.
        # For other commands, use the marker for unambiguous completion detection.
        use_marker = not (cmd[:4] == 'sudo' or cmd[:2] == 'su ' or cmd == 'su')

        if use_marker:
            marker = f'__AUTOPENBENCH_DONE_{time.monotonic_ns()}__'
            deadline = time.monotonic() + 15.0
            self.shell.send(
                f'{cmd}\nprintf "\\n{marker}\\n"\n'
            )  # Send the command and an unambiguous completion marker
            out = receive_data(self.shell, timeout=5.0)  # Receive initial data from the shell
        else:
            marker = None
            deadline = time.monotonic() + 15.0
            self.shell.send(cmd+'\n')  # Send the command to the shell
            out = receive_data(self.shell, timeout=1.0)  # Receive initial data from the shell

        # Special handling for sudo commands. No completion marker was sent
        # for sudo/su (it could be consumed as the password), so the
        # timeout-based heuristic is used instead.
        if cmd[:4] == 'sudo':
            # Password sudo: use the traditional timeout-based approach
            # (no marker sent, so nothing to consume as password)
            self.sudo = True  # Set sudo mode
            # Wait for the shell to ask for the sudo password
            while 'password' not in out.lower():
                last_line = out.split('\n')[-1] if out else ''
                if '$' in last_line or '#' in last_line:
                    if self.sudo:
                        self.sudo = False  # Disable sudo mode if prompt is ready
                    break
                if time.monotonic() >= deadline:
                    return out + '\n[!] Timed out waiting for sudo password prompt.'
                time.sleep(.5)  # Wait before attempting to receive more data
                out += receive_data(self.shell, timeout=1.0)  # Append new data
            # After password flow, switch to non-sudo waiting logic
            self.sudo = False
            # Fall through to the non-sudo handling to wait for the final prompt
        else:
            # Handle non-sudo commands
            last_line = ' '
            retries = 0
            while True:
                if marker is not None and marker in out:
                    break
                lines = out.split('\n')
                lines = [x.strip() for x in lines if x.strip() != '']
                if len(lines) > 0:
                    last_line = lines[-1].strip()

                self.msfshell = self.check_metasploit_shell(out)
                if self.msfshell and 'exit' in cmd:
                    self.msfshell = False

                if not self.sudo:
                    if ('@' in last_line and (
                            last_line[-1] == '$' or last_line[-1] == '#'
                        )) or ('bash' in last_line and (
                            last_line[-1] == '$' or last_line[-1] == '#')):
                        break
                    elif (last_line and last_line[-1] in ['?', '$', '#']) or \
                            'yes/no/[fingerprint]' in last_line.lower() or \
                            '[y/n]' in last_line.lower() or \
                            '--more--' in last_line.lower() or \
                            'msf6' in last_line.lower():
                        retries += 1

                    elif last_line and last_line[-1] == ':' and \
                        '::' not in last_line and \
                            '-->' not in last_line:
                        retries += 1

                    elif last_line and last_line[-1] == '>' and \
                        '<' not in last_line and \
                            '-->' not in last_line:
                        retries += 1

                    if 'What do you want to do about modified configuration '\
                            'file sshd_config?' in out:
                        break
                    if retries == 3:
                        self.shell.send('\n')
                        time.sleep(.5)
                        flushed = receive_data(self.shell, timeout=1.0)
                        if flushed:
                            out += flushed
                        out += '\n[!] The command timed out at an interactive prompt; no further shell output was produced.'
                        break
                else:
                    if last_line and ':' in last_line[-1] and '::' not in last_line:
                        retries += 1
                    if '@' in last_line and ('$' in last_line[-1] or
                                             '#' in last_line[-1]):
                        self.sudo = False
                        break
                    if retries == 3:
                        break

                if time.monotonic() >= deadline:
                    # Strip marker before returning on timeout
                    return out.replace(f'\n{marker}\n', '\n').replace(marker, '') + '\n[!] Timed out waiting for shell prompt after running command.'

                received_data = receive_data(self.shell, timeout=2.0)
                if received_data != '':
                    out = out + received_data

                if self.msfshell:
                    out = f'{out}\nmeterpreter >'
                    break

        if not self.msfshell:
            pass
        else:
            if '^J' in out:
                out = '\n'.join(out.split('^J')[1:])
            else:
                out = '\n'.join(out.split('\n')[1:])

        # Strip the completion marker and its surrounding newlines
        if marker is not None and marker in out:
            out = out.replace(f'\n{marker}\n', '\n').replace(marker, '')

        return out
