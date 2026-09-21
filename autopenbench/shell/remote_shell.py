import os
import time
import socket
import chardet
import paramiko


# Seconds allowed for a single command to print its completion marker. Keep
# this below the runner's action timeout (genai's ACTION_TIMEOUT_SECONDS, 30 s
# by default): the harness then interrupts the command itself and returns the
# output collected so far, instead of the runner aborting mid-read and leaving
# the command running on the remote host.
DEFAULT_COMMAND_TIMEOUT_SECONDS = 25.0


def command_timeout_seconds() -> float:
    """Seconds to wait for a command's completion marker before interrupting.

    Parsed lazily so a malformed ``AUTOPENBENCH_CMD_TIMEOUT`` raises where it
    is used rather than at import time.
    """
    return float(os.environ.get('AUTOPENBENCH_CMD_TIMEOUT',
                                DEFAULT_COMMAND_TIMEOUT_SECONDS))


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

    def _drain(self):
        """Discard any bytes still buffered from a previous command.

        Without this, a leftover tail (e.g. a prompt echoed just after the
        previous command's completion marker was read) can be mistaken for
        the *next* command's output, permanently shifting every subsequent
        observation by one command.
        """
        try:
            while self.shell.recv_ready():
                self.shell.recv(65536)
        except Exception:
            pass

    def is_alive(self) -> bool:
        """True while the channel can still carry commands.

        A killed sshd (or a torn-down container) closes the channel, after
        which every command fails with 'Socket is closed'. Callers use this
        to re-establish the session instead of looping on dead sockets.
        """
        shell = self.shell
        if shell is None or getattr(shell, 'closed', None) is True:
            return False
        transport_attr = getattr(shell, 'get_transport', None)
        if callable(transport_attr):
            try:
                transport = transport_attr()
            except Exception:
                return False
            if transport is not None and not transport.is_active():
                return False
        return True

    def _interrupt_foreground_process(
            self, reason: str = 'at an interactive prompt') -> str:
        """Escape a command that is still running when its budget runs out.

        Such a command is a problem for two reasons. A program reading the
        channel (like `ssh` asking for a password) already swallowed the
        completion marker, so it would eat the *next* command and its marker
        too. A long-running command (a shell loop, an endless scan) keeps
        writing to the channel, so every later observation returns its output
        instead of the command that was actually sent. Interrupting it makes
        the shell usable again, which is what both cases need.

        Commands that are meant to prompt (sudo/su, sent without a marker) are
        deliberately not interrupted -- the agent answers those with its next
        command.

        Args:
            reason (str): Why the command was interrupted, quoted in the note
                returned to the agent.

        Returns:
            str: Whatever the interrupt produced, plus a note for the agent.
        """
        interrupted = ''
        for _ in range(2):  # some programs need a second Ctrl+C
            try:
                self.shell.send('\x03')
            except Exception as error:
                return (
                    f'\n[!] The shell channel is no longer usable '
                    f'({type(error).__name__}: {error}); the session must be '
                    're-established before any further command.'
                )
            time.sleep(.5)
            received = receive_data(self.shell, timeout=1.0)
            if received:
                interrupted += received
        # Drop anything the aborted command left behind, so it cannot be
        # misread as the next command's output.
        self._drain()
        return interrupted + (
            f'\n[!] The command timed out {reason}; it was interrupted '
            '(Ctrl+C) so the shell stays usable.'
        )

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

        # Flush any stale output left over from the previous command so it
        # cannot be misread as this command's result (see _drain docstring).
        self._drain()

        # For commands that may prompt for password (sudo, su), use the timeout-based heuristic
        # without the marker, to avoid the marker being consumed as a password.
        # For other commands, use the marker for unambiguous completion detection.
        use_marker = not (cmd[:4] == 'sudo' or cmd[:2] == 'su ' or cmd == 'su')

        if use_marker:
            marker = f'__AUTOPENBENCH_DONE_{time.monotonic_ns()}__'
            deadline = time.monotonic() + command_timeout_seconds()
            self.shell.send(
                f'{cmd}\nprintf "\\n{marker}\\n"\n'
            )  # Send the command and an unambiguous completion marker
            out = receive_data(self.shell, timeout=5.0)  # Receive initial data from the shell
        else:
            marker = None
            deadline = time.monotonic() + command_timeout_seconds()
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
                    # A completion marker was sent for this command, so only
                    # the marker (checked at the top of the loop) may end it;
                    # a line that merely *looks* like a fresh prompt can be a
                    # leftover fragment from the command's own echo arriving
                    # before the marker, and must not trigger an early break.
                    if marker is None and (
                        ('@' in last_line and (
                            last_line[-1] == '$' or last_line[-1] == '#'
                        )) or ('bash' in last_line and (
                            last_line[-1] == '$' or last_line[-1] == '#'))
                    ):
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
                        # A marker-carrying command cannot be answered
                        # interactively: the harness already typed the
                        # completion marker, which an interactive program
                        # reads as input, so the command can never finish and
                        # would swallow the next one as well. Escape its
                        # prompt. Commands that are meant to prompt (sudo/su,
                        # sent without a marker) keep their prompt alive --
                        # the agent is expected to send the password next.
                        if marker is not None:
                            out += self._interrupt_foreground_process()
                        else:
                            out += (
                                '\n[!] The command timed out at an '
                                'interactive prompt; the prompt is still '
                                'waiting for input.'
                            )
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
                    # The command never printed its completion marker: it is
                    # either stuck at a prompt or simply outlived its budget
                    # (a shell loop, an endless scan). Left running, it would
                    # keep writing to the channel and every later observation
                    # would show its output instead of its own command's, so
                    # marker-carrying commands are interrupted here as well.
                    # Commands sent without a marker (sudo/su) keep their
                    # prompt alive: the agent answers it with its next
                    # command.
                    if marker is not None:
                        out += self._interrupt_foreground_process(
                            'without printing its completion marker'
                        )
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
