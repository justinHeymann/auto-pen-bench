import logging
import os
import re
import time

import chardet
import paramiko

logger = logging.getLogger(__name__)


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


# Network tools the benchmark deliberately withholds from the agent; the
# tasks that need them ship an adapted exploit instead. This filter is a
# guardrail, not a sandbox: it cannot see a withheld tool invoked from inside
# a script written by WriteFile, which is why the images themselves are what
# really enforce the restriction.
FORBIDDEN_NET_TOOLS = frozenset({'nc', 'ncat', 'netcat', 'socat'})

# Commands that run another command given as one of their arguments. Their
# arguments are inspected too, otherwise a withheld tool would be smuggled in
# behind one of them (`sudo nc ...`, `timeout 5 nc ...`, `bash -c 'nc ...'`).
_COMMAND_WRAPPERS = frozenset({
    'bash', 'builtin', 'busybox', 'command', 'dash', 'doas', 'env', 'exec',
    'ionice', 'nice', 'nohup', 'setsid', 'sh', 'stdbuf', 'su', 'sudo', 'time',
    'timeout', 'watch', 'xargs', 'zsh',
})

# Shell control operators that start a new command within the same line.
_SEGMENT_SEPARATORS = re.compile(r'[;&|()\n]+')


def _names_forbidden_tool(token: str) -> bool:
    """True if a single token names a withheld tool.

    Path-qualified and suffixed spellings (``/usr/bin/nc``, ``nc.openbsd``)
    count as well, so only the program name matters.
    """
    program = os.path.basename(token.strip('\'"')).split('.')[0]
    return program in FORBIDDEN_NET_TOOLS


def uses_forbidden_net_tool(cmd: str) -> bool:
    """True if any command in ``cmd`` invokes a withheld network tool.

    The *program* of each shell-separated segment is inspected, so an
    unrelated mention of the name (e.g. ``echo nc``) is not flagged, while
    path-qualified and suffixed forms (``/usr/bin/nc``, ``nc.openbsd``) and
    separator-prefixed forms (``;nc``) still are. Everything after a command
    wrapper (``sudo``, ``timeout``, ``xargs``, ``bash -c``, ...) is inspected
    as well, since that is where a withheld tool would be hiding.
    """
    for segment in _SEGMENT_SEPARATORS.split(cmd):
        tokens = segment.strip().split()
        if not tokens:
            continue
        if _names_forbidden_tool(tokens[0]):
            return True
        if tokens[0] in _COMMAND_WRAPPERS and any(
                _names_forbidden_tool(token) for token in tokens[1:]):
            return True
    return False


# Terminal escape sequences the benchmark images emit around every command:
# bracketed-paste/CSI toggles and systemd's OSC-3008 context blocks
# (`\x1b]3008;start=...;cwd=/root\x1b\\`). They are hundreds of characters per
# command and say nothing about the command's result.
_ESCAPE_SEQUENCES = re.compile(
    r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)'   # OSC ... (BEL | ST)
    r'|\x1b\[[0-9;?]*[ -/]*[@-~]'            # CSI ...
    r'|\x1b[@-Z\\-_]'                       # two-character escapes
)
_RUNS_OF_CR = re.compile(r'\r+\n')
# Where the PTY wraps a line, the last character of the wrapped line is echoed
# again at the start of the next one, separated by the bare CR that resets the
# cursor (`.../tmp/\r/pass.txt`, `h\rhexdump`). Left alone, that duplicate
# lands inside whatever text straddles the wrap -- including the completion
# marker, which then never matches and makes a finished command look like an
# interactive prompt.
_WRAPPED_ECHO = re.compile(r'([^\r\n])\r\1')


def normalize_newlines(text: str) -> str:
    """Normalises the line endings of a PTY into plain LF.

    CRLF runs become a single LF, the duplicated character a wrap inserts into
    the echo is collapsed, and the stray carriage returns the shell integration
    hooks emit to reset the cursor are dropped.

    Args:
        text (str): Raw data received from the shell.

    Returns:
        str: The same text with LF endings, without stray CRs and without the
            character a line-wrap echo duplicates.
    """
    repaired = _WRAPPED_ECHO.sub(r'\1', text)
    return _RUNS_OF_CR.sub('\n', repaired).replace('\r', '')


def clean_output(text: str) -> str:
    """Strips terminal escapes from shell output and normalises line endings.

    Args:
        text (str): Raw data received from the shell.

    Returns:
        str: The same text, without escape sequences and with LF endings.
    """
    return _ESCAPE_SEQUENCES.sub('', normalize_newlines(text))


def decode_payload(data: bytes) -> str:
    """Decode a chunk of shell output without losing or merging any byte.

    Valid UTF-8 -- which is what almost every observation is -- decodes as
    itself. Otherwise chardet is consulted for text in a legacy encoding, but
    only a guess that maps one byte to one character is accepted, because that
    is byte-preserving. A multi-byte guess (chardet reports ``utf-16-be`` at
    0.95 confidence for an ordinary binary chunk) merges bytes into single
    characters: bytes then disappear from the agent's view, and which ones
    disappear depends on where the read happened to split the stream, so the
    same command can yield different observations.

    Everything left over -- a compiled binary, a ciphertext, a memory dump, a
    key file -- is mapped byte-for-byte with latin-1, where every byte has
    exactly one character and the mapping is fixed. Whatever the accepted codec
    cannot map is kept as a ``\\xNN`` escape rather than replaced with U+FFFD,
    which would silently destroy the very bytes the agent is looking at.

    Args:
        data (bytes): A chunk received from the shell.

    Returns:
        str: The decoded text, carrying every byte of ``data``.
    """
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        pass

    encoding = chardet.detect(data)['encoding'] or 'utf-8'
    try:
        candidate = data.decode(encoding, errors='backslashreplace')
    except (LookupError, UnicodeDecodeError):
        candidate = None
    if candidate is not None and len(candidate) == len(data):
        return candidate

    return data.decode('latin-1')


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
        except TimeoutError:
            if time.monotonic() >= deadline:
                return ''
            time.sleep(0.1)
        except (OSError, EOFError):
            return ''

    return decode_payload(data)  # Return the decoded text data


def _looks_like_interactive_prompt(last_line: str) -> bool:
    """True when the last output line looks like a program waiting for input.

    Covers shell prompts and yes/no questions, pagers and msfconsole, plus
    `key:` and `>` continuations -- excluding the `::`, `-->` and `<` forms
    that legitimately end a command's output.
    """
    if not last_line:
        return False
    if last_line == '>':
        # bash's PS2 prompt, i.e. a continuation line of a multi-line command
        # (here-document body, quoted string). It means the command is still
        # being parsed, not that a program is waiting for input.
        return False
    if last_line[-1] in ('?', '$', '#'):
        return True
    lowered = last_line.lower()
    if any(token in lowered for token in
           ('yes/no/[fingerprint]', '[y/n]', '--more--', 'msf6')):
        return True
    if last_line.endswith(':') and '::' not in last_line and '-->' not in last_line:
        return True
    return last_line.endswith('>') and '<' not in last_line and '-->' not in last_line


class RemoteShell:
    """A class to manage an interactive remote shell session.

    Args:
        shell (paramiko.Channel): The shell channel for sending and receiving data.

    Attributes:
        shell (paramiko.Channel): The shell session channel.
        msfshell (bool): Indicates whether a Metasploit shell is active.

    Methods:
        check_metasploit_shell(out): Checks if the output is from a Metasploit shell.
        execute_cmd(cmd): Sends a command to the shell and retrieves the output.
    """

    def __init__(self, shell: paramiko.Channel):
        self.shell = shell  # Store the shell session
        self.msfshell = False  # Track if using a Metasploit shell
        try:
            # Set a timeout for receiving data from the shell
            self.shell.settimeout(5.0)
        except Exception as error:
            # Not fatal: receive_data() also guards against a channel that
            # cannot be configured.
            logger.debug('could not set channel timeout: %s', error)

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
        except Exception as error:
            # A channel that cannot be drained is usually already dead;
            # callers re-check liveness through is_alive().
            logger.debug('could not drain channel: %s', error)

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
            except Exception as error:
                logger.debug('could not read channel transport: %s', error)
                return False
            if transport is not None and not transport.is_active():
                return False
        return True

    def close(self):
        """Closes the channel and the SSH transport serving it.

        A dropped or replaced session must not leave its socket open: the
        driver rebuilds the controller shell whenever sshd dies, and every
        SSHConnect opens one more connection to its target.
        """
        transport = None
        try:
            transport = self.shell.get_transport()
        except Exception as error:
            logger.debug('could not read channel transport: %s', error)
        for closeable in (self.shell, transport):
            if closeable is None:
                continue
            try:
                closeable.close()
            except Exception as error:
                logger.debug('could not close session: %s', error)

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
        for line in out.split('\n'):
            if 'Command shell session' in line:
                if 'opened' in line:
                    return True  # If Metasploit shell session is open
                if 'closed' in line:
                    return False  # If Metasploit shell session is closed
        return self.msfshell  # Return the current state of msfshell

    def _clean(self, out: str, marker: str | None,
               marker_command: str | None) -> str:
        """Removes harness plumbing and terminal escapes from an observation.

        Three things are dropped before the agent sees the output: the shell's
        echo of the ``printf`` line that prints the completion marker (harness
        plumbing, not command output), the marker itself, and the escape
        sequences the benchmark images emit around every command.

        Args:
            out (str): The raw output collected for the command.
            marker (str or None): The completion marker of this command, if a
                marker was sent.
            marker_command (str or None): The command that prints it, if a
                marker was sent.

        Returns:
            str: The observation to hand to the agent.
        """
        out = clean_output(out)
        if marker is not None and marker_command is not None:
            out = out.replace(f'{marker_command}\n', '')
            out = out.replace(f'\n{marker}\n', '\n').replace(marker, '')
        return out

    def execute_cmd(self, cmd: str):
        """Sends a command to the remote shell and processes the response.

        Args:
            cmd (str): The command to be executed.

        Returns:
            str: The output from the shell after executing the command.
        """
        # Check if forbidden commands are being used (like netcat or socat)
        if uses_forbidden_net_tool(cmd):
            return "Don't use netcat or socat!"

        # Flush any stale output left over from the previous command so it
        # cannot be misread as this command's result (see _drain docstring).
        self._drain()

        # For commands that may prompt for a password (sudo, su -- including
        # `su -` and `su - root`), use the timeout-based heuristic *without*
        # the marker: the harness would otherwise type the marker into the
        # password prompt, where it is consumed as the password, and the
        # command could never finish. Every other command gets the marker for
        # unambiguous completion detection.
        tokens = cmd.strip().split()
        first_word = tokens[0] if tokens else ''
        use_marker = first_word not in ('sudo', 'su')

        marker = None
        marker_command = None
        if use_marker:
            marker = f'__AUTOPENBENCH_DONE_{time.monotonic_ns()}__'
            # The marker is printed on a line of its own: `printf` writes its
            # argument with *real* newlines around it, which is what tells its
            # output apart from the shell's echo of this very command line
            # (see the wait loop below).
            marker_command = f'printf "\\n{marker}\\n"'
            deadline = time.monotonic() + command_timeout_seconds()
            # Send the command and an unambiguous completion marker
            self.shell.send(f'{cmd}\n{marker_command}\n')
            out = receive_data(self.shell, timeout=5.0)  # Initial data
        else:
            deadline = time.monotonic() + command_timeout_seconds()
            self.shell.send(cmd+'\n')  # Send the command to the shell
            out = receive_data(self.shell, timeout=1.0)  # Initial data

        # Special handling for sudo commands. No completion marker was sent
        # for sudo/su (it could be consumed as the password), so the
        # timeout-based heuristic is used instead.
        if first_word == 'sudo':
            # Password sudo: wait for the shell to ask for the sudo password,
            # or for the command to finish without asking for one.
            while 'password' not in out.lower():
                last_line = normalize_newlines(out).split('\n')[-1] if out else ''
                if '$' in last_line or '#' in last_line:
                    break
                if time.monotonic() >= deadline:
                    return (self._clean(out, marker, marker_command)
                            + '\n[!] Timed out waiting for sudo password '
                            'prompt.')
                time.sleep(.5)  # Wait before attempting to receive more data
                out += receive_data(self.shell, timeout=1.0)  # Append new data
            # Control continues to the tail below: the prompt has already been
            # surfaced and the agent answers it with its next command, which is
            # why the non-sudo polling loop is intentionally skipped here.
        else:
            # Handle non-sudo commands
            last_line = ' '
            stuck_polls = 0
            # Whether the previous poll came back empty. A command that keeps
            # producing output is not waiting for input, so only silent polls
            # count towards the stuck-command heuristic below.
            quiet = out == ''
            while True:
                # A CRLF split across two reads would only be joined by
                # normalising the buffer as a whole.
                text = normalize_newlines(out)
                # Only the marker's own output may end a marked command. The
                # shell echoes the command line that prints it, and that echo
                # contains the marker text as well, so matching the bare
                # marker would stop at the echo -- before the command's output
                # had been read (the ``printf`` emits *real* newlines around
                # the marker, the echo contains them only as literal ``\n``).
                if marker is not None and f'\n{marker}\n' in text:
                    break
                lines = [x.strip() for x in text.split('\n') if x.strip() != '']
                if len(lines) > 0:
                    last_line = lines[-1].strip()

                self.msfshell = self.check_metasploit_shell(text)
                if self.msfshell and 'exit' in cmd:
                    self.msfshell = False

                # A completion marker was sent for this command, so only the
                # marker (checked at the top of the loop) may end it; a line
                # that merely *looks* like a fresh prompt can be a leftover
                # fragment from the command's own echo arriving before the
                # marker, and must not trigger an early break. Commands sent
                # without a marker (sudo/su) still end on the shell prompt.
                if marker is None and (
                    ('@' in last_line and (
                        last_line[-1] == '$' or last_line[-1] == '#'
                    )) or ('bash' in last_line and (
                        last_line[-1] == '$' or last_line[-1] == '#'))
                ):
                    break
                # A command that is still producing output is not waiting for
                # input, however many prompt-looking lines its output contains:
                # a multi-line send echoes bash's `> ` continuation prompt, a
                # finished command is followed by the shell prompt, and a scan
                # report can end in `host:`-shaped lines. Counting those as
                # evidence of an interactive prompt used to interrupt commands
                # that had already finished (their full output was in the
                # observation, followed by a Ctrl+C). Only a shell that has gone
                # *quiet* with a prompt-like last line is actually stuck.
                if quiet and _looks_like_interactive_prompt(last_line):
                    stuck_polls += 1
                elif not quiet:
                    stuck_polls = 0

                if 'What do you want to do about modified configuration '\
                        'file sshd_config?' in text:
                    break
                if stuck_polls >= 3:
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
                    return (self._clean(out, marker, marker_command)
                            + '\n[!] Timed out waiting for shell prompt '
                            'after running command.')

                received_data = receive_data(self.shell, timeout=2.0)
                quiet = received_data == ''
                if not quiet:
                    out = out + received_data

                if self.msfshell:
                    out = f'{out}\nmeterpreter >'
                    break

        if self.msfshell:
            # Drop the echoed command line, keeping only the session output.
            separator = '^J' if '^J' in out else '\n'
            out = '\n'.join(out.split(separator)[1:])

        return self._clean(out, marker, marker_command)
