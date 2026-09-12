"""Throwaway validation for the wedge-detection fix in RemoteShell."""
import socket
from unittest.mock import MagicMock

from autopenbench.shell import RemoteShell


def make_rs(shell):
    rs = RemoteShell.__new__(RemoteShell)
    rs.sudo = False
    rs.shell = shell
    rs.msfshell = False
    try:
        rs.shell.settimeout(5.0)
    except Exception:
        pass
    return rs


# 1) Simulate a wedged shell: every recv returns a frozen fingerprint prompt
shell = MagicMock()
shell.recv.side_effect = (
    [b"Are you sure you want to continue connecting (yes/no/[fingerprint])? "]
    + [b"Please type 'yes', 'no' or the fingerprint: "] * 20
)
rs = make_rs(shell)
out = rs.execute_cmd("ssh student@192.168.1.0 id")
assert "None of the sent commands were executed" in out, out
assert "fingerprint" in out
print("WEDGE DETECTION OK")
print("--- observation tail ---")
print("\n".join(out.splitlines()[-3:]))

# 2) Simulate recovery: agent answers the prompt, next command executes
shell2 = MagicMock()
shell2.recv.side_effect = [
    b"Please type 'yes', 'no' or the fingerprint: ",
    b"yes\n",
    b"Warning: Permanently added '192.168.1.0' to the list of known hosts.\r\n"
    b"uid=1000(student) gid=1000(student)\r\n"
    b"student@target:~$ ",
]
rs2 = make_rs(shell2)
out2 = rs2.execute_cmd("yes")
assert "uid=1000(student)" in out2, out2
print("RECOVERY OK: shell accepted the confirmation and executed")

# 3) Sudo branch with an already-ready prompt must not hang
shell3 = MagicMock()
shell3.recv.side_effect = [b"root@target:~# "]
rs3 = make_rs(shell3)
rs3.sudo = True
out3 = rs3.execute_cmd("sudo -l")
assert "root@target" in out3
print("SUDO PROMPT GUARD OK")

# 4) System prompt still yields a valid response model
from autopenbench.runner import SYSTEM_PROMPT, RESPONSE_MODEL

assert "machine_ipaddr" in SYSTEM_PROMPT
assert RESPONSE_MODEL.model_json_schema()["properties"]["action"]["anyOf"]
print("SYSTEM PROMPT + RESPONSE MODEL OK")
