"""Privilege detection helpers."""
from __future__ import annotations

import ctypes
import os


def is_admin() -> bool:
    """Return True if the current process has admin/root privileges."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def relaunch_as_admin(argv: list[str], keep_window_open: bool = True) -> int:
    """Re-launch the current Python entry point with admin rights via UAC.
    Returns the ShellExecute result (>32 = success). Windows-only.
    The new process runs in its own console; this process should exit afterward.
    """
    if os.name != "nt":
        raise RuntimeError("Elevation prompt is Windows-only.")
    import sys
    # Find the actual command. If running via the installed console-script
    # (landiscovery.exe), sys.argv[0] points to that .exe.
    cmd = sys.argv[0]
    args = " ".join(f'"{a}"' for a in argv)
    # Wrap in cmd /k so the new window stays open after completion.
    if keep_window_open:
        program = "cmd.exe"
        params = f'/k ""{cmd}" {args}"'
    else:
        program = cmd
        params = args
    SW_SHOWNORMAL = 1
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", program, params, None, SW_SHOWNORMAL
    )
    return int(rc)


def npcap_available() -> bool:
    """Best-effort detection of Npcap on Windows (needed for raw ARP via Scapy)."""
    if os.name != "nt":
        return True
    paths = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64", "Npcap"),
    ]
    return any(os.path.isdir(p) for p in paths)
