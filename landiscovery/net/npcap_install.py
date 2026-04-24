"""Helper to download and launch the official Npcap installer on Windows."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

import httpx

NPCAP_PAGE = "https://npcap.com/"
_UA = "Mozilla/5.0 (compatible; landiscovery/0.1)"


def find_latest_url(timeout: float = 15.0) -> Optional[str]:
    """Scrape https://npcap.com/ for the newest npcap-X.YZ.exe link."""
    try:
        r = httpx.get(NPCAP_PAGE, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": _UA})
        r.raise_for_status()
    except Exception:
        return None
    matches = re.findall(r'href="([^"]*npcap-[\d\.]+\.exe)"', r.text)
    if not matches:
        return None
    href = matches[0]
    if href.startswith("http"):
        return href
    if href.startswith("/"):
        return "https://npcap.com" + href
    return "https://npcap.com/" + href


def download(url: str, dest: Path, timeout: float = 120.0) -> Path:
    with httpx.stream("GET", url, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": _UA}) as r:
        r.raise_for_status()
        with dest.open("wb") as f:
            for chunk in r.iter_bytes():
                f.write(chunk)
    return dest


def launch_installer(installer: Path) -> int:
    """Launch the installer; Windows UAC will prompt for elevation."""
    if os.name != "nt":
        raise RuntimeError("Npcap is Windows-only.")
    # Use ShellExecute via 'start' to allow the UAC prompt.
    proc = subprocess.run(
        ["cmd", "/c", "start", "/wait", "", str(installer)],
        check=False,
    )
    return proc.returncode


def install_interactive() -> int:
    if os.name != "nt":
        print("Npcap is Windows-only; nothing to do.", file=sys.stderr)
        return 0
    url = find_latest_url()
    if not url:
        print("Could not locate the latest Npcap installer URL.", file=sys.stderr)
        print("Please install manually from https://npcap.com/", file=sys.stderr)
        return 2
    print(f"Downloading Npcap installer:\n  {url}")
    tmp = Path(tempfile.gettempdir()) / Path(url).name
    download(url, tmp)
    print(f"Saved to {tmp}")
    print("Launching installer (Windows will ask for admin permission)...")
    rc = launch_installer(tmp)
    if rc == 0:
        print("Installer finished. Open a NEW terminal so Scapy can pick up Npcap.")
    else:
        print(f"Installer exited with code {rc}.")
    return rc
