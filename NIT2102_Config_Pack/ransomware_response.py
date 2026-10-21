#!/usr/bin/env python3
"""Safe Wazuh Active Response for the NIT2102 ransomware lab.

The script is intentionally reversible. When Wazuh Rule 100200 fires it:
1. validates that the alert concerns a .locked file under the approved lab path;
2. removes write permissions from matching .locked files to contain further change;
3. records the action in /var/log/ransomware_response.log.

When Wazuh sends the timeout/delete action, saved permissions are restored.
No files are deleted and no network interface is disabled.
"""

import json
import os
import stat
import sys
import time
from pathlib import Path

TARGET_DIR = Path("/home/kali/Healthcare_Data").resolve()
LOG_FILE = Path("/var/log/ransomware_response.log")
STATE_FILE = Path("/var/ossec/active-response/ransomware_response_state.json")


def log(message: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")


def in_scope(path: Path) -> bool:
    try:
        resolved = path.resolve()
        return resolved == TARGET_DIR or TARGET_DIR in resolved.parents
    except OSError:
        return False


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def contain() -> None:
    state = load_state()
    affected = 0
    for path in TARGET_DIR.glob("*.locked"):
        if not in_scope(path) or not path.is_file():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        state[str(path)] = mode
        path.chmod(mode & ~0o222)  # remove all write bits; retain read/execute bits
        affected += 1
        log(f"Contained suspicious file: {path}")
    save_state(state)
    log(f"Containment complete. Files made read-only: {affected}")


def restore() -> None:
    state = load_state()
    restored = 0
    for raw_path, mode in state.items():
        path = Path(raw_path)
        if in_scope(path) and path.exists():
            path.chmod(int(mode))
            restored += 1
    if STATE_FILE.exists():
        STATE_FILE.unlink()
    log(f"Containment timeout ended. Permissions restored: {restored}")


def main() -> int:
    try:
        event = json.loads(sys.stdin.readline())
    except (json.JSONDecodeError, TypeError):
        log("Ignored malformed Active Response input.")
        return 1

    action = event.get("command", "")
    alert = event.get("parameters", {}).get("alert", {})
    alert_path = Path(alert.get("syscheck", {}).get("path", ""))

    if action == "add":
        if not (str(alert_path).endswith(".locked") and in_scope(alert_path)):
            log(f"Ignored out-of-scope alert path: {alert_path}")
            return 0
        log(f"Rule 100200 response triggered for: {alert_path}")
        contain()
        return 0

    if action == "delete":
        restore()
        return 0

    log(f"Ignored unsupported command: {action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
