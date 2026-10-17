"""
commands.py — Streaming command execution for real-time terminal feel.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Set, Tuple, Any

DEFAULT_TIMEOUT = 120
NMAP_TIMEOUT = 300
MAX_OUTPUT_CHARS = 8000

_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

_NMAP_ROOT_FLAGS: Set[str] = {
    "-sU", "-sS", "-sF", "-sX", "-sN", "-O", "-sV", "--script",
}

# ── Execution failure indicators ───────────────────────────────────────────────
EXECUTION_FAILURE_MARKERS: Tuple[str, ...] = (
    "requires root privileges",
    "quitting!",
    "operation not permitted",
    "permission denied",
    "sudo:",
    "command not found",
    "no such file or directory",
    "[not found]",
    "[timeout]",
    "timed out",
    "host seems down",
    "timeout error",
    "no servers could be reached",
    "[error]",
    "[parallel error]",
)

def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)

def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[... output truncated at {limit} chars ...]"


def output_has_execution_failure(text: str) -> bool:
    """Return True if *text* contains any marker indicating execution failure."""
    lower = text.lower()
    return any(marker in lower for marker in EXECUTION_FAILURE_MARKERS)

def check_tool_exists(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None

def _needs_sudo(args: List[str]) -> bool:
    if not args or args[0] != "nmap":
        return False
    args_lower = [a.lower() for a in args]
    return any(flag.lower() in arg for arg in args_lower for flag in _NMAP_ROOT_FLAGS)

def _inject_sudo(args: List[str]) -> List[str]:
    if not args: return args
    if args[0] == "sudo": return args
    if _needs_sudo(args):
        return ["sudo"] + args
    return args

def format_terminal_output(meta: Dict[str, Any]) -> str:
    """Format the metadata into the specific terminal-style block requested by user."""
    from app.utils.time_utils import convert_utc_to_ist
    start_ist = convert_utc_to_ist(meta.get('start_time'))
    end_ist = convert_utc_to_ist(meta.get('end_time'))

    return f"""=== EXECUTION INFO ===
Command: {meta.get('command')}
Start (IST): {start_ist}
End   (IST): {end_ist}
Duration: {meta.get('duration', 0.0):.2f} sec
======================

{meta.get('output')}"""


def run_command_with_metadata(
    args: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    log_callback: Optional[Callable[[str, str], None]] = None
) -> Dict[str, Any]:
    """
    Execute *args* and stream output line-by-line via log_callback.
    """
    effective_args = _inject_sudo(args)
    command_str = " ".join(effective_args)
    
    start_time = datetime.now()
    
    if log_callback:
        log_callback("EXEC", f"Starting: {command_str}")
        time.sleep(10) # Delay for 10 seconds to allow user to see the command in live feed

    tool = effective_args[0] if effective_args[0] != "sudo" else (
        effective_args[1] if len(effective_args) > 1 else ""
    )
    
    if tool and not check_tool_exists(tool):
        end_time = datetime.now()
        error_msg = f"[NOT FOUND] '{tool}' is not installed."
        meta = {
            "output": error_msg,
            "command": command_str,
            "start_time": start_time,
            "end_time": end_time,
            "duration": 0,
            "returncode": 127
        }
        if log_callback:
            log_callback("TERMINAL", f"ID:[{command_str}]\n" + format_terminal_output(meta))
        return meta

    try:
        # Start process with pipes
        process = subprocess.Popen(
            effective_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Merge stderr into stdout for streaming
            text=True,
            errors="replace",
            bufsize=1 # Line buffered
        )

        full_output = []
        
        # Stream output line by line
        for line in iter(process.stdout.readline, ""):
            stripped_line = _strip_ansi(line)
            full_output.append(stripped_line)
            if log_callback:
                # Send each line immediately to the UI with 'LIVE' stage
                # We use LIVE stage to indicate streaming content
                log_callback("LIVE", f"[{command_str}] {stripped_line}")

        process.stdout.close()
        # Wait for process to finish with a small safety timeout
        try:
            return_code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = -1
            
        end_time = datetime.now()
        output_str = "".join(full_output)
        duration = (end_time - start_time).total_seconds()

        meta = {
            "output": output_str,
            "command": command_str,
            "start_time": start_time,
            "end_time": end_time,
            "duration": duration,
            "returncode": return_code
        }

        if log_callback:
            # Final block for historical reference
            log_callback("TERMINAL", f"ID:[{command_str}]\n" + format_terminal_output(meta))

        return meta

    except Exception as exc:
        end_time = datetime.now()
        msg = f"[ERROR] {exc}"
        meta = {
            "output": msg,
            "command": command_str,
            "start_time": start_time,
            "end_time": end_time,
            "duration": 0,
            "returncode": 1
        }
        if log_callback:
            log_callback("TERMINAL", f"ID:[{command_str}]\n" + format_terminal_output(meta))
        return meta

class CommandCache:
    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None) -> None:
        self._lock = threading.Lock()
        self._store: Dict[str, Dict[str, Any]] = {}
        self.log_callback = log_callback

    def get_or_run(self, args: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        key = " ".join(args)
        with self._lock:
            if key in self._store:
                if self.log_callback: self.log_callback("CACHE", f"Using cached output for: {key}")
                return self._store[key]

        meta = run_command_with_metadata(args, timeout, self.log_callback)
        with self._lock:
            self._store[key] = meta
        return meta

def run_parallel(
    tasks: List[Tuple[str, Callable[[], str]]],
    max_workers: int = 6,
) -> Dict[str, str]:
    results: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn): label for label, fn in tasks}
        for future in as_completed(futures):
            label = futures[future]
            try:
                results[label] = future.result()
            except Exception as exc:
                results[label] = f"[PARALLEL ERROR] {exc}"
    return results
