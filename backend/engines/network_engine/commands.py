"""
commands.py — Safe command execution, sudo injection, output caching, and parallel dispatch.
Forensic-grade logging enabled.
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

# ── Constants ─────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 120
NMAP_TIMEOUT = 300
MAX_OUTPUT_CHARS = 8000

_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# ── nmap flags / scripts that require root (raw socket access) ────────────────
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


# ── Output helpers ────────────────────────────────────────────────────────────
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


# ── Tool availability ─────────────────────────────────────────────────────────
def check_tool_exists(tool_name: str) -> bool:
    """Return True if *tool_name* is on PATH and executable."""
    return shutil.which(tool_name) is not None


# ── sudo injection ────────────────────────────────────────────────────────────
def _needs_sudo(args: List[str]) -> bool:
    """Return True if this nmap invocation requires root privileges."""
    if not args or args[0] != "nmap":
        return False
    args_lower = [a.lower() for a in args]
    return any(flag.lower() in arg for arg in args_lower for flag in _NMAP_ROOT_FLAGS)


def _inject_sudo(args: List[str]) -> List[str]:
    """Prepend 'sudo' to *args* if root is required and not already present."""
    if args and args[0] == "sudo":
        return args
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


# ── Core executor ─────────────────────────────────────────────────────────────
def run_command_with_metadata(
    args: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    log_callback: Optional[Callable[[str, str], None]] = None
) -> Dict[str, Any]:
    """
    Execute *args* safely and return full metadata.
    """
    effective_args = _inject_sudo(args)
    command_str = " ".join(effective_args)
    
    if log_callback:
        log_callback("EXEC", f"Executing: {command_str}")
        time.sleep(10) # Delay for 10 seconds to allow user to see the command in live feed
    
    tool = effective_args[0] if effective_args[0] != "sudo" else (
        effective_args[1] if len(effective_args) > 1 else ""
    )
    
    start_time = datetime.now()
    
    if tool and not check_tool_exists(tool):
        end_time = datetime.now()
        error_msg = f"[NOT FOUND] '{tool}' is not installed or not on PATH."
        meta = {
            "output": error_msg,
            "command": command_str,
            "start_time": start_time,
            "end_time": end_time,
            "duration": (end_time - start_time).total_seconds()
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
                log_callback("LIVE", f"[{command_str}] {stripped_line}")

        process.stdout.close()
        # Wait for process to finish using the provided timeout
        try:
            return_code = process.wait(timeout=timeout)
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
            "duration": (end_time - start_time).total_seconds()
        }
        if log_callback:
            log_callback("TERMINAL", f"ID:[{command_str}]\n" + format_terminal_output(meta))
        return meta


def run_command(
    args: List[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[str, str]:
    """Execute *args* safely (no shell=True). Returns (stdout, stderr)."""
    effective_args = _inject_sudo(args)

    tool = effective_args[0] if effective_args[0] != "sudo" else (
        effective_args[1] if len(effective_args) > 1 else ""
    )
    if tool and not check_tool_exists(tool):
        return "", f"[NOT FOUND] '{tool}' is not installed or not on PATH."

    try:
        result = subprocess.run(
            effective_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )
        stdout = _strip_ansi(result.stdout.decode("utf-8", errors="replace"))
        stderr = _strip_ansi(result.stderr.decode("utf-8", errors="replace"))
        return stdout, stderr
    except subprocess.TimeoutExpired:
        return "", f"[TIMEOUT] Command exceeded {timeout}s: {' '.join(effective_args)}"
    except FileNotFoundError as exc:
        return "", f"[NOT FOUND] {exc}"
    except PermissionError as exc:
        return "", f"[PERMISSION ERROR] {exc}"
    except Exception as exc:
        return "", f"[ERROR] {exc}"


def run_command_combined(
    args: List[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Return stdout + stderr as a single string, truncated for DB storage."""
    effective_args = _inject_sudo(args)
    effective_cmd = " ".join(effective_args)

    stdout, stderr = run_command(args, timeout)

    parts = [f"[CMD] {effective_cmd}"]
    if stdout.strip():
        parts.append(stdout.strip())
    if stderr.strip():
        parts.append(f"--- stderr ---\n{stderr.strip()}")

    combined = "\n".join(parts)
    return _truncate(combined.strip())


def run_command_with_retry(
    args: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    max_retries: int = 2,
    delay: int = 2,
) -> str:
    """Run a command with retry on transient failures."""
    for attempt in range(max_retries):
        output = run_command_combined(args, timeout)
        if not output_has_execution_failure(output):
            return output
        if attempt < max_retries - 1:
            time.sleep(delay)
    return output


# ── Cache ─────────────────────────────────────────────────────────────────────
class CommandCache:
    """Thread-safe, per-scan cache. Stores and returns full metadata dict."""

    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._store: Dict[str, Dict[str, Any]] = {}
        self._running: Dict[str, threading.Event] = {}
        self.log_callback = log_callback

    def _key(self, args: List[str]) -> str:
        return " ".join(args)

    def get_or_run(self, args: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        key = self._key(args)

        with self._lock:
            if key in self._store:
                if self.log_callback:
                    self.log_callback("CACHE", f"Using cached output for: {key}")
                return self._store[key]

            if key not in self._running:
                event = threading.Event()
                self._running[key] = event
                first_caller = True
            else:
                event = self._running[key]
                first_caller = False

        if first_caller:
            meta = run_command_with_metadata(args, timeout, self.log_callback)
            with self._lock:
                self._store[key] = meta
                del self._running[key]
                event.set()
            return meta
        else:
            event.wait(timeout=timeout + 10)
            with self._lock:
                return self._store.get(key, {"output": "[ERROR] Cache miss", "command": key})


# ── Parallel dispatcher ───────────────────────────────────────────────────────
def run_parallel(
    tasks: List[Tuple[str, Callable[[], str]]],
    max_workers: int = 6,
) -> Dict[str, str]:
    """Run a list of (label, callable) tasks concurrently."""
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
