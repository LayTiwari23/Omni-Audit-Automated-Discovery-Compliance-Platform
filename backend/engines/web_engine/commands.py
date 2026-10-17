"""
commands.py - Reusable command execution and output caching for Web Engine.
Forensic-grade logging enabled.
"""

import subprocess
import shutil
import threading
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Callable, Optional

# --- Execution Constants ---
DEFAULT_TIMEOUT = 35
NMAP_TIMEOUT = 300
TESTSSL_TIMEOUT = 900

_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)

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
    Execute *args* safely and return full metadata.
    """
    command_str = " ".join(args)
    tool = args[0]
    
    if log_callback:
        log_callback("EXEC", f"Executing: {command_str}")
        time.sleep(10) # Delay for 10 seconds to allow user to see the command in live feed
    
    start_time = datetime.now()
    
    if not shutil.which(tool):
        end_time = datetime.now()
        error_msg = f"[NOT FOUND] '{tool}' is not installed or not on PATH."
        meta = {
            "output": error_msg,
            "command": command_str,
            "start_time": start_time,
            "end_time": end_time,
            "duration": (end_time - start_time).total_seconds(),
            "returncode": 127
        }
        if log_callback:
            log_callback("TERMINAL", f"ID:[{command_str}]\n" + format_terminal_output(meta))
        return meta

    try:
        # Start process with pipes
        process = subprocess.Popen(
            args,
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
            "duration": (end_time - start_time).total_seconds(),
            "returncode": 1
        }
        if log_callback:
            log_callback("TERMINAL", f"ID:[{command_str}]\n" + format_terminal_output(meta))
        return meta

class CommandCache:
    """Thread-safe cache for tool outputs with full metadata."""
    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None):
        self._lock = threading.Lock()
        self._store: Dict[str, Dict[str, Any]] = {}
        self.log_callback = log_callback

    def get_or_run(self, args: List[str], timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
        key = " ".join(args)
        with self._lock:
            if key in self._store:
                if self.log_callback:
                    self.log_callback("CACHE", f"Using cached output for: {key}")
                return self._store[key]

        meta = run_command_with_metadata(args, timeout, self.log_callback)
        with self._lock:
            self._store[key] = meta
        return meta

def run_nmap_ports(domain: str, cache: CommandCache, port: int = None) -> Dict[str, Any]:
    if port:
        args = ["nmap", "-sT", "-Pn", "-p", str(port), "--open", "--host-timeout", "600s", domain]
    else:
        args = ["nmap", "-sT", "-Pn", "--top-ports", "1000", "--open", "--host-timeout", "600s", domain]
    return cache.get_or_run(args, NMAP_TIMEOUT)

def run_nmap_methods(domain: str, cache: CommandCache, port: int = None) -> Dict[str, Any]:
    args = ["nmap", "--script", "http-methods", "--script-args", "http-methods.retest"]
    if port:
        args.extend(["-p", str(port)])
    args.append(domain)
    return cache.get_or_run(args, NMAP_TIMEOUT)

def run_curl_headers(url: str, cache: CommandCache, extra_args: List[str] = None) -> Dict[str, Any]:
    # url already contains port if needed (e.g. http://1.2.3.4:8000)
    args = ["curl", "-s", "-I", "-L", "--max-redirs", "5", "--connect-timeout", "10"]
    if extra_args:
        args.extend(extra_args)
    args.append(url)
    return cache.get_or_run(args, DEFAULT_TIMEOUT)

def run_testssl(domain: str, cache: CommandCache, port: int = None) -> Dict[str, Any]:
    binary = shutil.which("testssl.sh") or shutil.which("testssl")
    if not binary:
        binary = "testssl.sh"
    
    target = f"{domain}:{port}" if port else domain
    args = [binary, "--quiet", "--fast", "--warnings", "off", "--color", "0", target]
    return cache.get_or_run(args, TESTSSL_TIMEOUT)

def run_dig_caa(domain: str, cache: CommandCache) -> Dict[str, Any]:
    args = ["dig", "+noall", "+answer", "CAA", domain]
    return cache.get_or_run(args, DEFAULT_TIMEOUT)
