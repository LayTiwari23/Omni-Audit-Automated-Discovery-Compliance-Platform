"""
Command execution utilities with forensic logging and caching.
"""

import logging
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Union

logger = logging.getLogger(__name__)


class CommandCache:
    """Caches command results during a scan to avoid redundant execution."""

    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get_or_run(self, command: Union[str, List[str]], timeout: int = 120) -> Dict[str, Any]:
        """
        Run a shell command and return its metadata and output.
        The result is cached for the lifetime of the instance.
        """
        cmd_str = command if isinstance(command, str) else " ".join(command)
        cmd_args = shlex.split(cmd_str) if isinstance(command, str) else command

        if cmd_str in self._cache:
            logger.debug("Cache hit for command: %s", cmd_str)
            return self._cache[cmd_str]

        logger.info("Executing: %s", cmd_str)
        start_time = datetime.now(timezone.utc)
        start_monotonic = time.monotonic()
        
        try:
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout + result.stderr
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            output = f"Command timed out after {timeout} seconds"
            returncode = -1
            logger.error("Command timed out: %s", cmd_str)
        except FileNotFoundError:
            output = f"Command not found: {cmd_args[0]}"
            returncode = -1
            logger.error("Command not found: %s", cmd_str)
        except Exception as exc:
            output = f"Error executing command: {exc}"
            returncode = -1
            logger.exception("Command execution failed: %s", cmd_str)
        
        end_time = datetime.now(timezone.utc)
        duration = time.monotonic() - start_monotonic

        meta = {
            "command": cmd_str,
            "output": output,
            "returncode": returncode,
            "start_time": start_time,
            "end_time": end_time,
            "duration": duration
        }

        self._cache[cmd_str] = meta
        return meta

    def execute(self, command: str, timeout: int = 120) -> str:
        """Legacy wrapper for backward compatibility."""
        return self.get_or_run(command, timeout)["output"]

    def clear_cache(self) -> None:
        """Clear all cached results."""
        self._cache.clear()


def check_tool_exists(tool_name: str) -> bool:
    """
    Verify that a required command-line tool is available in the system PATH.
    Returns True if found, False otherwise.
    """
    exists = shutil.which(tool_name) is not None
    if not exists:
        logger.warning("Required tool not found: %s", tool_name)
    return exists
