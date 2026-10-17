"""
parser.py - Tool output parsers for Web Engine.
"""

import re
from typing import List, Optional, Dict

def _parse_headers(raw: str) -> dict:
    headers: dict = {}
    blocks = re.split(r"\r?\n\r?\n", raw.strip())
    for block in blocks:
        for line in block.splitlines():
            if ":" in line and not line.upper().startswith("HTTP/"):
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()
    return headers

def _split_http_responses(raw: str) -> list[str]:
    blocks = []
    current = []
    for line in raw.splitlines():
        if line.upper().startswith("HTTP/"):
            if current:
                blocks.append("\n".join(current))
                current = []
        current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks

def _parse_response_block(block: str) -> dict:
    lines = block.splitlines()
    status_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ": " in line:
            key, val = line.split(": ", 1)
            headers[key.strip().lower()] = val.strip()
    return {"status_line": status_line, "headers": headers}

def _first_response_block(raw: str) -> dict:
    blocks = _split_http_responses(raw)
    if blocks:
        return _parse_response_block(blocks[0])
    return {"status_line": "", "headers": {}}

def _final_response_block(raw: str) -> dict:
    blocks = _split_http_responses(raw)
    if blocks:
        return _parse_response_block(blocks[-1])
    return {"status_line": "", "headers": {}}

def _extract_nmap_section(raw: str, keyword: str) -> str:
    lines = raw.splitlines()
    hits = [i for i, l in enumerate(lines) if keyword.lower() in l.lower()]
    if not hits:
        return f"No '{keyword}' section found in nmap output"
    first = max(0, hits[0] - 2)
    last = min(len(lines), hits[-1] + 5)
    return "\n".join(lines[first:last])

def _extract_testssl_section(raw: str, *keywords: str) -> str:
    matched = []
    for line in raw.splitlines():
        if any(kw.lower() in line.lower() for kw in keywords):
            matched.append(line.rstrip())
        if len(matched) >= 10:
            break
    return "\n".join(matched) if matched else "Not found in testssl output"

def _vuln_pass(raw: str, *keywords: str) -> bool:
    section = _extract_testssl_section(raw, *keywords)
    if "Not found" in section:
        return False
    lower = section.lower()
    if any(tok in lower for tok in ["not vulnerable", "not affected", "not offered"]):
        return True
    if any(tok in lower for tok in ["vulnerable", "offered", "affected"]):
        return False
    return False

def _extract_header_line(raw: str, header_name: str) -> str:
    pattern = re.compile(rf"^{re.escape(header_name)}\s*:.*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(raw)
    return match.group(0).strip() if match else ""
