"""
checks.py - Web compliance checks with Forensic-grade logging.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict
from .commands import run_nmap_ports, run_nmap_methods, run_curl_headers, run_testssl, run_dig_caa, CommandCache
from .parser import (
    _first_response_block, _final_response_block, _extract_nmap_section,
    _extract_testssl_section, _vuln_pass, _extract_header_line, _parse_headers,
    _split_http_responses, _parse_response_block
)

# Optional: Import CVSS/Remediation if they exist in the project
try:
    from threat.cvss_service import get_cvss_for_check
    from remediation.remediation_engine import get_remediation
except ImportError:
    def get_cvss_for_check(id, name): return {}
    def get_remediation(id): return {}

def format_forensic_output(meta: Dict[str, Any]) -> str:
    """Format the metadata into a terminal-style banner at the top."""
    return f"""=== EXECUTION INFO ===
Command: {meta.get('command')}
Start (UTC): {meta.get('start_time')}
End   (UTC): {meta.get('end_time')}
Duration: {meta.get('duration'):.2f} sec
======================

{meta.get('output')}"""

def _build_result(check_id, name, tool, meta, logic, result):
    # Base structure
    res_dict = {
        "check_id": check_id,
        "check_name": name,
        "tool_name": tool,
        "command_executed": meta.get('command', 'N/A'),
        "raw_output": format_forensic_output(meta),
        "decision_logic": logic,
        "result": result,
        "execution_start": meta.get('start_time'),
        "execution_end": meta.get('end_time'),
        "execution_duration": meta.get('duration', 0.0),
        "cvss_score": 0.0,
        "severity": "",
        "cve_id": None,
        "remediation_text": "",
        "remediation_example": "",
        "remediation_reference": ""
    }
    
    # Enrichment for non-PASS results
    if result in ["FAIL", "INCONCLUSIVE"]:
        cvss = get_cvss_for_check(check_id, name)
        
        # Pass context for Dynamic AI Remediation if available
        finding_context = {
            "check_name": name,
            "raw_output": res_dict["raw_output"],
            "summary": logic
        }
        rem = get_remediation(check_id, finding_details=finding_context)
        
        res_dict.update({
            "cvss_score": cvss.get("cvss_score", 0.0),
            "severity": cvss.get("severity", ""),
            "cve_id": cvss.get("cve_id"),
            "remediation_text": rem.get("fix", ""),
            "remediation_example": rem.get("example", ""),
            "remediation_reference": rem.get("reference", "")
        })
        
    return res_dict

# --- 28 Web Checks ---

def check_01_port_lockdown(domain, cache, port=None):
    meta = run_nmap_ports(domain, cache, port=port)
    stdout = meta['output']
    allowed = {"80", "443"}
    open_ports = []
    for line in stdout.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open", line)
        if m: open_ports.append(m.group(1))
    forbidden = [p for p in open_ports if p not in allowed]
    result = "PASS" if not forbidden else "FAIL"
    logic = f"Allowed ports: 80, 443. Open ports found: {', '.join(open_ports)}. Unexpected ports: {', '.join(forbidden) if forbidden else 'none'}."
    return _build_result(1, "Port 80 and 443 are only open", "nmap", meta, logic, result)

def check_02_http_only(domain, cache, port=None):
    url = f"http://{domain}" if not port else f"http://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    first = _first_response_block(stdout)
    status = first["status_line"]
    loc = first["headers"].get("location", "")
    is_redir = bool(re.search(r"30[12378]", status))
    is_https = loc.lower().startswith("https://")
    result = "PASS" if (is_redir and is_https) else "FAIL"
    logic = f"First status: {status}. Location: {loc}. Redirects to HTTPS: {is_https}."
    return _build_result(2, "Website should not be operational over http only", "curl", meta, logic, result)

def check_03_https_operational(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    final = _final_response_block(stdout)
    status = final["status_line"]
    m = re.search(r"\s(\d{3})\s", status)
    code_val = int(m.group(1)) if m else 0
    result = "PASS" if 200 <= code_val < 400 else "FAIL"
    logic = f"Final HTTP status code: {code_val}."
    return _build_result(3, "Website is operational over https", "curl", meta, logic, result)

def check_04_server_version(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    line = _extract_header_line(stdout, "Server")
    has_ver = bool(re.search(r"\d", line))
    result = "PASS" if not has_ver else "FAIL"
    logic = f"Server header must not include version numbers. Found: '{line}'."
    return _build_result(4, "Header: Webserver version display is disabled", "curl", meta, logic, result)

def check_05_software_version(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    hdrs = _parse_headers(stdout)
    keys = ["x-powered-by", "x-generator", "x-aspnet-version"]
    found = [f"{k}: {hdrs[k]}" for k in keys if hdrs.get(k)]
    has_ver = any(re.search(r"\d", d) for d in found)
    result = "PASS" if not has_ver else "FAIL"
    logic = f"Software version headers found: {', '.join(found) if found else 'none'}."
    return _build_result(5, "Header: PHP/CMS/Other software version display is disabled", "curl", meta, logic, result)

def check_06_etag(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    line = _extract_header_line(stdout, "ETag")
    is_leaky = bool(re.search(r'"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"', line, re.I))
    result = "PASS" if not is_leaky else "FAIL"
    logic = f"ETag value: '{line if line else 'absent'}'."
    return _build_result(6, "Header: E-tag should not leak/display sensitive information", "curl", meta, logic, result)

def check_07_xss_protection(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    line = _extract_header_line(stdout, "X-XSS-Protection")
    ok = bool(line) and not line.strip().endswith(": 0")
    result = "PASS" if ok else "FAIL"
    logic = f"X-XSS-Protection should be enabled. Found: '{line}'."
    return _build_result(7, "Header: X-XSS-Protection is enabled", "curl", meta, logic, result)

def check_08_xframe_options(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    line = _extract_header_line(stdout, "X-Frame-Options")
    ok = any(v in line.upper() for v in ["DENY", "SAMEORIGIN"])
    result = "PASS" if ok else "FAIL"
    logic = f"X-Frame-Options should be DENY or SAMEORIGIN. Found: '{line}'."
    return _build_result(8, "Header: X-Frame-Options is enabled", "curl", meta, logic, result)

def check_09_hsts(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    line = _extract_header_line(stdout, "Strict-Transport-Security")
    ok = bool(line) and "max-age" in line.lower()
    result = "PASS" if ok else "FAIL"
    logic = f"HSTS header found: '{line}'."
    return _build_result(9, "Header: Enabled with Strict-Transport-Security", "curl", meta, logic, result)

def check_10_csp(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    line = _extract_header_line(stdout, "Content-Security-Policy")
    result = "PASS" if line else "FAIL"
    logic = f"CSP header found: '{line}'."
    return _build_result(10, "Header: Content-Security-Policy is enabled", "curl", meta, logic, result)

def check_11_cookie_flags(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    cookies = [l for l in stdout.splitlines() if l.lower().startswith("set-cookie:")]
    if not cookies:
        return _build_result(11, "Header: Cookies is set as HttpOnly and Secure", "curl", meta, "No cookies set – N/A.", "PASS")
    bad = [c for c in cookies if "httponly" not in c.lower() or "secure" not in c.lower()]
    result = "PASS" if not bad else "FAIL"
    logic = f"Found {len(cookies)} cookies, {len(bad)} issues with HttpOnly/Secure."
    return _build_result(11, "Header: Cookies is set as HttpOnly and Secure", "curl", meta, logic, result)

def check_12_cookie_samesite(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    cookies = [l for l in stdout.splitlines() if l.lower().startswith("set-cookie:")]
    if not cookies:
        return _build_result(12, 'Header: Cookie parameter "SameSite" is set to either Strict or Lax', "curl", meta, "No cookies set – N/A.", "PASS")
    bad = [c for c in cookies if "samesite=strict" not in c.lower() and "samesite=lax" not in c.lower()]
    result = "PASS" if not bad else "FAIL"
    logic = f"Found {len(cookies)} cookies, {len(bad)} issues with SameSite."
    return _build_result(12, 'Header: Cookie parameter "SameSite" is set to either Strict or Lax', "curl", meta, logic, result)

def check_13_cache_control(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    line = _extract_header_line(stdout, "Cache-Control")
    result = "PASS" if line else "FAIL"
    logic = f"Cache-Control found: '{line}'."
    return _build_result(13, "Header: Cache-control is set", "curl", meta, logic, result)

def check_14_http_methods(domain, cache, port=None):
    meta = run_nmap_methods(domain, cache, port=port)
    stdout = meta['output']
    dang = ["PUT", "TRACE", "DELETE", "OPTIONS"]
    section = _extract_nmap_section(stdout, "http-methods")
    found = [m for m in dang if m in section.upper()]
    result = "PASS" if not found else "FAIL"
    logic = f"Dangerous HTTP methods detected: {', '.join(found) if found else 'none'}."
    return _build_result(14, "HTTP Methods like PUT, TRACE, DELETE, OPTION, TRACE are disabled", "nmap", meta, logic, result)

def check_15_cms_admin_exposed(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache)
    stdout = meta['output']
    loc = _extract_header_line(stdout, "Location")
    pats = ["/admin", "/wp-login", "/wp-admin", "/manager"]
    found = [p for p in pats if p in loc.lower()]
    result = "PASS" if not found else "FAIL"
    logic = f"Admin paths detected in redirect: {', '.join(found) if found else 'none'}."
    return _build_result(15, "Remote Login of CMS or Site Manager is not accessible", "curl", meta, logic, result)

def _testssl_replica(domain, cache, cid, name, kws, desc, port=None):
    meta = run_testssl(domain, cache, port=port)
    stdout = meta['output']
    if meta.get('returncode') == 127: 
        return _build_result(cid, name, "testssl", meta, "testssl.sh not found", "FAIL")
    ok = _vuln_pass(stdout, *kws)
    return _build_result(cid, name, "testssl", meta, desc if ok else f"Vulnerable/Offered detected in: {kws}", "PASS" if ok else "FAIL")

def check_16_tls_versions(domain, cache, port=None):
    return _testssl_replica(domain, cache, 16, "TLSv1.0, SSLv2, SSLv3 support is disabled", ["SSLv2", "SSLv3", "TLS 1", "TLS 1.1"], "No weak protocol is offered.", port=port)

def check_17_weak_ciphers(domain, cache, port=None):
    kws = ["NULL", "EXPORT", "LOW", "RC4", "DES", "3DES", "ANON", "weak cipher"]
    return _testssl_replica(domain, cache, 17, "Weak Cipher support is disabled", kws, "No weak ciphers detected.", port=port)

def check_18_poodle(domain, cache, port=None):
    return _testssl_replica(domain, cache, 18, "Protected from POODLE attack", ["POODLE", "poodle"], "Not vulnerable to POODLE.", port=port)

def check_19_logjam(domain, cache, port=None):
    return _testssl_replica(domain, cache, 19, "Protected from Logjam attack", ["Logjam", "logjam", "LOGJAM", "DH_anon", "DHE export"], "Not vulnerable to Logjam.", port=port)

def check_20_heartbleed(domain, cache, port=None):
    return _testssl_replica(domain, cache, 20, "Patched from Heartbleed bug", ["Heartbleed", "heartbleed", "HEARTBLEED"], "Not vulnerable to Heartbleed.", port=port)

def check_21_crime(domain, cache, port=None):
    return _testssl_replica(domain, cache, 21, "Protected from CRIME Vulnerability", ["CRIME", "crime"], "Not vulnerable to CRIME.", port=port)

def check_22_ccs_injection(domain, cache, port=None):
    return _testssl_replica(domain, cache, 22, "Protected from CCS Injection Vulnerability", ["CCS", "CCS injection", "ccs"], "Not vulnerable to CCS Injection.", port=port)

def check_23_anon_ciphers(domain, cache, port=None):
    return _testssl_replica(domain, cache, 23, "Protected from Anonymous Cipher Vulnerability", ["anonymous", "ANON", "NULL cipher"], "No anonymous ciphers found.", port=port)

def check_24_freak(domain, cache, port=None):
    return _testssl_replica(domain, cache, 24, "Protected from Openssl FREAK Vulnerability", ["FREAK", "freak", "EXPORT_RSA"], "Not vulnerable to FREAK.", port=port)

def check_25_drown(domain, cache, port=None):
    return _testssl_replica(domain, cache, 25, "Protected from SSL2 DROWN Vulnerability", ["DROWN", "drown", "SSLv2"], "Not vulnerable to DROWN.", port=port)

def check_26_forward_secrecy(domain, cache, port=None):
    meta = run_testssl(domain, cache, port=port)
    stdout = meta['output']
    section = _extract_testssl_section(stdout, "Forward Secrecy", "PFS", "ECDHE", "DHE")
    ok = any(x in section.lower() for x in ["yes", "offered", "supported", "fs is offered"])
    return _build_result(26, "Supports Forwarding Secrecy over SSL", "testssl", meta, "Forward secrecy is offered.", "PASS" if ok else "FAIL")

def check_27_http10_blocked(domain, cache, port=None):
    url = f"https://{domain}" if not port else f"https://{domain}:{port}"
    meta = run_curl_headers(url, cache, ["--http1.0"])
    stdout = meta['output']
    line = stdout.splitlines()[0] if stdout else ""
    ok = "HTTP/1.1 200" in line
    logic = f"Server upgraded the connection to a modern protocol: '{line}'." if ok else f"Server accepted HTTP/1.0: '{line}'."
    return _build_result(27, "Web server blocked the HTTP/1.0 response", "curl", meta, logic, "PASS" if ok else "FAIL")

def check_28_dns_caa(domain, cache, port=None):
    meta = run_dig_caa(domain, cache)
    stdout = meta['output']
    count = len(stdout.strip().splitlines())
    ok = count > 0
    logic = f"{count} CAA record(s) found."
    return _build_result(28, "DNS CAA is setup on DNS", "dig", meta, logic, "PASS" if ok else "FAIL")
