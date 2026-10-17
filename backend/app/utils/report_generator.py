""""
# Mock Drill Security Assessment Report Generator  v2.0

==================================================
Enterprise-grade PDF engine — clean, non-redundant, rounded UI.

Public API:
    from app.utils.report_generator import generate_report
    pdf_bytes = generate_report(scan_id)
"""

import re
import io
import textwrap
import hashlib
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether,
    NextPageTemplate, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.flowables import Flowable

# Database imports
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.models.scan_result import ScanRawResult
from app.models.discovery import DiscoveryJob, DiscoveryResult
from app.db.session import SessionLocal
from app.db import base

# ── Page geometry ────────────────────────────────────────────────────────────
PAGE_W, PAGE_H = A4
MARGIN         = 16 * mm
CONTENT_W      = PAGE_W - 2 * MARGIN

# ── Brand palette ────────────────────────────────────────────────────────────
C_NAVY    = colors.HexColor("#0B1929")
C_BLUE    = colors.HexColor("#1565C0")
C_LBLUE   = colors.HexColor("#E8F0FE")
C_MIDB    = colors.HexColor("#90CAF9")
C_BORDER  = colors.HexColor("#CFD8DC")
C_BG1     = colors.HexColor("#F8FAFD")
C_BG2     = colors.HexColor("#FFFFFF")
C_TEXT    = colors.HexColor("#1A1A2E")
C_MUTED   = colors.HexColor("#607D8B")
C_PASS    = colors.HexColor("#2E7D32")
C_FAIL    = colors.HexColor("#C62828")

SEV_FG = {
    "CRITICAL": colors.HexColor("#7B0000"),
    "HIGH":     colors.HexColor("#C62828"),
    "MEDIUM":   colors.HexColor("#E65100"),
    "LOW":      colors.HexColor("#2E7D32"),
    "INFO":     colors.HexColor("#1565C0"),
    "N/A":      colors.HexColor("#546E7A"),
}
SEV_BG = {
    "CRITICAL": colors.HexColor("#FFEBEE"),
    "HIGH":     colors.HexColor("#FFEBEE"),
    "MEDIUM":   colors.HexColor("#FFF3E0"),
    "LOW":      colors.HexColor("#E8F5E9"),
    "INFO":     colors.HexColor("#E3F2FD"),
    "N/A":      colors.HexColor("#ECEFF1"),
}

RAW_MAX_LINES = 55          # lines shown in detailed findings
RAW_WRAP_COLS = 108         # chars before wrapping


# ============================================================================
# §1  UTILITY HELPERS
# ============================================================================

def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes AND the broken ■[0;32m artefact."""
    if not text:
        return ""
    text = re.sub(r'\x1b\[[0-9;]*[mGKHFJA-Z]', "", text)
    text = re.sub(r'■\[[0-9;]*m', "", text)
    text = re.sub(r'\x1b[^a-zA-Z]*[a-zA-Z]', "", text)
    return text


def raw_fingerprint(raw: str) -> str:
    """SHA-256 of stripped raw output for deduplication."""
    return hashlib.sha256(strip_ansi(raw or "").strip().encode()).hexdigest()


def to_yn(result) -> str:
    r = str(result or "").strip().upper()
    return "Y" if r in ("PASS", "Y", "YES", "1", "TRUE", "OK") else "N"


def sev_key(sev) -> str:
    s = str(sev or "N/A").strip().upper()
    return s if s in SEV_FG else "N/A"


def overall_risk(results) -> str:
    failed_sevs = [sev_key(r.get("severity")) for r in results
                   if to_yn(r.get("result")) == "N"]
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if lvl in failed_sevs:
            return lvl
    return "INFORMATIONAL"


def safe(val, fallback="N/A") -> str:
    s = str(val).strip() if val is not None else ""
    return s if s else fallback


def fmt_dt(val) -> str:
    if val is None:
        return "N/A"
    try:
        from app.utils.time_utils import convert_utc_to_ist
        return convert_utc_to_ist(str(val))
    except:
        return re.sub(r'\.\d+', "", re.sub(r'\+00:00$', "", str(val)))


def xml(text: str) -> str:
    """Escape for ReportLab XML Paragraph."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def natural_sort_key(val):
    """Sort strings containing numbers numerically (e.g. '2' before '10')."""
    if val is None:
        return [0]
    return [int(t) if t.isdigit() else t.lower()
            for t in re.split(r'([0-9]+)', str(val))]


def wrap_raw(text: str) -> str:
    """Word-wrap raw output lines so nothing overflows the page."""
    out = []
    for line in text.splitlines():
        if len(line) > RAW_WRAP_COLS:
            out.extend(textwrap.wrap(line, RAW_WRAP_COLS, break_long_words=True,
                                     break_on_hyphens=False))
        else:
            out.append(line)
    return "\n".join(out)


# ── Intelligent description / impact ────────────────────────────────────────

_DESC = {
    "open port": (
        "Enumerates all TCP/UDP ports currently reachable on the target host. "
        "Only ports required for legitimate business services should be exposed to the network."
    ),
    "ssh service version": (
        "Verifies that the SSH daemon does not disclose its exact software version in the "
        "connection banner. Version exposure allows attackers to cross-reference known CVEs "
        "for rapid, targeted exploitation."
    ),
    "protocol v1": (
        "Confirms the SSH server rejects the deprecated SSHv1 protocol. SSHv1 contains "
        "well-documented cryptographic weaknesses including session-hijacking vulnerabilities "
        "and must never be permitted on production infrastructure."
    ),
    "cipher": (
        "Evaluates the symmetric encryption ciphers advertised by the SSH server. "
        "Only authenticated-encryption ciphers such as ChaCha20-Poly1305 and AES-GCM "
        "should be permitted; legacy block ciphers in CBC mode must be disabled."
    ),
    "key algo": (
        "Verifies that the SSH server only offers modern key-exchange algorithms. "
        "Deprecated algorithms such as diffie-hellman-group1-sha1 or ECDH curves suspected "
        "of being backdoored expose sessions to offline decryption attacks."
    ),
    "mac": (
        "Ensures only cryptographically strong Message Authentication Code (MAC) algorithms "
        "are supported. Weak MACs based on MD5 or truncated SHA-1 allow message forgery and "
        "integrity attacks on encrypted SSH sessions."
    ),
    "tls": (
        "Assesses the TLS/SSL configuration, verifying that only secure protocol versions "
        "(TLS 1.2+) and strong cipher suites are offered while deprecated versions are disabled."
    ),
    "http header": (
        "Inspects HTTP response headers for mandatory security directives including HSTS, "
        "X-Frame-Options, Content-Security-Policy, and X-Content-Type-Options."
    ),
}

_IMPACT = {
    "CRITICAL": (
        "A critical vulnerability that can be exploited remotely by an unskilled attacker "
        "with no authentication. Immediate remediation is mandatory — exploitation can result "
        "in complete system compromise, data exfiltration, or ransomware deployment."
    ),
    "HIGH": (
        "A high-severity weakness that significantly lowers the bar for exploitation. "
        "An attacker with basic skills or access to public exploit code can leverage this "
        "finding to gain unauthorised access or escalate privileges."
    ),
    "MEDIUM": (
        "A medium-severity misconfiguration that weakens defence-in-depth. "
        "When combined with other findings it can form an exploitation chain leading to "
        "privilege escalation or sensitive data exposure. Should be remediated promptly."
    ),
    "LOW": (
        "A low-severity deviation from security best practice. While not directly exploitable "
        "in isolation, it reduces the system's overall security posture and should be addressed "
        "during the next maintenance window."
    ),
    "N/A": (
        "This check is informational. Review the finding and confirm it aligns with your "
        "organisation's security policy and acceptable-use requirements."
    ),
}

_IMPACT_SPECIFIC = {
    "open port": (
        "Each additional open port is a potential entry point. Unrecognised or unnecessary "
        "services may contain unpatched vulnerabilities or default credentials that an "
        "attacker can exploit to gain initial access to the system."
    ),
    "ssh service version": (
        "Exposing the exact SSH build allows attackers to instantly identify the software "
        "version and query public CVE databases for applicable exploits, dramatically "
        "accelerating reconnaissance and targeted attacks."
    ),
    "protocol v1": (
        "SSHv1 is vulnerable to session-insertion attacks, weak key negotiation, and "
        "man-in-the-middle interception. Any host accepting SSHv1 connections can have its "
        "administrative credentials silently stolen."
    ),
    "cipher": (
        "Weak or broken ciphers allow a network-positioned attacker to decrypt captured "
        "SSH sessions, exposing credentials, commands, and sensitive data transmitted "
        "over what appears to be an encrypted channel."
    ),
    "key algo": (
        "Insecure key-exchange algorithms can be broken with sufficient compute resources, "
        "enabling retroactive decryption of all previously recorded sessions and real-time "
        "man-in-the-middle attacks on new connections."
    ),
    "mac": (
        "Broken MAC algorithms allow a network attacker to forge or silently modify encrypted "
        "SSH packets without detection, undermining the integrity guarantee of the entire "
        "session regardless of cipher strength."
    ),
}


def infer_description(check_name: str, decision_logic: str) -> str:
    name = check_name.lower()
    for kw, desc in _DESC.items():
        if kw in name:
            return desc
    dl = safe(decision_logic, "")
    if dl != "N/A":
        return f"This check asserts the following condition: {dl}"
    return f"Automated compliance verification for: {safe(check_name)}."


def infer_impact(check_name: str, severity: str) -> str:
    name = check_name.lower()
    for kw, impact in _IMPACT_SPECIFIC.items():
        if kw in name:
            return impact
    return _IMPACT.get(sev_key(severity), _IMPACT["N/A"])


# ============================================================================
# §2  CUSTOM FLOWABLES  (rounded-corner UI components)
# ============================================================================

def create_rounded_box(content_flowables, width, bg=C_BG1, border=C_BORDER, radius=6, pad=10):
    """
    Creates a Table that looks like a rounded card.
    By putting each flowable in its own row, ReportLab can split the card across pages.
    """
    if not isinstance(content_flowables, (list, tuple)):
        content_flowables = [content_flowables]

    rows = [[f] for f in content_flowables]
    tbl = Table(rows, colWidths=[width], splitByRow=True)
    tbl.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, -1), bg),
        ('BOX',            (0, 0), (-1, -1), 0.7, border),
        ('ROUNDEDCORNERS', [radius]),
        ('LEFTPADDING',    (0, 0), (-1, -1), pad),
        ('RIGHTPADDING',   (0, 0), (-1, -1), pad),
        ('TOPPADDING',     (0, 0), (-1, -1), pad),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), pad),
        ('VALIGN',         (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [bg]), 
    ]))
    return tbl

class RoundedBox(Flowable):
    """
    A container that draws a rounded-corner card around its content.
    Pass content as a list of Paragraph / Table flowables.
    """
    def __init__(self, content_flowables, bg=C_BG1, border=C_BORDER,
                 radius=6, pad=10):
        super().__init__()
        self._content = content_flowables
        self.bg       = bg
        self.border   = border
        self.radius   = radius
        self.pad      = pad
        self._inner_h = 0
        self._inner_w = 0

    def wrap(self, aw, ah):
        self._inner_w = aw - 2 * self.pad
        h = 0
        for f in self._content:
            fw, fh = f.wrap(self._inner_w, ah)
            h += fh + 3
        self._inner_h = h + self.pad
        self.width  = aw
        self.height = self._inner_h + self.pad
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(self.bg)
        c.setStrokeColor(self.border)
        c.setLineWidth(0.7)
        c.roundRect(0, 0, self.width, self.height, self.radius, stroke=1, fill=1)
        # draw children top-down inside padding
        y = self.height - self.pad
        for f in self._content:
            fw, fh = f.wrap(self._inner_w, 10000)
            y -= fh
            f.drawOn(c, self.pad, y)
            y -= 3
        c.restoreState()


class SevBadge(Flowable):
    """Rounded severity pill (compact)."""
    def __init__(self, severity, w=37, h=15):
        super().__init__()
        self.sev = sev_key(severity)
        self._w, self._h = w, h

    def wrap(self, aw, ah): return self._w, self._h

    def draw(self):
        c = self.canv
        r = self._h / 2
        # Background
        c.setFillColor(SEV_BG[self.sev])
        c.roundRect(0, 0, self._w, self._h, r, stroke=0, fill=1)
        # Border
        c.setStrokeColor(SEV_FG[self.sev])
        c.setLineWidth(0.6)
        c.roundRect(0, 0, self._w, self._h, r, stroke=1, fill=0)
        # Text
        c.setFillColor(SEV_FG[self.sev])
        c.setFont("Times-Bold", 7.0)
        c.drawCentredString(self._w / 2, (self._h - 7.0) / 2 + 0.5, self.sev)


class YNBadge(Flowable):
    """Rounded Y / N pill with transparent background."""
    def __init__(self, yn, w=26, h=15):
        super().__init__()
        self.yn = yn
        self._w, self._h = w, h

    def wrap(self, aw, ah): return self._w, self._h

    def draw(self):
        c = self.canv
        r = self._h / 2
        # Use a very light, semi-transparent background
        if self.yn == "Y":
            bg = colors.Color(red=0.18, green=0.49, blue=0.20, alpha=0.15) # Light green
            fg = colors.HexColor("#2E7D32")
        else:
            bg = colors.Color(red=0.78, green=0.16, blue=0.16, alpha=0.15) # Light red
            fg = colors.HexColor("#C62828")
            
        c.setFillColor(bg)
        c.roundRect(0, 0, self._w, self._h, r, stroke=0, fill=1)
        c.setFillColor(fg)
        c.setFont("Times-Bold", 8)
        c.drawCentredString(self._w / 2, (self._h - 8) / 2 + 0.5, self.yn)


class HRule(Flowable):
    def __init__(self, color=C_BORDER, lw=0.5):
        super().__init__()
        self.color = color
        self.lw    = lw

    def wrap(self, aw, ah):
        self.width = aw
        return aw, self.lw + 2

    def draw(self):
        c = self.canv
        c.setStrokeColor(self.color)
        c.setLineWidth(self.lw)
        c.line(0, 1, self.width, 1)


class SectionHeader(Flowable):
    """Modern, professional section header with a clean underline accent."""
    def __init__(self, number, title, bg=C_NAVY, fg=None, h=32, r=0):
        super().__init__()
        self.number = number
        self.title  = title.upper()
        self.color  = bg  # Primary accent color
        self._h     = h

    def wrap(self, aw, ah):
        self.width = aw
        return aw, self._h

    def draw(self):
        c = self.canv
        # Typography: Clear, bold, and professional
        c.setFont("Times-Bold", 13)
        c.setFillColor(self.color)
        
        # Format: "02 | EXECUTIVE SUMMARY"
        # Indent text slightly to align with content boxes
        indent = 4 * mm
        header_text = f"{int(self.number):02d}  |  {self.title}"
        c.drawString(indent, 12, header_text)
        
        # Elegant accent line
        # 1. Thick primary color segment
        c.setStrokeColor(self.color)
        c.setLineWidth(2)
        c.line(indent, 4, indent + 60, 4)
        
        # 2. Thin subtle extension
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.5)
        c.line(indent + 60, 4, self.width - indent, 4)


class MetricCard(Flowable):
    """Single stat card with number + label."""
    def __init__(self, number, label, num_color=C_NAVY, w=80, h=52, r=8):
        super().__init__()
        self.number    = str(number)
        self.label     = label
        self.num_color = num_color
        self._w, self._h, self.r = w, h, r

    def wrap(self, aw, ah): return self._w, self._h

    def draw(self):
        c = self.canv
        c.setFillColor(C_BG2)
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(0.7)
        c.roundRect(0, 0, self._w, self._h, self.r, stroke=1, fill=1)
        # number
        c.setFillColor(self.num_color)
        c.setFont("Times-Bold", 18) # Slightly smaller for better fit
        c.drawCentredString(self._w / 2, self._h - 28, self.number)
        # label
        c.setFillColor(C_MUTED)
        c.setFont("Times-Roman", 7.5)
        c.drawCentredString(self._w / 2, 9, self.label)


class CoverPage(Flowable):
    """Full-bleed dark cover — drawn entirely on canvas."""
    def __init__(self, meta):
        super().__init__()
        self.meta = meta

    def wrap(self, aw, ah): return PAGE_W, PAGE_H

    def draw(self):
        c = self.canv
        m = self.meta
        domain    = safe(m.get("domain"), "Unknown")
        scan_id   = safe(m.get("scan_id"), "N/A")
        scan_type = safe(m.get("scan_type"), "Standard")
        scan_date = fmt_dt(m.get("created_at"))
        from app.utils.time_utils import convert_utc_to_ist
        generated = convert_utc_to_ist(datetime.now().isoformat())
        cx = PAGE_W / 2

        # Background: Solid white
        c.setFillColor(colors.white)
        c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

        # Subtle top accent (Clean line)
        c.setFillColor(C_BLUE)
        c.rect(0, PAGE_H - 10 * mm, PAGE_W, 2 * mm, stroke=0, fill=1)

        # Title: Large, bold, centered
        c.setFillColor(C_NAVY)
        c.setFont("Times-Bold", 34)
        c.drawCentredString(cx, PAGE_H * 0.65, "SECURITY ASSESSMENT REPORT")
        
        # Subtitle
        c.setFillColor(C_BLUE)
        c.setFont("Times-Bold", 16)
        c.drawCentredString(cx, PAGE_H * 0.60, "Mock Drill Automated Compliance Platform")

        # Divider
        c.setStrokeColor(C_BORDER)
        c.setLineWidth(1)
        c.line(PAGE_W * 0.2, PAGE_H * 0.55, PAGE_W * 0.8, PAGE_H * 0.55)

        # Meta info: Center-aligned, no cards, larger font
        c.setFillColor(C_TEXT)
        
        from app.utils.ip_utils import get_public_ip
        scanner_ip = get_public_ip()
        
        y_start = PAGE_H * 0.45
        line_h = 24
        
        fields = [
            ("Target Domain", domain),
            ("Scan Type",     scan_type.upper()),
            ("Scan ID",       str(scan_id)),
            ("Checks Performed By",  scanner_ip),
            ("Scan Date",     scan_date),
            ("Report Issued", generated)
        ]

        for i, (label, val) in enumerate(fields):
            y = y_start - (i * line_h)
            c.setFont("Times-Bold", 12)
            c.drawRightString(cx - 10, y, f"{label}:")
            c.setFont("Times-Roman", 12)
            c.drawString(cx + 10, y, val)

        # Bottom disclaimer
        c.setFillColor(C_MUTED)
        c.setFont("Times-Roman", 9)
        c.drawCentredString(cx, PAGE_H * 0.08,
                            "This document contains sensitive security configuration data.")
        c.drawCentredString(cx, PAGE_H * 0.06,
                            "CONFIDENTIAL — AUTHORISED ACCESS ONLY")

        # Bottom accent
        c.setFillColor(C_NAVY)
        c.rect(0, 0, PAGE_W, 4 * mm, stroke=0, fill=1)


# ============================================================================
# §3  STYLES
# ============================================================================

def _s(name, **kw) -> ParagraphStyle:
    return ParagraphStyle(name, **kw)


def build_styles() -> dict:
    base = dict(
        fontName="Times-Roman", fontSize=9,
        textColor=C_TEXT, leading=13, spaceAfter=3,
    )
    return {
        "body":      _s("body",      **base),
        "body_b":    _s("body_b",    **{**base, "fontName": "Times-Bold"}),
        "label":     _s("label",     **{**base, "fontSize": 7.5,
                                        "textColor": C_MUTED, "spaceAfter": 1}),
        "sub_h":     _s("sub_h",     fontName="Times-Bold", fontSize=10,
                                     textColor=C_BLUE, spaceAfter=4, spaceBefore=6),
        "mono":      _s("mono",      fontName="Courier", fontSize=7.5,
                                     textColor=colors.HexColor("#1A237E"),
                                     leading=10.5,
                                     spaceAfter=0),
        "tbl_hdr":   _s("tbl_hdr",   fontName="Times-Bold", fontSize=8,
                                     textColor=colors.white, alignment=TA_CENTER),
        "tbl_cell":  _s("tbl_cell",  fontName="Times-Roman", fontSize=8,
                                     textColor=C_TEXT, leading=11, wordWrap="LTR"),
        "tbl_cc":    _s("tbl_cc",    fontName="Times-Roman", fontSize=8,
                                     textColor=C_TEXT, leading=11, alignment=TA_CENTER),
        "footer":    _s("footer",    fontName="Times-Roman", fontSize=7,
                                     textColor=C_MUTED, alignment=TA_CENTER),
        "check_ttl": _s("check_ttl", fontName="Times-Bold", fontSize=11,
                                     textColor=C_NAVY, leading=15),
        "ok_msg":    _s("ok_msg",    fontName="Times-Bold", fontSize=10,
                                     textColor=C_PASS, leading=15),
    }


# ============================================================================
# §4  PAGE TEMPLATE
# ============================================================================

class MockDrillDoc(BaseDocTemplate):
    def __init__(self, buf, scan_id, domain, generated_date, **kw):
        super().__init__(buf, **kw)
        self.scan_id = scan_id
        self.domain = domain
        self.generated_date = generated_date
        self._build_templates()

    def _build_templates(self):
        cover_frame = Frame(0, 0, PAGE_W, PAGE_H,
                            leftPadding=0, rightPadding=0,
                            topPadding=0, bottomPadding=0, id="cvr")
        content_frame = Frame(
            MARGIN, MARGIN + 12 * mm,
            CONTENT_W, PAGE_H - 2 * MARGIN - 22 * mm,
            leftPadding=0, rightPadding=0,
            id="body",
        )
        self.addPageTemplates([
            PageTemplate("Cover",   frames=[cover_frame],   onPage=self._pg_cover),
            PageTemplate("Content", frames=[content_frame], onPage=self._pg_content),
        ])

    def _pg_cover(self, canvas, doc):
        pass  # Cover draws itself

    def _pg_content(self, canvas, doc):
        canvas.saveState()
        # ── Header (No box, moved down) ─────────────────────────────────
        canvas.setFillColor(C_NAVY)
        canvas.setFont("Times-Bold", 8)
        header_y = PAGE_H - 12 * mm
        canvas.drawString(MARGIN, header_y, f"Target: {self.domain}")
        canvas.drawRightString(MARGIN + CONTENT_W, header_y, f"Scan ID: {self.scan_id}")
        
        # ── Footer (No box) ─────────────────────────────────────────────
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Times-Roman", 8)
        footer_y = 10 * mm
        canvas.drawString(MARGIN, footer_y, f"Page {doc.page}")
        canvas.drawRightString(MARGIN + CONTENT_W, footer_y, f"Date: {self.generated_date}")
        canvas.restoreState()


# ============================================================================
# §5  SECTION BUILDERS
# ============================================================================

# ── §5.1  Cover ─────────────────────────────────────────────────────────────

def sec_cover(story, meta):
    story.append(CoverPage(meta))
    story.append(PageBreak())


# ── §5.2  Executive Summary ─────────────────────────────────────────────────

def sec_executive_summary(story, S, meta, results):
    # Add space at top to ensure no overlap with header
    story.append(Spacer(1, 10 * mm))
    
    story.append(SectionHeader(2, "Executive Summary"))
    story.append(Spacer(1, 12))

    total  = len(results)
    passed = sum(1 for r in results if to_yn(r.get("result")) == "Y")
    failed = total - passed
    pct    = (passed / total * 100) if total else 0.0
    rating = overall_risk(results)
    rc     = SEV_FG.get(rating, C_BLUE) if rating != "INFORMATIONAL" else C_BLUE

    # ── Metric cards row ────────────────────────────────────────────────────
    # Indent content to match SectionHeader design
    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent
    cw = inner_w / 4 - 6
    
    cards = [[
        MetricCard(total,          "Total Checks",  C_NAVY,  cw),
        MetricCard(passed,         "Passed",        C_PASS,  cw),
        MetricCard(failed,         "Failed",        C_FAIL,  cw),
        MetricCard(f"{pct:.1f}%",  "Compliance",   C_BLUE,  cw),
    ]]
    
    # Use Table with hAlign='CENTER' to balance the page
    cards_tbl = Table(cards, colWidths=[inner_w / 4] * 4, hAlign='CENTER')
    cards_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(cards_tbl)
    story.append(Spacer(1, 12))

    # ── Risk rating + summary paragraph in a rounded card ───────────────────
    risk_line = Paragraph(
        f'Overall Risk Rating: <font name="Times-Bold" '
        f'color="{rc.hexval()}">{rating}</font>',
        S["sub_h"]
    )
    summary_text = (
        "This report summarises the security posture of the target system based on "
        "automated compliance checks executed by the Mock Drill scanning engine. Findings "
        "highlight deviations from established security best practices. Each failed check "
        "includes full technical evidence and actionable remediation guidance."
    )
    summary_para = Paragraph(summary_text, S["body"])

    # Rounded box also indented to match
    box = create_rounded_box([risk_line, summary_para], width=inner_w, bg=C_BG1, border=C_BORDER, pad=12)
    story.append(box)
    story.append(Spacer(1, 6))


# ── §5.3  Risk Distribution ─────────────────────────────────────────────────

def sec_risk_distribution(story, S, results):
    """
    Displays the distribution of findings by severity in a beautiful
    card-type tabular format with a header and footer.
    """
    story.append(Spacer(1, 8))
    story.append(SectionHeader(3, "Risk Distribution Analysis"))
    story.append(Spacer(1, 10))

    # --- 1. Prepare data ------------------------------------------------------
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "N/A"]
    counts = {s: 0 for s in order}
    failed_counts = {s: 0 for s in order}

    for r in results:
        sev = sev_key(r.get("severity"))
        counts[sev] = counts.get(sev, 0) + 1
        if to_yn(r.get("result")) == "N":
            failed_counts[sev] = failed_counts.get(sev, 0) + 1

    total_findings = sum(counts.values())
    total_failed   = sum(failed_counts.values())
    max_count = max(counts.values()) if counts.values() else 1

    # --- 2. Build Card Content -------------------------------------------------
    # Match the 4mm indent used in SectionHeader and Executive Summary
    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent
    
    # Header for the card
    card_header = Paragraph(
        "<b>Summary of Findings by Severity</b>", 
        S["sub_h"]
    )
    
    # Table Data
    class MiniBar(Flowable):
        """Small horizontal bar for table cell."""
        def __init__(self, val, max_v, color):
            super().__init__()
            self.val = val; self.max_v = max_v; self.color = color
        def wrap(self, aw, ah):
            self.width = aw
            return aw, 12
        def draw(self):
            w = (self.val / self.max_v) * (self.width - 4) if self.max_v > 0 else 0
            self.canv.setFillColor(colors.HexColor("#F1F3F4"))
            self.canv.roundRect(0, 2, self.width, 8, 4, stroke=0, fill=1)
            if w > 0:
                self.canv.setFillColor(self.color)
                self.canv.roundRect(0, 2, w, 8, 4, stroke=0, fill=1)

    tbl_data = [[
        Paragraph("Severity Level", S["tbl_hdr"]),
        Paragraph("Count", S["tbl_hdr"]),
        Paragraph("Distribution", S["tbl_hdr"]),
        Paragraph("Status", S["tbl_hdr"])
    ]]

    for sev in order:
        cnt = counts[sev]
        f_cnt = failed_counts[sev]
        pct = (cnt / total_findings * 100) if total_findings > 0 else 0
        
        status_text = ""
        status_color = C_TEXT
        if f_cnt > 0:
            status_text = f"FAIL ({f_cnt})"
            status_color = C_FAIL
        elif cnt > 0:
            status_text = "PASS"
            status_color = C_PASS
        else:
            status_text = "N/A"
            status_color = C_MUTED

        tbl_data.append([
            SevBadge(sev),
            Paragraph(f"<b>{cnt}</b> <font size='7' color='#607D8B'>({pct:.1f}%)</font>", S["tbl_cc"]),
            MiniBar(cnt, max_count, SEV_FG.get(sev, C_BLUE)),
            Paragraph(f'<font color="{status_color.hexval()}"><b>{status_text}</b></font>', S["tbl_cc"])
        ])

    # Add a summary footer row to the table
    tbl_data.append([
        Paragraph("<b>TOTAL</b>", S["body_b"]),
        Paragraph(f"<b>{total_findings}</b>", S["tbl_cc"]),
        "",
        Paragraph(f'<b>{total_failed} Failed</b>', S["tbl_cc"])
    ])

    # Fit INSIDE the RoundedBox which is inside the inner_w
    # pad=15 inside RoundedBox
    table_w = inner_w - 30
    col_widths = [table_w * 0.22, table_w * 0.18, table_w * 0.40, table_w * 0.20]
    
    tbl = Table(tbl_data, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_NAVY),
        ('BACKGROUND', (0, -1), (-1, -1), C_BG1),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -2), 0.2, C_BORDER),
        ('BOX', (0, 0), (-1, -1), 0.5, C_BORDER),
        ('ROUNDEDCORNERS', [6]),
    ]))

    # Footer for the card
    card_footer = Paragraph(
        "<i>Note: Severity is determined by CVSS score and security best practices.</i>",
        S["footer"]
    )

    # Wrap everything in a card
    box = create_rounded_box([
        card_header,
        Spacer(1, 8),
        tbl,
        Spacer(1, 10),
        card_footer
    ], width=inner_w, bg=C_BG2, border=C_BORDER, pad=15)
    
    story.append(box)
    story.append(Spacer(1, 10))




# ── §5.4  Summary Table ─────────────────────────────────────────────────────

def sec_summary_table(story, S, results, section_num=4):
    story.append(PageBreak())
    story.append(SectionHeader(section_num, "Summary of Findings"))
    story.append(Spacer(1, 10))

    # Match the 4mm indent used in other sections
    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

    # Column widths — carefully proportioned
    cw = [
        inner_w * 0.055,   # Sr
        inner_w * 0.295,   # Check Name
        inner_w * 0.075,   # Status
        inner_w * 0.135,   # Severity
        inner_w * 0.085,   # CVSS
        inner_w * 0.355,   # Remarks
    ]

    hdr = [Paragraph(h, S["tbl_hdr"]) for h in
           ["#", "Check Name", "Status", "Severity", "CVSS", "Remarks"]]
    rows = [hdr]

    for i, r in enumerate(results, 1):
        yn    = to_yn(r.get("result"))
        sev   = sev_key(r.get("severity"))
        cvss  = r.get("cvss_score")
        cvss_s = f"{float(cvss):.1f}" if cvss is not None else "N/A"
        rem   = safe(r.get("decision_logic"), "—")
        name  = safe(r.get("check_name"), f"Check {i}")

        rows.append([
            Paragraph(str(i), S["tbl_cc"]),
            Paragraph(xml(name), S["tbl_cell"]),
            YNBadge(yn, 26, 15),
            SevBadge(sev),
            Paragraph(cvss_s, S["tbl_cc"]),
            Paragraph(xml(rem[:200] + ("…" if len(rem) > 200 else "")), S["tbl_cell"]),
        ])

    # Row shading — light red for failures
    row_cmds = []
    for i, r in enumerate(results, 1):
        if to_yn(r.get("result")) == "N":
            row_cmds.append(("BACKGROUND", (0, i), (-1, i),
                             colors.HexColor("#FFF5F5")))

    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG2, C_BG1]),
        ("BOX",           (0, 0), (-1, -1), 0.6, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("ROUNDEDCORNERS", [6]),
    ] + row_cmds)

    tbl = Table(rows, colWidths=cw, repeatRows=1, splitByRow=True, hAlign='CENTER')
    tbl.setStyle(style)
    story.append(tbl)


    # ── §5.5  Detailed Findings ──────────────────────────────────────────────────
def sec_detailed_findings(story, S, results, section_num=5):
    story.append(PageBreak())
    story.append(SectionHeader(section_num, "Detailed Findings"))

    # Sort by check_id (strict ordering requirement)
    ordered = sorted(results, key=lambda r: natural_sort_key(r.get("check_id")))

    for idx, r in enumerate(ordered, 1):
        if idx > 1:
            story.append(PageBreak())
        _render_single_check(story, S, r, idx)


def _render_single_check(story, S, r, display_idx):
    check_id  = r.get("check_id", display_idx)
    name      = safe(r.get("check_name"), f"Check {display_idx}")
    sev       = sev_key(r.get("severity"))
    cvss      = r.get("cvss_score")
    cvss_s    = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    yn        = to_yn(r.get("result"))
    decision  = safe(r.get("decision_logic"), "No decision logic recorded.")
    cmd       = safe(r.get("command_executed"), "N/A")
    start     = fmt_dt(r.get("execution_start"))
    end       = fmt_dt(r.get("execution_end"))
    dur       = safe(r.get("execution_duration"), "N/A")
    rem_text  = r.get("remediation_text") or ""
    rem_ex    = r.get("remediation_example") or ""
    rem_ref   = r.get("remediation_reference") or ""
    cve       = r.get("cve_id") or ""
    raw_raw   = r.get("raw_output") or ""

    description = infer_description(name, decision)
    impact      = infer_impact(name, sev)

    story.append(Spacer(1, 12))

    # Match the 4mm indent used in other sections
    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

    # ── Check header bar (rounded, coloured left-border style) ────────────
    sc = SEV_FG[sev]

    class _CheckHeader(Flowable):
        def __init__(self, cid, cname, sev_badge, yn_badge, meta_str, width):
            super().__init__()
            self.cid = cid; self.cname = cname
            self.sev_badge = sev_badge; self.yn_badge = yn_badge
            self.meta_str = meta_str
            self.width = width
        def wrap(self, aw, ah):
            return self.width, 62
        def draw(self):
            c = self.canv
            c.setFillColor(C_BG1)
            c.setStrokeColor(C_BORDER)
            c.setLineWidth(0.6)
            c.roundRect(0, 0, self.width, 62, 6, stroke=1, fill=1)
            # Left accent strip
            c.setFillColor(sc)
            c.roundRect(0, 0, 5, 62, 3, stroke=0, fill=1)
            # Title
            c.setFillColor(C_NAVY)
            c.setFont("Times-Bold", 10)
            c.drawString(14, 44, f"Check {self.cid}: {self.cname}")
            # Badges (moved under title)
            self.sev_badge.drawOn(c, 14, 24)
            self.yn_badge.drawOn(c, 14 + 74, 24)
            # Meta (moved below badges)
            c.setFillColor(C_MUTED)
            c.setFont("Times-Roman", 7.5)
            c.drawString(14, 10, self.meta_str)

    meta_str_parts = [f"CVSS: {cvss_s}"]
    if cve:
        meta_str_parts.append(f"CVE: {cve}")
    meta_str = "  ·  ".join(meta_str_parts)

    header = _CheckHeader(check_id, xml(name),
                        SevBadge(sev), YNBadge(yn, 28, 16),
                        meta_str, inner_w)
    
    wrapper = Table([[header]], colWidths=[inner_w], hAlign='CENTER')
    wrapper.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(wrapper)
    story.append(Spacer(1, 6))

    # All sub-content also indented
    # We don't use a single wrapper table because it breaks page splitting for large tables.
    # Instead, we indent each element individually if needed, but most are Paragraphs
    # which respect the Frame margins. We'll just append them to the story.
    
    story.append(Paragraph("Description", S["sub_h"]))
    story.append(Paragraph(xml(description), S["body"]))
    story.append(Paragraph("Impact", S["sub_h"]))
    story.append(Paragraph(xml(impact), S["body"]))
    story.append(Paragraph("Evidence", S["sub_h"]))

    # Command Executed Box
    cmd_box = create_rounded_box([
        Paragraph("Command Executed", S["label"]),
        Paragraph(f'<font name="Courier" size="8">{xml(cmd)}</font>', S["body"])
    ], width=inner_w, bg=colors.HexColor("#F0F4F8"), border=C_BORDER, pad=8)
    
    story.append(cmd_box)
    story.append(Spacer(1, 6))

    # Raw Output
    cleaned = strip_ansi(raw_raw)
    wrapped = wrap_raw(cleaned)
    raw_lines = wrapped.splitlines()
    story.append(Paragraph("Raw Output (Full Evidence)", S["label"]))
    
    # Each line as a separate row ensures it can split across pages
    raw_rows = [[Paragraph(xml(line) if line.strip() else "&nbsp;", S["mono"])] for line in raw_lines]
    if not raw_rows:
        raw_rows = [[Paragraph("No output recorded.", S["body"])]]
        
    raw_tbl = Table(raw_rows, colWidths=[inner_w], splitByRow=True, hAlign='CENTER')
    raw_tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, -1), colors.HexColor("#F8F9FA")),
        ("BOX",            (0, 0), (-1, -1), 0.7, C_BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 0.5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 0.5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 10),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(raw_tbl)
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("Decision Logic", S["sub_h"]))
    story.append(Paragraph(xml(decision), S["body"]))
    story.append(Paragraph("Recommendation", S["sub_h"]))
    
    if rem_text.strip():
        story.append(Paragraph(xml(rem_text), S["body"]))
    else:
        story.append(Paragraph("No remediation required for this check.", S["body"]))

    if rem_ex.strip():
        story.append(Paragraph("Example:", S["body_b"]))
        story.append(Paragraph(xml(rem_ex).replace("\n", "<br/>"), S["mono"]))
    if rem_ref.strip():
        story.append(Paragraph(f'Reference: <font color="{C_BLUE.hexval()}">{xml(rem_ref)}</font>', S["body"]))

    story.append(Spacer(1, 6))
    story.append(HRule(C_BORDER, 0.5))



# ── §5.6  High Risk Findings ─────────────────────────────────────────────────

def sec_high_risk(story, S, results, section_num=6):
    story.append(PageBreak())
    story.append(SectionHeader(section_num, "High Risk Findings",
                               bg=colors.HexColor("#B71C1C")))
    story.append(Spacer(1, 10))

    high_risk = [
        r for r in sorted(results, key=lambda x: natural_sort_key(x.get("check_id")))
        if sev_key(r.get("severity")) in ("HIGH", "CRITICAL")
        and to_yn(r.get("result")) == "N"
    ]

    # Match the 4mm indent
    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

    if not high_risk:
        box = create_rounded_box(
            [Paragraph(
                "✓  No HIGH or CRITICAL severity failures were identified in this scan.",
                S["ok_msg"]
            )],
            width=inner_w,
            bg=colors.HexColor("#F1F8E9"),
            border=colors.HexColor("#A5D6A7"),
            pad=14,
        )
        story.append(box)
        return

    cw = [inner_w * 0.28, inner_w * 0.12, inner_w * 0.30, inner_w * 0.30]
    hdr = [Paragraph(h, S["tbl_hdr"]) for h in
           ["Check Name", "Severity", "Risk Summary", "Recommendation"]]
    rows = [hdr]

    for r in high_risk:
        rows.append([
            Paragraph(xml(safe(r.get("check_name"), "Unknown")), S["tbl_cell"]),
            SevBadge(sev_key(r.get("severity"))),
            Paragraph(xml(safe(r.get("decision_logic"), "—")[:250]), S["tbl_cell"]),
            Paragraph(xml(safe(r.get("remediation_text"),
                              "See detailed findings.")[:250]), S["tbl_cell"]),
        ])

    tbl = Table(rows, colWidths=cw, repeatRows=1, splitByRow=True, hAlign='CENTER')
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#C62828")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [colors.HexColor("#FFEBEE"), colors.HexColor("#FFF5F5")]),
        ("BOX",           (0, 0), (-1, -1), 0.6, colors.HexColor("#EF9A9A")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, colors.HexColor("#FFCDD2")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),  # Headers centered
        ("ALIGN",         (1, 1), (1, -1), "CENTER"),  # Severity centered
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("ROUNDEDCORNERS", [6]),
    ]))
    
    story.append(tbl)


# ============================================================================
# §6  MAIN ENTRY POINT
# ============================================================================

def generate_report(scan_id: int, db: Session = None) -> bytes:
    """
    Standard platform entry point. Fetches DB data and builds PDF.
    """
    if db is None:
        db = SessionLocal()
        close_db = True
    else:
        close_db = False

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        raw_rows = db.query(ScanRawResult).filter(
            ScanRawResult.scan_id == scan_id
        ).order_by(ScanRawResult.check_id).all()

        results = []
        for r in raw_rows:
            results.append({
                "check_id":           r.check_id,
                "check_name":         r.check_name,
                "tool_name":          r.tool_name,
                "command_executed":   r.command_executed,
                "raw_output":         r.raw_output,
                "decision_logic":     r.decision_logic,
                "result":             r.result,
                "cvss_score":         r.cvss_score,
                "severity":           r.severity,
                "cve_id":             r.cve_id,
                "remediation_text":   r.remediation_text,
                "remediation_example":r.remediation_example,
                "remediation_reference":r.remediation_reference,
                "execution_start":    r.execution_start,
                "execution_end":      r.execution_end,
                "execution_duration": r.execution_duration
            })

        meta = {
            "domain":     scan.domain,
            "scan_id":    scan.id,
            "scan_type":  scan.scan_type,
            "created_at": scan.created_at
        }

        # Fetch discovery results for this scan (if it was an auto-scan)
        # 1. If scan belongs to a group, try to find discovery for that group
        # 2. Or if there's a DiscoveryJob specifically for this scan (auto-mode)
        discovery_results = []
        
        # Check for direct discovery job (auto-mode)
        job = db.query(DiscoveryJob).filter(
            DiscoveryJob.raw_input == scan.domain,
            DiscoveryJob.user_id == scan.user_id
        ).order_by(DiscoveryJob.created_at.desc()).first()
        
        if job:
            discovery_results = job.results
        elif scan.group_id:
            # Try to find by schedule_id first (if scan.group_id is actually a schedule_id)
            sched_job = db.query(DiscoveryJob).filter(
                DiscoveryJob.schedule_id == scan.group_id
            ).order_by(DiscoveryJob.created_at.desc()).first()
            
            if sched_job:
                discovery_results = sched_job.results
            else:
                # Fallback to group discovery if available
                group_job = db.query(DiscoveryJob).filter(
                    DiscoveryJob.group_id == scan.group_id
                ).order_by(DiscoveryJob.created_at.desc()).first()
                if group_job:
                    discovery_results = group_job.results

        return generate_mock_drill_report(meta, results, discovery_results)

    finally:
        if close_db:
            db.close()


def generate_mock_drill_report(scan_metadata: dict, scan_results: list, discovery_results: list = None) -> bytes:
    """
    Generate a Mock Drill Security Assessment PDF report.
    """
    # ── Sort once by check_id; all sections respect this order ───────────
    ordered = sorted(scan_results, key=lambda r: natural_sort_key(r.get("check_id")))

    scan_id = str(scan_metadata.get("scan_id", "N/A"))
    domain  = str(scan_metadata.get("domain", "Unknown"))
    date_s  = fmt_dt(scan_metadata.get("created_at"))
    buf     = io.BytesIO()

    doc = MockDrillDoc(
        buf,
        scan_id      = scan_id,
        domain       = domain,
        generated_date = date_s,
        pagesize     = A4,
        leftMargin = MARGIN,
        rightMargin= MARGIN,
        topMargin  = MARGIN + 10 * mm,
        bottomMargin=MARGIN + 9 * mm,
        title      = f"Mock Drill Security Assessment Report",
        author     = "Mock Drill Automated Scanner",
        subject    = "Security Compliance Report",
        creator    = "Mock Drill Platform v2",
    )

    S     = build_styles()
    story = []

    # Cover
    story.append(NextPageTemplate("Cover"))
    sec_cover(story, scan_metadata)

    # All content pages
    story.append(NextPageTemplate("Content"))
    sec_executive_summary(story, S, scan_metadata, ordered)
    sec_risk_distribution(story, S, ordered)
    
    # NEW: Add discovery data if available
    if discovery_results:
        _add_targets_and_services(story, S, discovery_results, section_num=4)
        sec_summary_table(story, S, ordered, section_num=5)
        sec_detailed_findings(story, S, ordered, section_num=6)
        sec_high_risk(story, S, ordered, section_num=7)
    else:
        sec_summary_table(story, S, ordered, section_num=4)
        sec_detailed_findings(story, S, ordered, section_num=5)
        sec_high_risk(story, S, ordered, section_num=6)

    doc.build(story)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes


def _add_targets_and_services(story, S, discovery_results, section_num=4):
    """Render targets and discovered services in a structured, nested card layout."""
    story.append(PageBreak())
    story.append(SectionHeader(section_num, "Scan Targets & Services"))
    story.append(Spacer(1, 10))

    if not discovery_results:
        story.append(Paragraph("No discovery data available for this scan.", S["body"]))
        return

    # Group by target
    targets = {}
    for dr in discovery_results:
        # Compatibility with both dict and model object
        if hasattr(dr, 'target_ip'):
            t_ip, t_dom, port, svc_name, eng, ver = dr.target_ip, dr.target_domain, dr.port, dr.service, dr.engine, dr.version_info
        else:
            t_ip, t_dom, port, svc_name, eng, ver = dr.get("target_ip"), dr.get("target_domain"), dr.get("port"), dr.get("service"), dr.get("engine"), dr.get("version_info")

        key = t_ip or t_dom
        if not key: continue
        if key not in targets:
            targets[key] = {"ip": t_ip, "domain": t_dom, "services": []}
        
        targets[key]["services"].append({
            "port": port,
            "service": svc_name or "unknown",
            "engine": eng,
            "version": ver or ""
        })

    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

    def create_shaded_val(label, value, width):
        val_para = Paragraph(f"<b>{xml(str(value))}</b>", S["body"])
        val_box = Table([[val_para]], colWidths=[width * 0.7])
        val_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ('ROUNDEDCORNERS', [4]),
            ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 2), ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('BOX', (0, 0), (-1, -1), 0.3, C_BORDER),
        ]))
        row = Table([[Paragraph(f"• {label}:", S["body"]), val_box]], colWidths=[width * 0.25, width * 0.75])
        row.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('LEFTPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 2)]))
        return row

    for idx, (target_key, data) in enumerate(sorted(targets.items()), 1):
        target_display = target_key
        if data["domain"] and data["domain"] != data["ip"]:
            target_display = f"{data['domain']} ({data['ip']})"
        
        target_items = [Paragraph(f"<b>{idx}. {xml(target_display)}</b>", S["body_b"]), Spacer(1, 6)]
        card_inner_w = inner_w - 20
        
        for svc in data["services"]:
            svc_items = [
                create_shaded_val("Port", svc['port'], card_inner_w),
                create_shaded_val("Service", svc['service'], card_inner_w)
            ]
            if svc['version']:
                svc_items.append(create_shaded_val("Info", svc['version'][:200], card_inner_w))
            target_items.extend(svc_items)
            target_items.append(Spacer(1, 4))

        # Use the function instead of the class to allow splitting
        main_card = create_rounded_box(target_items, inner_w, bg=C_BG1, border=C_BORDER, pad=10)
        story.append(main_card)
        story.append(Spacer(1, 10))
