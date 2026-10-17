"""
# Campaign Report Generator for Mock Drill Platform

==============================================
Generates a consolidated PDF report for all scans under a campaign (scan group).
Reuses styles, helpers, and layout functions from the existing report_generator.py.
"""

import io
import re
import textwrap
import logging
from datetime import datetime
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    NextPageTemplate, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, Frame,
)
from reportlab.platypus.flowables import Flowable

# Import reusable components from the existing report generator
from app.utils.report_generator import (
    build_styles, MockDrillDoc, NextPageTemplate, PageBreak, Spacer,
    SectionHeader, RoundedBox, create_rounded_box, HRule, SevBadge, YNBadge,
    sec_cover, sec_executive_summary, sec_risk_distribution, sec_summary_table, sec_high_risk,
    xml, safe, fmt_dt, sev_key, to_yn, natural_sort_key, strip_ansi, wrap_raw,
    overall_risk, MetricCard, CoverPage,
    C_BLUE, C_NAVY, C_BORDER, C_BG1, C_BG2, C_MUTED, SEV_FG, C_TEXT,
    CONTENT_W, MARGIN, PAGE_W, PAGE_H,
)
from app.models.scan_group import ScanGroup
from app.models.scan import Scan
from app.models.scan_result import ScanRawResult
from app.db import base

# Re-define internal helpers from report_generator to avoid modifying the original file
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
        "Medium-severity finding that provides an attacker with useful reconnaissance data "
        "or a partial foothold. While harder to exploit in isolation, these are often "
        "chained with other vulnerabilities to bypass security controls."
    ),
    "LOW": (
        "Low-severity issue that deviates from security best practices but does not "
        "directly lead to compromise. These should be addressed as part of routine maintenance "
        "to harden the target against sophisticated attackers."
    ),
    "INFO": (
        "Informational finding regarding the target's configuration or service environment. "
        "No direct security risk is identified, but the data is provided for administrative "
        "awareness and documentation purposes."
    ),
    "N/A": "No impact assessment available for this check type."
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

def _render_single_check(story, S, r, display_idx):
    check_id  = r.get("check_id", display_idx)
    name      = safe(r.get("check_name"), f"Check {display_idx}")
    sev       = sev_key(r.get("severity"))
    cvss      = r.get("cvss_score")
    cvss_s    = f"{float(cvss):.1f}" if cvss is not None else "N/A"
    yn        = to_yn(r.get("result"))
    decision  = safe(r.get("decision_logic"), "No decision logic recorded.")
    cmd       = safe(r.get("command_executed"), "N/A")
    rem_text  = r.get("remediation_text") or ""
    rem_ex    = r.get("remediation_example") or ""
    rem_ref   = r.get("remediation_reference") or ""
    cve       = r.get("cve_id") or ""
    raw_raw   = r.get("raw_output") or ""

    description = infer_description(name, decision)
    impact      = infer_impact(name, sev)

    story.append(Spacer(1, 12))

    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

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
            c.setFillColor(sc)
            c.roundRect(0, 0, 5, 62, 3, stroke=0, fill=1)
            c.setFillColor(C_NAVY)
            c.setFont("Times-Bold", 10)
            c.drawString(14, 44, f"Check {self.cid}: {self.cname}")
            self.sev_badge.drawOn(c, 14, 24)
            self.yn_badge.drawOn(c, 14 + 74, 24)
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

    story.append(Paragraph("Description", S["sub_h"]))
    story.append(Paragraph(xml(description), S["body"]))
    story.append(Paragraph("Impact", S["sub_h"]))
    story.append(Paragraph(xml(impact), S["body"]))
    story.append(Paragraph("Evidence", S["sub_h"]))

    cmd_box = create_rounded_box([
        Paragraph("Command Executed", S["label"]),
        Paragraph(f'<font name="Courier" size="8">{xml(cmd)}</font>', S["body"])
    ], width=inner_w, bg=colors.HexColor("#F0F4F8"), border=C_BORDER, pad=8)

    story.append(cmd_box)
    story.append(Spacer(1, 6))

    cleaned = strip_ansi(raw_raw)
    wrapped = wrap_raw(cleaned)
    raw_lines = wrapped.splitlines()
    story.append(Paragraph("Raw Output (Full Evidence)", S["label"]))

    # Use a single table for ALL lines to ensure consistent borders/background,
    # but make each line a separate ROW so reportlab can split across pages.
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


def generate_campaign_report(group: ScanGroup, scans: list, discovery_results: list, db: Session) -> bytes:
    """
    Generate a consolidated PDF report for a campaign (group of scans).
    """
    logger.info(f"Generating campaign report for group {group.id} ({group.name}) with {len(scans)} scans")
    # Prepare metadata (similar structure to individual scan)
    meta = {
        "domain": group.name,
        "scan_id": f"CAMPAIGN-{group.id}",
        "scan_type": "Campaign",
        "created_at": group.created_at,
        "is_campaign": True,
        "campaign_name": group.name,
        "campaign_description": group.description,
    }

    # Collect all scan raw results from all scans in the group
    all_results = []
    for scan in scans:
        raw_results = db.query(ScanRawResult).filter(ScanRawResult.scan_id == scan.id).all()
        logger.debug(f"Scan {scan.id} ({scan.domain}) has {len(raw_results)} raw results")
        port = scan.scan_metadata.get("port") if scan.scan_metadata else None
        for r in raw_results:
            all_results.append({
                "check_id": r.check_id,
                "check_name": r.check_name,
                "tool_name": r.tool_name,
                "command_executed": r.command_executed,
                "raw_output": r.raw_output,
                "decision_logic": r.decision_logic,
                "result": r.result,
                "cvss_score": r.cvss_score,
                "severity": r.severity,
                "cve_id": r.cve_id,
                "remediation_text": r.remediation_text,
                "remediation_example": r.remediation_example,
                "remediation_reference": r.remediation_reference,
                "execution_start": r.execution_start,
                "execution_end": r.execution_end,
                "execution_duration": r.execution_duration,
                "scan_target": scan.domain,
                "scan_engine": scan.scan_type,
                "scan_port": port,
                "scan_id": scan.id
            })
    
    logger.info(f"Total results collected for campaign report: {len(all_results)}")

    try:
        return _build_campaign_pdf(meta, all_results, discovery_results, group.name)
    except Exception as e:
        logger.error(f"Error building campaign PDF: {str(e)}", exc_info=True)
        raise e


def _build_campaign_pdf(meta, all_results, discovery_results, campaign_name):
    """Internal PDF builder for campaign reports."""
    logger.info(f"Starting PDF build for campaign: {campaign_name}")
    buf = io.BytesIO()
    date_s = fmt_dt(meta.get("created_at"))

    doc = MockDrillDoc(
        buf,
        scan_id=meta["scan_id"],
        domain=meta["domain"],
        generated_date=date_s,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN + 10 * mm,
        bottomMargin=MARGIN + 9 * mm,
        title=f"Mock Drill Campaign Report – {campaign_name}",
        author="Mock Drill Automated Scanner",
        subject="Campaign Security Report",
        creator="Mock Drill Platform v2",
    )

    S = build_styles()
    story = []

    # Handle empty results case
    if not all_results:
        logger.warning("No results found for campaign report, adding placeholder.")
        # We still need basic sections
        story.append(NextPageTemplate("Cover"))
        sec_cover(story, meta)
        story.append(NextPageTemplate("Content"))
        story.append(SectionHeader(2, "Campaign Overview"))
        story.append(Paragraph("No security scan results were found for this campaign.", S["body"]))
        _add_targets_and_services(story, S, discovery_results, section_num=3)
    else:
        # Cover
        logger.debug("Building cover page")
        story.append(NextPageTemplate("Cover"))
        sec_cover(story, meta)

        # Content pages
        logger.debug("Building content sections")
        story.append(NextPageTemplate("Content"))
        logger.debug("Added cover and template, now exec summary")
        sec_executive_summary(story, S, meta, all_results)
        logger.debug("Added exec summary, now risk distribution")
        sec_risk_distribution(story, S, all_results)

        # Campaign-specific: Targets & Services structured list
        logger.debug("Building targets and services list")
        _add_targets_and_services(story, S, discovery_results, section_num=4)

        # Summary table (all findings)
        logger.debug("Building summary table")
        sec_summary_table_campaign(story, S, all_results, discovery_results)

        # Detailed findings grouped by target
        logger.debug("Building grouped detailed findings")
        _add_grouped_detailed_findings(story, S, all_results, discovery_results)

        # High risk findings
        logger.debug("Building high risk findings")
        sec_high_risk_campaign(story, S, all_results)

    logger.debug(f"Finalizing PDF document with {len(story)} flowables")
    doc.build(story)
    pdf_bytes = buf.getvalue()
    buf.close()
    logger.info(f"PDF build complete. Size: {len(pdf_bytes)} bytes")
    return pdf_bytes


def _add_targets_and_services(story, S, discovery_results, section_num=4):
    """Render targets and discovered services in a structured, nested card layout."""
    story.append(PageBreak())
    story.append(SectionHeader(section_num, "Campaign Targets & Services"))
    story.append(Spacer(1, 10))

    if not discovery_results:
        story.append(Paragraph("No discovery data available for this campaign.", S["body"]))
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
        if not key:
            continue
        if key not in targets:
            targets[key] = {
                "ip": t_ip,
                "domain": t_dom,
                "services": []
            }
        targets[key]["services"].append({
            "port": port,
            "service": svc_name or "unknown",
            "engine": eng,
            "version": ver or ""
        })

    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

    def create_shaded_val(label, value, width):
        """Helper to create a label and a shaded value box."""
        val_para = Paragraph(f"<b>{xml(str(value))}</b>", S["body"])
        # Shaded box for the value
        val_box = Table([[val_para]], colWidths=[width * 0.7])
        val_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ('ROUNDEDCORNERS', [4]),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('BOX', (0, 0), (-1, -1), 0.3, C_BORDER),
        ]))
        
        row = Table([
            [Paragraph(f"• {label}:", S["body"]), val_box]
        ], colWidths=[width * 0.25, width * 0.75])
        row.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        return row

    for idx, (target_key, data) in enumerate(sorted(targets.items()), 1):
        target_display = target_key
        if data["domain"] and data["domain"] != data["ip"]:
            target_display = f"{data['domain']} ({data['ip']})"
        
        target_items = []
        target_items.append(Paragraph(f"<b>{idx}. {xml(target_display)}</b>", S["body_b"]))
        target_items.append(Spacer(1, 6))
        
        has_multiple = len(data["services"]) > 1
        card_inner_w = inner_w - 20 # Subtracting padding of RoundedBox
        
        for svc in data["services"]:
            svc_items = []
            svc_items.append(create_shaded_val("Port", svc['port'], card_inner_w - (16 if has_multiple else 0)))
            svc_items.append(create_shaded_val("Service", svc['service'], card_inner_w - (16 if has_multiple else 0)))
            if svc['version']:
                svc_items.append(create_shaded_val("Info", svc['version'][:200], card_inner_w - (16 if has_multiple else 0)))
            
            if has_multiple:
                # Nested card for each service if multiple ports
                svc_card = create_rounded_box(svc_items, card_inner_w - (16 if has_multiple else 0), bg=colors.white, border=C_BORDER, pad=8, radius=4)
                target_items.append(svc_card)
                target_items.append(Spacer(1, 4))
            else:
                target_items.extend(svc_items)
                target_items.append(Spacer(1, 4))

        # Main Target Card
        main_card = create_rounded_box(target_items, inner_w, bg=C_BG1, border=C_BORDER, pad=10)
        
        story.append(main_card)
        story.append(Spacer(1, 10))


def sec_summary_table_campaign(story, S, results, discovery_results):
    """Campaign version of summary table, separated by target and service, with capsules."""
    story.append(PageBreak())
    story.append(SectionHeader(5, "Summary of Findings"))
    story.append(Spacer(1, 10))

    # Build discovery map for info
    disc_map = {}
    for dr in discovery_results:
        key = (dr.target_ip or dr.target_domain, dr.port)
        disc_map[key] = dr.version_info or "N/A"

    # Group by target and port/service
    grouped = {}
    for r in results:
        t = r.get("scan_target", "Unknown Target")
        p = r.get("scan_port")
        s = r.get("scan_engine", "Unknown Service")
        key = (t, p, s)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(r)

    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

    def create_capsule(label, text, bg_color):
        p = Paragraph(f"<font size='8'><b>{label}:</b> {xml(str(text))}</font>", S["body"])
        t = Table([[p]], hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg_color),
            ('ROUNDEDCORNERS', [4]),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('BOX', (0,0), (-1,-1), 0.3, C_BORDER),
        ]))
        return t

    first = True
    for (target, port, engine), res_list in sorted(grouped.items()):
        if not first:
            story.append(PageBreak())
        first = False
        
        story.append(Spacer(1, 4))
        # Target Header
        story.append(Paragraph(f"<b>Target: {xml(target)}</b>", S["sub_h"]))
        story.append(HRule(C_BORDER, 0.5))
        story.append(Spacer(1, 6))

        # Capsules row
        port_s = str(port) if port else "N/A"
        info_s = disc_map.get((target, port), "N/A")
        
        caps_row = [
            create_capsule("Port", port_s, colors.HexColor("#E0F2FE")), # Light blue
            create_capsule("Service", engine.upper(), colors.HexColor("#DCFCE7")), # Light green
        ]
        
        caps_tbl = Table([caps_row], hAlign='LEFT', colWidths=[None, None])
        caps_tbl.setStyle(TableStyle([
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(caps_tbl)
        story.append(Spacer(1, 4))
        
        # Info capsule (full width or below)
        info_capsule = create_capsule("Info", info_s[:200], colors.HexColor("#F1F5F9")) # Light gray
        story.append(info_capsule)
        story.append(Spacer(1, 10))
        
        # Table
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

        sorted_res = sorted(res_list, key=lambda x: natural_sort_key(x.get("check_id")))

        for i, r in enumerate(sorted_res, 1):
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

        row_cmds = []
        for i, r in enumerate(sorted_res, 1):
            if to_yn(r.get("result")) == "N":
                row_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFF5F5")))

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
        story.append(Spacer(1, 10))


def sec_high_risk_campaign(story, S, results):
    """Campaign version of high risk findings with corrected numbering (7)."""
    story.append(PageBreak())
    story.append(SectionHeader(7, "High Risk Findings", bg=colors.HexColor("#B71C1C")))
    story.append(Spacer(1, 10))

    high_risk = [
        r for r in sorted(results, key=lambda x: natural_sort_key(x.get("check_id")))
        if sev_key(r.get("severity")) in ("HIGH", "CRITICAL")
        and to_yn(r.get("result")) == "N"
    ]

    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent

    if not high_risk:
        box = RoundedBox(
            [Paragraph("✓  No HIGH or CRITICAL severity failures were identified in this scan.", S["ok_msg"])],
            bg=colors.HexColor("#F1F8E9"),
            border=colors.HexColor("#A5D6A7"),
            pad=14,
        )
        wrapper = Table([[box]], colWidths=[inner_w], hAlign='CENTER')
        wrapper.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(wrapper)
        return

    cw = [inner_w * 0.28, inner_w * 0.12, inner_w * 0.30, inner_w * 0.30]
    hdr = [Paragraph(h, S["tbl_hdr"]) for h in ["Check Name", "Severity", "Risk Summary", "Recommendation"]]
    rows = [hdr]

    for r in high_risk:
        rows.append([
            Paragraph(xml(safe(r.get("check_name"), "Unknown")), S["tbl_cell"]),
            SevBadge(sev_key(r.get("severity"))),
            Paragraph(xml(safe(r.get("decision_logic"), "—")[:250]), S["tbl_cell"]),
            Paragraph(xml(safe(r.get("remediation_text"), "See detailed findings.")[:250]), S["tbl_cell"]),
        ])

    tbl = Table(rows, colWidths=cw, repeatRows=1, splitByRow=True, hAlign='CENTER')
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#C62828")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#FFEBEE"), colors.HexColor("#FFF5F5")]),
        ("BOX",           (0, 0), (-1, -1), 0.6, colors.HexColor("#EF9A9A")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, colors.HexColor("#FFCDD2")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (0, 0), (-1, 0), "CENTER"),
        ("ALIGN",         (1, 1), (1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 5),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(tbl)


def _add_grouped_detailed_findings(story, S, all_results, discovery_results):
    """Render detailed findings for each target, grouped with capsules."""

    story.append(PageBreak())
    story.append(SectionHeader(6, "Detailed Findings by Target"))
    story.append(Spacer(1, 10))

    # Build discovery map for info
    disc_map = {}
    for dr in discovery_results:
        key = (dr.target_ip or dr.target_domain, dr.port)
        disc_map[key] = dr.version_info or "N/A"

    # Group by target and port/service
    grouped = {}
    for r in all_results:
        t = r.get("scan_target", "Unknown Target")
        p = r.get("scan_port")
        s = r.get("scan_engine", "Unknown Service")
        key = (t, p, s)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(r)

    def create_capsule(label, text, bg_color):
        p = Paragraph(f"<font size='8'><b>{label}:</b> {xml(str(text))}</font>", S["body"])
        t = Table([[p]], hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg_color),
            ('ROUNDEDCORNERS', [4]),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('BOX', (0,0), (-1,-1), 0.3, C_BORDER),
        ]))
        return t

    first = True
    for (target, port, engine), results_list in sorted(grouped.items()):
        if not first:
            story.append(PageBreak())
        first = False
        
        story.append(Spacer(1, 4))
        # Target Header
        story.append(Paragraph(f"<b>Target: {xml(target)}</b>", S["sub_h"]))
        story.append(HRule(C_BORDER, 0.5))
        story.append(Spacer(1, 6))

        # Capsules row
        port_s = str(port) if port else "N/A"
        info_s = disc_map.get((target, port), "N/A")
        
        caps_row = [
            create_capsule("Port", port_s, colors.HexColor("#E0F2FE")), # Light blue
            create_capsule("Service", engine.upper(), colors.HexColor("#DCFCE7")), # Light green
        ]
        
        caps_tbl = Table([caps_row], hAlign='LEFT', colWidths=[None, None])
        caps_tbl.setStyle(TableStyle([
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(caps_tbl)
        story.append(Spacer(1, 4))
        
        # Info capsule
        info_capsule = create_capsule("Info", info_s[:200], colors.HexColor("#F1F5F9")) # Light gray
        story.append(info_capsule)
        story.append(Spacer(1, 10))

        sorted_results = sorted(results_list, key=lambda r: natural_sort_key(r.get("check_id")))
        for idx, r in enumerate(sorted_results, 1):
            _render_single_check(story, S, r, idx)
            if idx < len(sorted_results):
                story.append(Spacer(1, 4))
        story.append(Spacer(1, 12))
