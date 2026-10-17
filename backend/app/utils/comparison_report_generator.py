"""
# Comparison Report Generator for Mock Drill Platform

================================================
Generates professional PDF comparison reports for two scans or two campaigns.
"""

import io
import logging
from sqlalchemy import text
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    NextPageTemplate, PageBreak, Paragraph, Spacer, Table, TableStyle, Flowable
)

from app.utils.report_generator import (
    build_styles, MockDrillDoc, SectionHeader, RoundedBox, YNBadge,
    sec_cover, xml, safe, fmt_dt, to_yn,
    C_BLUE, C_NAVY, C_BORDER, C_BG1, C_BG2, C_MUTED,
    CONTENT_W, MARGIN
)

logger = logging.getLogger(__name__)

class ComparisonBar(Flowable):
    """Horizontal bar for comparison metrics."""
    def __init__(self, val, max_v, color, width=200):
        super().__init__()
        self.val = val; self.max_v = max_v; self.color = color
        self.width = width
    def wrap(self, aw, ah):
        return self.width, 14
    def draw(self):
        w = (self.val / self.max_v) * (self.width - 4) if self.max_v > 0 else 0
        self.canv.setFillColor(colors.HexColor("#F1F3F4"))
        self.canv.roundRect(0, 2, self.width, 10, 5, stroke=0, fill=1)
        if w > 0:
            self.canv.setFillColor(self.color)
            self.canv.roundRect(0, 2, w, 10, 5, stroke=0, fill=1)

class ComparisonCard(Flowable):
    """Stat card for comparison metrics."""
    def __init__(self, label, value, sublabel, color=C_NAVY, width=150, height=65):
        super().__init__()
        self.label = label
        self.value = value
        self.sublabel = sublabel
        self.color = color
        self.w = width
        self.h = height

    def wrap(self, aw, ah):
        return self.w, self.h

    def draw(self):
        c = self.canv
        # Border and background
        c.setStrokeColor(C_BORDER)
        c.setFillColor(C_BG2)
        c.setLineWidth(0.8)
        c.roundRect(0, 0, self.w, self.h, 8, stroke=1, fill=1)
        
        # Left accent stripe
        c.setFillColor(self.color)
        c.roundRect(0, 0, 4, self.h, 3, stroke=0, fill=1)
        
        # Label
        c.setFillColor(C_MUTED)
        c.setFont("Times-Bold", 8)
        c.drawString(12, self.h - 18, self.label.upper())
        
        # Value
        c.setFillColor(colors.HexColor("#1A1A2E"))
        c.setFont("Times-Bold", 18)
        c.drawString(12, self.h - 42, str(self.value))
        
        # Sublabel
        c.setFillColor(C_MUTED)
        c.setFont("Times-Roman", 7.5)
        c.drawString(12, 10, self.sublabel)

def generate_comparison_report(scan1_id: int, scan2_id: int, db: Session) -> bytes:
    """Generate a PDF comparing two specific scans."""
    
    # 1. Fetch metadata
    s1 = db.execute(text("SELECT id, domain, scan_type, created_at, compliance_percent FROM scans WHERE id = :id"), {"id": scan1_id}).fetchone()
    s2 = db.execute(text("SELECT id, domain, scan_type, created_at, compliance_percent FROM scans WHERE id = :id"), {"id": scan2_id}).fetchone()
    
    if not s1 or not s2:
        raise ValueError("One or both scans not found")

    pct1 = s1[4] or 0.0
    pct2 = s2[4] or 0.0
    diff = round(pct2 - pct1, 2)

    # 2. Fetch and compare results
    def _get_results(sid):
        rows = db.execute(
            text("SELECT check_id, check_name, result, severity FROM scan_raw_results WHERE scan_id = :sid"),
            {"sid": sid}
        ).fetchall()
        return {r[0]: {"name": r[1], "result": r[2], "sev": r[3]} for r in rows}

    r1 = _get_results(scan1_id)
    r2 = _get_results(scan2_id)
    
    all_check_ids = sorted(set(r1.keys()) | set(r2.keys()))
    
    unchanged_data = []
    changed_data = []
    improved = 0
    worsened = 0
    unchanged = 0

    for cid in all_check_ids:
        v1 = r1.get(cid, {}).get("result", "FAIL")
        v2 = r2.get(cid, {}).get("result", "FAIL")
        name = r1.get(cid, {}).get("name") or r2.get(cid, {}).get("name") or f"Check {cid}"
        
        if v1 == v2:
            unchanged += 1
            unchanged_data.append({
                "id": cid,
                "name": name,
                "res": v1
            })
        else:
            status = "BETTER" if (v1 == "FAIL" and v2 == "PASS") else "WORSENED"
            if status == "BETTER": improved += 1
            else: worsened += 1
            
            changed_data.append({
                "id": cid,
                "name": name,
                "res1": v1,
                "res2": v2,
                "status": status
            })

    # 3. Build PDF
    buf = io.BytesIO()
    meta = {
        "domain": f"Comparison: {s1[1]} vs {s2[1]}",
        "scan_id": f"COMP-{scan1_id}-{scan2_id}",
        "scan_type": "Comparison Report",
        "created_at": datetime.now()
    }
    
    doc = MockDrillDoc(
        buf,
        meta["scan_id"],
        meta["domain"],
        fmt_dt(meta["created_at"]),
        title=f"Mock Drill Comparison Report",
    )
    
    S = build_styles()
    story = []

    # Cover
    story.append(NextPageTemplate("Cover"))
    sec_cover(story, meta)
    
    # Content
    story.append(NextPageTemplate("Content"))
    story.append(Spacer(1, 25)) # Move content down from the top
    story.append(SectionHeader(1, "Comparison Summary"))
    
    # --- Indented Summary Cards ---
    story.append(Spacer(1, 10))
    indent = 4 * mm
    inner_w = CONTENT_W - 2 * indent
    
    card_w = (inner_w - 20) / 3
    delta_color = colors.HexColor("#10B981") if diff >= 0 else colors.HexColor("#F43F5E")
    
    baseline_card = ComparisonCard("Baseline", f"{pct1}%", f"Scan #{s1[0]} ({s1[2].upper()})", color=C_NAVY, width=card_w)
    delta_card = ComparisonCard("Delta", f"{'+' if diff > 0 else ''}{diff}%", "Global Compliance Change", color=delta_color, width=card_w)
    target_card = ComparisonCard("Target", f"{pct2}%", f"Scan #{s2[0]} ({s2[2].upper()})", color=C_NAVY, width=card_w)
    
    card_table = Table([[baseline_card, delta_card, target_card]], colWidths=[card_w+10, card_w+10, card_w+10])
    card_table.setStyle(TableStyle([
        ('LEFTPADDING', (0,0), (-1,-1), indent),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 15))

    # --- Distribution Section ---
    story.append(SectionHeader(2, "Change Distribution Analysis"))
    story.append(Spacer(1, 10))
    
    max_c = max(improved, worsened, unchanged, 1)
    
    dist_data = [
        [Paragraph("Improved (Better)", S["body_b"]), Paragraph(str(improved), S["body"]), ComparisonBar(improved, max_c, colors.HexColor("#10B981"), width=inner_w*0.5)],
        [Paragraph("Regressed (Worsened)", S["body_b"]), Paragraph(str(worsened), S["body"]), ComparisonBar(worsened, max_c, colors.HexColor("#F43F5E"), width=inner_w*0.5)],
        [Paragraph("No Change", S["body_b"]), Paragraph(str(unchanged), S["body"]), ComparisonBar(unchanged, max_c, colors.HexColor("#6B7280"), width=inner_w*0.5)],
    ]
    
    dist_table = Table(dist_data, colWidths=[inner_w*0.25, inner_w*0.1, inner_w*0.65], hAlign='LEFT')
    dist_table.setStyle(TableStyle([
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    
    dist_card = RoundedBox([dist_table], bg=C_BG1, border=C_BORDER, pad=10)
    story.append(Table([[dist_card]], colWidths=[inner_w], hAlign='CENTER'))
    story.append(Spacer(1, 20))

    # --- Category 1: Unchanged Checks ---
    story.append(PageBreak())
    story.append(SectionHeader(3, "Detailed Findings: Unchanged Checks"))
    story.append(Spacer(1, 10))
    
    if not unchanged_data:
        story.append(Paragraph("No unchanged checks found.", S["body"]))
    else:
        cw_u = [inner_w*0.08, inner_w*0.72, inner_w*0.20]
        h_u = [Paragraph(h, S["tbl_hdr"]) for h in ["#", "Check Name", "Status (Both)"]]
        rows_u = [h_u]
        for i, d in enumerate(unchanged_data, 1):
            rows_u.append([
                Paragraph(str(i), S["tbl_cc"]),
                Paragraph(xml(d["name"]), S["tbl_cell"]),
                YNBadge(to_yn(d["res"]), 24, 14)
            ])
        ct_u = Table(rows_u, colWidths=cw_u, repeatRows=1)
        ct_u.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_NAVY),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_BG1, C_BG2]),
            ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(Table([[ct_u]], colWidths=[inner_w], hAlign='CENTER'))

    # --- Category 2: Changed Checks ---
    story.append(PageBreak())
    story.append(SectionHeader(4, "Detailed Findings: Changed Checks"))
    story.append(Spacer(1, 10))
    
    if not changed_data:
        story.append(Paragraph("No security posture changes detected between baseline and target.", S["body"]))
    else:
        cw_c = [inner_w*0.08, inner_w*0.52, inner_w*0.12, inner_w*0.12, inner_w*0.16]
        h_c = [Paragraph(h, S["tbl_hdr"]) for h in ["#", "Check Name", "Baseline", "Target", "Change"]]
        rows_c = [h_c]
        
        for i, d in enumerate(changed_data, 1):
            change_color = "#10B981" if d["status"] == "BETTER" else "#F43F5E"
            rows_c.append([
                Paragraph(str(i), S["tbl_cc"]),
                Paragraph(xml(d["name"]), S["tbl_cell"]),
                YNBadge(to_yn(d["res1"]), 24, 14),
                YNBadge(to_yn(d["res2"]), 24, 14),
                Paragraph(f"<font color='{change_color}'><b>{d['status']}</b></font>", S["tbl_cc"])
            ])
            
        ct_c = Table(rows_c, colWidths=cw_c, repeatRows=1)
        ct_c.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), C_NAVY),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [C_BG1, C_BG2]),
            ('GRID', (0,0), (-1,-1), 0.3, C_BORDER),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(Table([[ct_c]], colWidths=[inner_w], hAlign='CENTER'))

    doc.build(story)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes
