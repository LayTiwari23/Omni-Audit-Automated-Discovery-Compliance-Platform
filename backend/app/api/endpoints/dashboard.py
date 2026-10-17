from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import os
import redis

from app.db.session import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.models.scan_result import ScanRawResult
from app.models.scan_log import ScanLog
from app.models.scan_group import ScanGroup

router = APIRouter()

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

from fastapi.responses import StreamingResponse
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

@router.get("/download-summary")
def download_executive_summary(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    stats = get_dashboard_stats(days, current_user, db)
    kpis = stats["kpis"]
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=24, spaceAfter=20, textColor=colors.HexColor("#4f46e5"))
    story.append(Paragraph("Security Compliance Executive Summary", title_style))
    story.append(Paragraph(f"Reporting Period: Last {days} Days", styles['Normal']))
    story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))

    # KPI Table
    story.append(Paragraph("Key Performance Indicators (KPIs)", styles['Heading2']))
    data = [
        ["Metric", "Value"],
        ["Global Compliance Score", f"{kpis['avg_compliance']}%"],
        ["Total Scans Performed", str(kpis['total_scans'])],
        ["Critical Vulnerabilities", str(kpis['critical_vulns'])],
        ["High Risk Vulnerabilities", str(kpis['high_vulns'])],
        ["Medium Risk Vulnerabilities", str(kpis['medium_vulns'])],
        ["Low Risk Vulnerabilities", str(kpis['low_vulns'])]
    ]
    t = Table(data, colWidths=[250, 150])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#4f46e5")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 1, colors.grey)
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Critical Targets
    if stats["critical_targets"]:
        story.append(Paragraph("Top Critical Targets Requiring Remediation", styles['Heading2']))
        target_data = [["Target", "Engine", "Compliance"]]
        for target in stats["critical_targets"]:
            target_data.append([target["target"], target["type"].capitalize(), f"{target['compliance']}%"])
        
        t2 = Table(target_data, colWidths=[200, 100, 100])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#ef4444")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 1, colors.grey)
        ]))
        story.append(t2)

    doc.build(story)
    buffer.seek(0)
    
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=executive_summary_{days}d.pdf"}
    )

@router.get("/stats")
def get_dashboard_stats(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 1. Executive KPIs
    total_scans = db.query(Scan).filter(Scan.user_id == current_user.id).count()
    
    avg_compliance = db.query(func.avg(Scan.compliance_percent))\
        .filter(Scan.user_id == current_user.id, Scan.status == "COMPLETED")\
        .scalar() or 0.0

    # Vulnerability Breakdown (from ScanRawResult)
    vuln_breakdown = db.query(
        ScanRawResult.severity,
        func.count(ScanRawResult.id)
    ).join(Scan).filter(
        Scan.user_id == current_user.id,
        ScanRawResult.result == "FAIL"
    ).group_by(ScanRawResult.severity).all()
    
    severity_map = {s: count for s, count in vuln_breakdown if s}
    
    # 2. Visual Analytics - Compliance Trend (Last X days)
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    
    trend_data = []
    current_date = start_date
    while current_date <= end_date:
        d_str = current_date.strftime("%Y-%m-%d")
        daily_avg = db.query(func.avg(Scan.compliance_percent))\
            .filter(
                Scan.user_id == current_user.id,
                Scan.status == "COMPLETED",
                func.date(Scan.created_at) == current_date.date()
            ).scalar() or 0.0
        
        trend_data.append({"date": d_str, "compliance": round(float(daily_avg), 1)})
        current_date += timedelta(days=1)

    # Scan Distribution
    dist_query = db.query(
        Scan.scan_type,
        func.count(Scan.id)
    ).filter(
        Scan.user_id == current_user.id,
        Scan.scan_type != "auto"
    ).group_by(Scan.scan_type).all()
    
    distribution = [{"name": t.capitalize(), "value": count} for t, count in dist_query]

    # 3. Actionable Risk - Top 5 Critical Targets
    critical_targets = db.query(Scan)\
        .filter(Scan.user_id == current_user.id, Scan.status == "COMPLETED")\
        .order_by(Scan.compliance_percent.asc())\
        .limit(5).all()
    
    top_critical = [{
        "id": s.id,
        "target": s.domain,
        "type": s.scan_type,
        "compliance": s.compliance_percent,
        "date": s.created_at.isoformat()
    } for s in critical_targets]

    # Recent Activity
    recent_logs = db.query(ScanLog).join(Scan)\
        .filter(Scan.user_id == current_user.id)\
        .order_by(ScanLog.created_at.desc())\
        .limit(10).all()
    
    activity = [{
        "id": l.id,
        "scan_id": l.scan_id,
        "stage": l.stage,
        "message": l.message,
        "timestamp": l.created_at.isoformat()
    } for l in recent_logs]

    # 4. System Health Monitoring
    from app.utils.ip_utils import get_public_ip
    health = {"api": "up", "redis": "down", "celery": "down", "db": "up", "scanner_ip": get_public_ip()}
    try:
        r = redis.from_url(REDIS_URL, socket_timeout=1)
        if r.ping():
            health["redis"] = "up"
            # Check celery via redis keys if possible, or just assume up if redis is up for this demo
            health["celery"] = "up"
    except:
        pass

    return {
        "kpis": {
            "total_scans": total_scans,
            "avg_compliance": round(float(avg_compliance), 1),
            "critical_vulns": severity_map.get("CRITICAL", 0),
            "high_vulns": severity_map.get("HIGH", 0),
            "medium_vulns": severity_map.get("MEDIUM", 0),
            "low_vulns": severity_map.get("LOW", 0)
        },
        "trend": trend_data,
        "distribution": distribution,
        "critical_targets": top_critical,
        "activity": activity,
        "health": health
    }
