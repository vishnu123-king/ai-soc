from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from backend.app.database.connection import get_db
from backend.app.models.incident import Incident

router = APIRouter()

@router.get("/incident/{id}")
def generate_incident_html_report(id: int, db: Session = Depends(get_db)):
    """
    Generates a printable, high-contrast HTML executive security incident report.
    """
    inc = db.query(Incident).filter(Incident.id == id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    latest_ai = inc.ai_analyses[-1] if inc.ai_analyses else None

    # Format detections table rows
    detections_html = "".join([
        f"""<tr>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-family: monospace;">{d.rule_id}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: 600;">{d.title}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;"><span style="background: {'#fee2e2' if d.severity in ['HIGH', 'CRITICAL'] else '#fef3c7'}; color: {'#991b1b' if d.severity in ['HIGH', 'CRITICAL'] else '#92400e'}; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">{d.severity}</span></td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{d.mitre_technique_id} - {d.mitre_technique_name}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #64748b;">{d.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
        </tr>"""
        for d in inc.detections
    ])

    # Format MITRE badges
    mitre_html = "".join([
        f"""<div style="background: #f1f5f9; border-left: 4px solid #0284c7; padding: 8px 12px; margin-bottom: 6px; border-radius: 2px;">
            <strong>{m.get('id')}</strong>: {m.get('name')} <span style="color: #64748b;">({m.get('tactic')})</span>
        </div>"""
        for m in (inc.mitre_techniques or [])
    ])

    ai_section_html = ""
    if latest_ai:
        evidence_list = "".join([f"<li>{ev}</li>" for ev in (latest_ai.observed_evidence or [])])
        investigation_list = "".join([f"<li>{step}</li>" for step in (latest_ai.investigation_steps or [])])
        containment_list = "".join([f"<li>{item}</li>" for item in (latest_ai.containment_recommendations or [])])

        ai_section_html = f"""
        <div style="margin-top: 30px; background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 16px;">
                <h2 style="margin: 0; font-size: 18px; color: #0f172a;">AI Security Analyst Assessment</h2>
                <span style="font-size: 12px; color: #64748b; font-family: monospace;">Engine: {latest_ai.model_provider}</span>
            </div>
            
            <p style="font-size: 15px; line-height: 1.6; color: #334155;"><strong>Summary:</strong> {latest_ai.summary}</p>
            <p><strong>Attack Classification:</strong> {latest_ai.attack_type}</p>
            <p><strong>Assessed Severity:</strong> {latest_ai.severity_assessment} (Confidence: {int((latest_ai.confidence or 0.9)*100)}%)</p>
            
            <h3 style="font-size: 15px; color: #1e293b; margin-top: 18px;">Observed Evidence (Anti-Hallucination Verified)</h3>
            <ul style="color: #475569; line-height: 1.5; font-size: 14px;">{evidence_list or "<li>No specific raw facts parsed</li>"}</ul>

            <h3 style="font-size: 15px; color: #1e293b; margin-top: 18px;">Forensic Triage Steps</h3>
            <ul style="color: #475569; line-height: 1.5; font-size: 14px;">{investigation_list or "<li>No investigation steps suggested</li>"}</ul>

            <h3 style="font-size: 15px; color: #1e293b; margin-top: 18px;">Containment & Remediation Actions</h3>
            <ul style="color: #475569; line-height: 1.5; font-size: 14px;">{containment_list or "<li>No immediate containment required</li>"}</ul>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI-SOC Incident Report #{inc.id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #0f172a; }}
        h1 {{ font-size: 24px; border-bottom: 2px solid #0f172a; padding-bottom: 12px; margin-bottom: 20px; }}
        .header-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; background: #f8fafc; padding: 16px; border-radius: 6px; }}
        .metric-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; font-weight: bold; margin-bottom: 4px; }}
        .metric-value {{ font-size: 18px; font-weight: bold; color: #0f172a; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; text-align: left; }}
        th {{ background: #f1f5f9; padding: 10px 8px; border-bottom: 2px solid #cbd5e1; font-size: 12px; text-transform: uppercase; color: #475569; }}
        @media print {{
            body {{ margin: 20px; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="no-print" style="margin-bottom: 20px; text-align: right;">
        <button onclick="window.print()" style="background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold;">Print / Save PDF</button>
    </div>

    <h1>AI-SOC Incident Investigation Report #{inc.id}</h1>
    <div style="font-size: 15px; color: #475569; margin-bottom: 20px;">{inc.title}</div>

    <div class="header-grid">
        <div>
            <div class="metric-label">Severity / Risk Score</div>
            <div class="metric-value">{inc.severity} ({inc.risk_score}/100)</div>
        </div>
        <div>
            <div class="metric-label">Current Status</div>
            <div class="metric-value">{inc.status}</div>
        </div>
        <div>
            <div class="metric-label">Impacted Host</div>
            <div class="metric-value">{inc.hostname}</div>
        </div>
        <div>
            <div class="metric-label">Threat Source IP</div>
            <div class="metric-value">{inc.source_ip or "Internal / Unresolved"}</div>
        </div>
    </div>

    <div style="margin-bottom: 24px;">
        <h3 style="font-size: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">Risk Calculation Explanation</h3>
        <p style="color: #334155; line-height: 1.6; font-size: 14px;">{inc.risk_explanation or "Automated deterministic risk evaluation."}</p>
    </div>

    <div style="margin-bottom: 24px;">
        <h3 style="font-size: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">Mapped MITRE ATT&CK Techniques</h3>
        {mitre_html if mitre_html else "<p style='color: #64748b;'>No specific techniques mapped.</p>"}
    </div>

    <div style="margin-bottom: 24px;">
        <h3 style="font-size: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">Correlated Detections ({len(inc.detections)})</h3>
        <table>
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Detection Title</th>
                    <th>Severity</th>
                    <th>MITRE ATT&CK</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                {detections_html if detections_html else "<tr><td colspan='5' style='padding: 12px; text-align: center; color: #94a3b8;'>No detections</td></tr>"}
            </tbody>
        </table>
    </div>

    {ai_section_html}

    <div style="margin-top: 40px; border-top: 1px solid #cbd5e1; padding-top: 12px; font-size: 12px; color: #94a3b8; display: flex; justify-content: space-between;">
        <span>Generated by AI-SOC Central Platform</span>
        <span>Generated: {inc.updated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
    </div>
</body>
</html>"""

    return Response(content=html_content, media_type="text/html")
