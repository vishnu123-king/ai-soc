import html
from typing import Dict, Any
from datetime import datetime

def generate_html_incident_report(incident_data: Dict[str, Any]) -> str:
    """
    Generates a formal, printable HTML Incident Response & SOC Triage Report.
    """
    incident_id = incident_data.get("id", "N/A")
    title = html.escape(str(incident_data.get("title", "Security Incident")))
    severity = str(incident_data.get("severity", "UNKNOWN")).upper()
    risk_score = incident_data.get("risk_score", 0.0)
    risk_explanation = html.escape(str(incident_data.get("risk_explanation", "")))
    host = html.escape(str(incident_data.get("affected_host", "N/A")))
    source_ip = html.escape(str(incident_data.get("source_ip", "N/A")))
    username = html.escape(str(incident_data.get("username", "N/A")))
    status = html.escape(str(incident_data.get("status", "OPEN")))
    created_at = str(incident_data.get("created_at", datetime.utcnow().isoformat()))
    
    alerts = incident_data.get("alerts", [])
    mitre_techniques = incident_data.get("mitre_techniques", [])
    ai_analysis = incident_data.get("ai_analysis") or {}

    sev_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
    }.get(severity, "#64748b")

    # MITRE badges
    mitre_html = ""
    for t in mitre_techniques:
        tid = html.escape(t.get("id", ""))
        tname = html.escape(t.get("name", ""))
        ttactic = html.escape(t.get("tactic", ""))
        mitre_html += f"""
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px 12px; margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 700; color: #38bdf8; font-family: monospace;">{tid}</span>
                <span style="font-size: 11px; background: #0f172a; color: #94a3b8; padding: 2px 6px; border-radius: 4px;">{ttactic}</span>
            </div>
            <div style="font-size: 13px; color: #f1f5f9; margin-top: 4px;">{tname}</div>
        </div>
        """

    # Alerts table
    alerts_rows = ""
    for a in alerts:
        a_time = html.escape(str(a.get("timestamp", "")))
        a_rule = html.escape(str(a.get("rule_name", "")))
        a_sev = html.escape(str(a.get("severity", "")))
        a_desc = html.escape(str(a.get("description", "")))
        a_tech = html.escape(str(a.get("mitre_technique_id", "N/A")))
        alerts_rows += f"""
        <tr style="border-bottom: 1px solid #334155;">
            <td style="padding: 10px; font-family: monospace; font-size: 12px; color: #94a3b8;">{a_time}</td>
            <td style="padding: 10px; font-weight: 600; color: #f8fafc;">{a_rule}</td>
            <td style="padding: 10px;"><span style="background: #0f172a; border: 1px solid #475569; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: {sev_color};">{a_sev}</span></td>
            <td style="padding: 10px; font-family: monospace; color: #38bdf8;">{a_tech}</td>
            <td style="padding: 10px; font-size: 13px; color: #cbd5e1;">{a_desc}</td>
        </tr>
        """

    # AI Section
    ai_summary = html.escape(str(ai_analysis.get("incident_summary", "No AI analysis performed yet.")))
    ai_attack_type = html.escape(str(ai_analysis.get("likely_attack_type", "Pending Triage")))
    ai_confidence = f"{float(ai_analysis.get('confidence', 0.0)) * 100:.0f}%" if ai_analysis.get("confidence") else "N/A"
    ai_model = html.escape(str(ai_analysis.get("model_provider", "Heuristic / Rule Engine")))

    progression_items = "".join(f"<li style='margin-bottom: 6px; color: #e2e8f0;'>{html.escape(str(step))}</li>" for step in ai_analysis.get("attack_progression", []))
    investigation_items = "".join(f"<li style='margin-bottom: 6px; color: #e2e8f0;'>{html.escape(str(step))}</li>" for step in ai_analysis.get("recommended_investigation_steps", []))
    containment_items = "".join(f"<li style='margin-bottom: 6px; color: #e2e8f0;'>{html.escape(str(step))}</li>" for step in ai_analysis.get("recommended_containment_steps", []))
    evidence_items = "".join(f"<li style='margin-bottom: 4px; font-family: monospace; font-size: 12px; color: #cbd5e1;'>{html.escape(str(ev))}</li>" for step in ai_analysis.get("evidence", []) for ev in [step])

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI-SOC Incident Report - INC-{incident_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #0b0f19;
            color: #e2e8f0;
            line-height: 1.6;
            margin: 0;
            padding: 32px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
        }}
        .header {{
            border-bottom: 2px solid #1f2937;
            padding-bottom: 24px;
            margin-bottom: 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 12px;
            letter-spacing: 0.05em;
        }}
        .section {{
            margin-bottom: 32px;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: 700;
            color: #f8fafc;
            border-left: 4px solid #38bdf8;
            padding-left: 12px;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        .card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th {{
            background: #1e293b;
            color: #94a3b8;
            font-size: 12px;
            text-align: left;
            padding: 10px;
            text-transform: uppercase;
        }}
        @media print {{
            body {{ background: white; color: #111827; padding: 0; }}
            .container {{ border: none; box-shadow: none; padding: 0; background: white; }}
            .card {{ border: 1px solid #ccc; background: #f9f9f9; }}
            th {{ background: #eee; color: #333; }}
            tr {{ border-bottom: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div style="font-size: 12px; color: #38bdf8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;">AI-SOC Automated Security Incident Report</div>
                <h1 style="margin: 4px 0 0 0; font-size: 26px; color: #f8fafc;">INC-{incident_id}: {title}</h1>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color};">{severity}</span>
                <div style="font-size: 12px; color: #64748b; margin-top: 6px;">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Incident Metadata & Risk Assessment</div>
            <div class="grid-2">
                <div class="card">
                    <table style="margin: 0;">
                        <tr><td style="color: #94a3b8; font-size: 13px; padding: 4px 0;">Affected Host:</td><td style="font-weight: 600; font-family: monospace;">{host}</td></tr>
                        <tr><td style="color: #94a3b8; font-size: 13px; padding: 4px 0;">Threat Source IP:</td><td style="font-weight: 600; font-family: monospace; color: #f87171;">{source_ip}</td></tr>
                        <tr><td style="color: #94a3b8; font-size: 13px; padding: 4px 0;">Targeted Account:</td><td style="font-weight: 600; font-family: monospace;">{username}</td></tr>
                        <tr><td style="color: #94a3b8; font-size: 13px; padding: 4px 0;">Lifecycle Status:</td><td><span style="background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 11px;">{status}</span></td></tr>
                        <tr><td style="color: #94a3b8; font-size: 13px; padding: 4px 0;">First Detected:</td><td style="font-size: 12px; font-family: monospace;">{created_at}</td></tr>
                    </table>
                </div>
                <div class="card" style="display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;">
                    <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Deterministic Risk Score</div>
                    <div style="font-size: 48px; font-weight: 800; color: {sev_color}; margin: 4px 0;">{risk_score}<span style="font-size: 20px; color: #64748b;">/100</span></div>
                    <div style="font-size: 12px; color: #cbd5e1; max-width: 90%;">{risk_explanation}</div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">AI Analyst Assessment ({ai_model})</div>
            <div class="card" style="margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="font-weight: 700; color: #38bdf8;">Likely Attack Taxonomy:</span>
                    <span style="color: #cbd5e1; font-size: 13px;">Confidence: <strong>{ai_confidence}</strong></span>
                </div>
                <div style="font-size: 15px; font-weight: 600; color: #f8fafc; margin-bottom: 12px;">{ai_attack_type}</div>
                <p style="font-size: 14px; color: #cbd5e1; margin: 0;">{ai_summary}</p>
            </div>

            <div class="grid-2">
                <div class="card">
                    <h4 style="margin: 0 0 10px 0; color: #38bdf8; font-size: 14px;">Hypothesized Attack Progression</h4>
                    <ol style="padding-left: 20px; margin: 0; font-size: 13px;">
                        {progression_items or "<li>Activity telemetry under triage.</li>"}
                    </ol>
                </div>
                <div class="card">
                    <h4 style="margin: 0 0 10px 0; color: #38bdf8; font-size: 14px;">Correlated Evidence Points</h4>
                    <ul style="padding-left: 20px; margin: 0;">
                        {evidence_items or "<li>No specific evidence extracted.</li>"}
                    </ul>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">MITRE ATT&CK Mapping</div>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px;">
                {mitre_html or "<div style='color: #64748b;'>No MITRE techniques mapped.</div>"}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Correlated Detections Timeline</div>
            <div class="card" style="padding: 0; overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Detection Rule</th>
                            <th>Severity</th>
                            <th>MITRE ID</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alerts_rows or "<tr><td colspan='5' style='padding: 16px; text-align: center; color: #64748b;'>No alerts attached.</td></tr>"}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Actionable SOC Recommendations</div>
            <div class="grid-2">
                <div class="card" style="border-left: 4px solid #38bdf8;">
                    <h4 style="margin: 0 0 8px 0; color: #38bdf8;">Investigation Procedures</h4>
                    <ul style="padding-left: 20px; margin: 0; font-size: 13px;">
                        {investigation_items or "<li>Conduct forensic endpoint capture.</li>"}
                    </ul>
                </div>
                <div class="card" style="border-left: 4px solid #ef4444;">
                    <h4 style="margin: 0 0 8px 0; color: #ef4444;">Containment & Mitigation Procedures</h4>
                    <ul style="padding-left: 20px; margin: 0; font-size: 13px;">
                        {containment_items or "<li>Isolate host and revoke credentials.</li>"}
                    </ul>
                </div>
            </div>
        </div>

        <div style="border-top: 1px solid #1f2937; padding-top: 16px; text-align: center; font-size: 11px; color: #64748b;">
            AI-SOC Security Architecture &bull; Monolithic Academic Prototype &bull; Pure Read-Only Analytical Execution
        </div>
    </div>
</body>
</html>
"""
    return report_html
