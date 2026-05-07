"""Export API: JSON, CSV, HTML report."""
import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.db_models import Finding, Node, RoleAssignment, Scan

router = APIRouter(prefix="/api/export", tags=["export"])


@router.get("/{scan_id}/json")
def export_json(scan_id: str, db: Session = Depends(get_db)):
    scan, findings, nodes, ras = _load_scan_data(scan_id, db)

    payload = {
        "az_map_version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
        "scan": {
            "id": scan.id,
            "subscription_id": scan.subscription_id,
            "subscription_name": scan.subscription_name,
            "tenant_id": scan.tenant_id,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "summary": {
            "total_nodes": len(nodes),
            "total_findings": len(findings),
            "critical_findings": sum(1 for f in findings if f.severity == "critical"),
            "high_findings": sum(1 for f in findings if f.severity == "high"),
        },
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "affected_node": f.affected_node_name,
                "risk_score": f.risk_score,
                "blast_radius": f.blast_radius,
                "why_risky": f.why_risky,
                "remediation": f.remediation,
                "attack_chain": f.attack_chain,
                "tags": f.tags,
            }
            for f in sorted(findings, key=lambda x: x.risk_score, reverse=True)
        ],
        "inventory": [
            {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "name": n.name,
                "display_name": n.display_name,
                "risk_level": n.risk_level,
                "risk_score": n.risk_score,
            }
            for n in nodes
        ],
        "role_assignments": [
            {
                "principal_id": ra.principal_id,
                "principal_name": ra.principal_name,
                "principal_type": ra.principal_type,
                "role_name": ra.role_name,
                "scope": ra.scope,
                "scope_level": ra.scope_level,
            }
            for ra in ras
        ],
    }
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="azmap_{scan_id[:8]}.json"'},
    )


@router.get("/{scan_id}/csv")
def export_csv(scan_id: str, db: Session = Depends(get_db)):
    scan, findings, _, _ = _load_scan_data(scan_id, db)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "severity", "risk_score", "blast_radius", "finding_type",
        "title", "affected_node", "why_risky", "remediation", "tags"
    ])
    writer.writeheader()
    for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
        writer.writerow({
            "severity": f.severity,
            "risk_score": f.risk_score,
            "blast_radius": f.blast_radius,
            "finding_type": f.finding_type,
            "title": f.title,
            "affected_node": f.affected_node_name or "",
            "why_risky": f.why_risky or "",
            "remediation": (f.remediation or "").replace("\n", " "),
            "tags": ", ".join(f.tags or []),
        })

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="azmap_findings_{scan_id[:8]}.csv"'},
    )


@router.get("/{scan_id}/html")
def export_html(scan_id: str, db: Session = Depends(get_db)):
    scan, findings, nodes, ras = _load_scan_data(scan_id, db)

    sev_colors = {"critical": "#F44336", "high": "#FF9800", "medium": "#FFC107",
                  "low": "#4CAF50", "info": "#9E9E9E", "safe": "#4CAF50", "risky": "#FF9800"}

    sev_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    node_type_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        type_counts[f.finding_type] = type_counts.get(f.finding_type, 0) + 1
    for n in nodes:
        node_type_counts[n.node_type] = node_type_counts.get(n.node_type, 0) + 1

    total_findings = len(findings)
    total_nodes = len(nodes)

    # Executive summary table
    exec_rows = "".join(
        f"<tr><td>{label}</td><td><strong>{val}</strong></td></tr>"
        for label, val in [
            ("Subscription", _esc(scan.subscription_name or scan.subscription_id)),
            ("Tenant ID", _esc(scan.tenant_id or "N/A")),
            ("Scan Date", scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "In Progress"),
            ("Total Resources", total_nodes),
            ("Total Findings", total_findings),
            ("Critical / High", f"{sev_counts.get('critical',0)} / {sev_counts.get('high',0)}"),
            ("Role Assignments", len(ras)),
        ]
    )

    # Findings by type table
    type_rows = "".join(
        f"<tr><td>{ft.replace('_',' ').title()}</td><td>{cnt}</td></tr>"
        for ft, cnt in sorted(type_counts.items(), key=lambda x: -x[1])
    )

    # Resource breakdown table
    resource_rows = "".join(
        f"<tr><td>{nt.replace('_',' ').title()}</td><td>{cnt}</td></tr>"
        for nt, cnt in sorted(node_type_counts.items(), key=lambda x: -x[1])
    )

    # Findings section
    findings_html = ""
    for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
        color = sev_colors.get(f.severity, "#9E9E9E")
        chain_html = "".join(
            f'<li style="margin:4px 0;">Step {s.get("step","")}: {_esc(s.get("action",""))}</li>'
            for s in (f.attack_chain or [])
        )
        tags_html = "".join(
            f'<span style="display:inline-block;background:#f0f0f0;border-radius:3px;'
            f'padding:1px 6px;font-size:11px;margin:2px 2px 0 0;">{_esc(t)}</span>'
            for t in (f.tags or [])
        )
        findings_html += f"""
<div class="finding" style="border-left:4px solid {color}; margin:16px 0; padding:16px 20px; background:#fafafa; border-radius:6px; page-break-inside:avoid;">
  <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
    <h3 style="margin:0; font-size:15px; font-weight:600; word-break:break-word; flex:1;">{_esc(f.title)}</h3>
    <div style="flex-shrink:0;">
      <span style="background:{color};color:#fff;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;">{f.severity.upper()}</span>
    </div>
  </div>
  <p style="color:#555; margin:8px 0 4px; font-size:13px;">{_esc(f.description or '')}</p>
  <p style="font-size:12px; color:#777; margin:4px 0;">
    <strong>Risk Score:</strong> {f.risk_score}/10 &nbsp;·&nbsp;
    <strong>Blast Radius:</strong> {f.blast_radius} &nbsp;·&nbsp;
    <strong>Type:</strong> {f.finding_type.replace('_',' ')}
    {f"&nbsp;·&nbsp;<strong>Affected:</strong> {_esc(f.affected_node_name)}" if f.affected_node_name else ""}
  </p>
  {"<div style='margin:10px 0; padding:8px 12px; background:#FFF8E1; border-radius:4px; font-size:12px;'><strong>⚠ Why Risky:</strong> " + _esc(f.why_risky) + "</div>" if f.why_risky else ""}
  {"<div style='margin:8px 0;'><strong style='font-size:12px;'>Attack Chain:</strong><ol style='margin:6px 0 0;padding-left:20px;font-size:12px;color:#444;'>" + chain_html + "</ol></div>" if chain_html else ""}
  {"<div style='margin:8px 0; padding:8px 12px; background:#F1F8E9; border-radius:4px; font-size:12px;'><strong>✓ Remediation:</strong> " + _esc(f.remediation) + "</div>" if f.remediation else ""}
  {"<div style='margin-top:8px;'>" + tags_html + "</div>" if tags_html else ""}
</div>"""

    # Inventory (top 100 by risk)
    inventory_rows = "".join(
        f'<tr>'
        f'<td style="word-break:break-all;">{_esc(n.display_name or n.name)}</td>'
        f'<td>{n.node_type.replace("_"," ")}</td>'
        f'<td style="color:{sev_colors.get(n.risk_level,"#9E9E9E")};font-weight:600;">{n.risk_level}</td>'
        f'<td>{n.risk_score}</td>'
        f'<td style="font-size:11px;color:#888;">{"; ".join((n.risk_reasons or [])[:2])}</td>'
        f'</tr>'
        for n in sorted(nodes, key=lambda x: x.risk_score, reverse=True)[:100]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>az-map Report — {_esc(scan.subscription_name or scan.subscription_id)}</title>
<style>
  *{{box-sizing:border-box;}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:32px 40px;color:#1a1a1a;background:#fff;max-width:1100px;}}
  h1{{font-size:26px;font-weight:700;margin-bottom:4px;}}
  h2{{font-size:18px;font-weight:600;border-bottom:2px solid #eee;padding-bottom:8px;margin:40px 0 16px;}}
  h3{{font-size:15px;font-weight:600;}}
  .meta{{color:#666;font-size:13px;margin-bottom:24px;}}
  .badges{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0 24px;}}
  .badge{{padding:14px 20px;border-radius:8px;text-align:center;min-width:110px;}}
  .badge .num{{font-size:32px;font-weight:700;line-height:1;}}
  .badge .lbl{{font-size:11px;color:#777;text-transform:uppercase;letter-spacing:.8px;margin-top:4px;}}
  table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:24px;}}
  th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid #eee;vertical-align:top;}}
  th{{font-weight:600;background:#f8f8f8;white-space:nowrap;}}
  tr:hover td{{background:#fafafa;}}
  .two-col{{display:grid;grid-template-columns:1fr 1fr;gap:24px;}}
  @media print{{.two-col{{grid-template-columns:1fr;}}}}
  @media(max-width:700px){{.two-col{{grid-template-columns:1fr;}}.badges{{flex-wrap:wrap;}}}}
</style>
</head>
<body>
<h1>az-map Security Report</h1>
<div class="meta">Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp; az-map v1.0</div>

<h2>Executive Summary</h2>
<div class="badges">
  <div class="badge" style="background:#FFEBEE;"><div class="num" style="color:#F44336;">{sev_counts.get('critical',0)}</div><div class="lbl">Critical</div></div>
  <div class="badge" style="background:#FFF3E0;"><div class="num" style="color:#FF9800;">{sev_counts.get('high',0)}</div><div class="lbl">High</div></div>
  <div class="badge" style="background:#FFFDE7;"><div class="num" style="color:#FFC107;">{sev_counts.get('medium',0)}</div><div class="lbl">Medium</div></div>
  <div class="badge" style="background:#E8F5E9;"><div class="num" style="color:#4CAF50;">{sev_counts.get('low',0)}</div><div class="lbl">Low</div></div>
  <div class="badge" style="background:#EDE7F6;"><div class="num" style="color:#7B68EE;">{total_nodes}</div><div class="lbl">Resources</div></div>
  <div class="badge" style="background:#F3F4F6;"><div class="num" style="color:#374151;">{len(ras)}</div><div class="lbl">Role Assigns</div></div>
</div>

<div class="two-col">
  <div>
    <h2 style="margin-top:0;">Scan Details</h2>
    <table><tbody>{exec_rows}</tbody></table>
  </div>
  <div>
    <h2 style="margin-top:0;">Findings by Type</h2>
    <table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{type_rows or "<tr><td colspan='2'>No findings</td></tr>"}</tbody></table>
  </div>
</div>

<h2>Findings ({total_findings})</h2>
{findings_html or "<p style='color:#999;'>No findings detected.</p>"}

<h2>Resource Inventory ({total_nodes})</h2>
<div class="two-col" style="margin-bottom:24px;">
  <div>
    <strong style="font-size:13px;">By Type</strong>
    <table style="margin-top:8px;"><thead><tr><th>Type</th><th>Count</th></tr></thead>
    <tbody>{resource_rows}</tbody></table>
  </div>
</div>
<table>
<thead><tr><th>Name</th><th>Type</th><th>Risk</th><th>Score</th><th>Reasons</th></tr></thead>
<tbody>{inventory_rows or "<tr><td colspan='5'>No resources</td></tr>"}</tbody>
</table>

<p style="margin-top:48px;color:#bbb;font-size:11px;border-top:1px solid #eee;padding-top:16px;">
  Generated by az-map — Azure Security Analysis Tool &nbsp;|&nbsp;
  Subscription: {_esc(scan.subscription_name or scan.subscription_id)} &nbsp;|&nbsp;
  {scan.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan.completed_at else 'In Progress'}
</p>
</body>
</html>"""
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="azmap_report_{scan_id[:8]}.html"'},
    )


@router.get("/{scan_id}/paths")
def export_paths(scan_id: str, db: Session = Depends(get_db)):
    """Export all detected attack paths as structured JSON."""
    from ..graph.builder import build_graph
    from ..analyzers.attack_paths import AttackPathAnalyzer

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    G = build_graph(scan_id, db)
    analyzer = AttackPathAnalyzer(G)

    # Collect owner-equivalent node IDs
    owner_nodes = [
        nid for nid, data in G.nodes(data=True)
        if data.get("node_type") == "role_definition"
        and any(kw in data.get("name", "").lower() for kw in ("owner", "user access admin", "rbac admin"))
    ]

    escalation_paths = analyzer.find_all_escalation_paths(owner_nodes)

    # Also find lateral movement from all critical nodes
    critical_nodes = [
        nid for nid, data in G.nodes(data=True)
        if data.get("risk_level") == "critical"
    ]
    lateral_paths = []
    for nid in critical_nodes[:20]:  # cap to avoid huge payloads
        paths = analyzer.find_lateral_movement(nid, max_depth=3)
        lateral_paths.extend(paths[:5])

    payload = {
        "az_map_version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
        "scan_id": scan_id,
        "subscription": scan.subscription_name or scan.subscription_id,
        "escalation_paths": escalation_paths[:100],
        "lateral_movement_paths": lateral_paths[:100],
        "summary": {
            "total_escalation_paths": len(escalation_paths),
            "total_lateral_paths": len(lateral_paths),
        },
    }
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="azmap_paths_{scan_id[:8]}.json"'},
    )


def _load_scan_data(scan_id: str, db: Session):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    nodes = db.query(Node).filter(Node.scan_id == scan_id).all()
    ras = db.query(RoleAssignment).filter(RoleAssignment.scan_id == scan_id).all()
    return scan, findings, nodes, ras


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
