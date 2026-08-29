#!/usr/bin/env python3
"""HTML report generator -- produces a self-contained visual security dashboard
with severity charts, finding details, and summary statistics."""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from typing import Any


def generate_html_report(
    findings: list[dict],
    project_name: str = "Project",
    root: str = ".",
    metadata: dict | None = None,
) -> str:
    meta = metadata or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        sev = f.get("severity", "MEDIUM").upper()
        if sev not in by_sev:
            sev = "MEDIUM"
        by_sev[sev].append(f)

    by_cat = {}
    for f in findings:
        cat = f.get("category", f.get("rule_id", "other").split("-")[0])
        by_cat.setdefault(cat, []).append(f)

    by_file = {}
    for f in findings:
        path = f.get("path", "unknown")
        by_file.setdefault(path, []).append(f)

    total = len(findings)
    crit = len(by_sev["CRITICAL"])
    high = len(by_sev["HIGH"])
    med = len(by_sev["MEDIUM"])
    low = len(by_sev["LOW"])

    if crit > 0:
        grade = "F"
        grade_color = "#e74c3c"
    elif high > 5:
        grade = "D"
        grade_color = "#e67e22"
    elif high > 0:
        grade = "C"
        grade_color = "#f39c12"
    elif med > 5:
        grade = "B"
        grade_color = "#27ae60"
    else:
        grade = "A"
        grade_color = "#2ecc71"

    findings_rows = ""
    for f in sorted(findings, key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "MEDIUM").upper(), 2),
        x.get("path", ""),
        x.get("line", 0),
    )):
        sev = f.get("severity", "MEDIUM").upper()
        sev_class = sev.lower()
        path = html.escape(f.get("path", ""))
        line = f.get("line", 0)
        rule_id = html.escape(f.get("rule_id", ""))
        desc = html.escape(f.get("description", f.get("message", "")))
        cwe = html.escape(f.get("cwe", ""))
        cat = html.escape(f.get("category", ""))
        remediation = html.escape(f.get("remediation", ""))
        mitre = html.escape(f.get("mitre_id", f.get("mitre", "")))

        extra = ""
        if cwe:
            extra += f'<span class="tag cwe">{cwe}</span>'
        if mitre:
            extra += f'<span class="tag mitre">{mitre}</span>'
        if cat:
            extra += f'<span class="tag cat">{cat}</span>'

        fix_html = f'<div class="fix">Fix: {remediation}</div>' if remediation else ""

        findings_rows += f"""
        <tr class="{sev_class}">
          <td><span class="severity {sev_class}">{sev}</span></td>
          <td class="path">{path}:{line}</td>
          <td>{rule_id}</td>
          <td>{desc}{fix_html}<div class="tags">{extra}</div></td>
        </tr>"""

    cat_rows = ""
    for cat, group in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        cat_crit = sum(1 for f in group if f.get("severity", "").upper() == "CRITICAL")
        cat_high = sum(1 for f in group if f.get("severity", "").upper() == "HIGH")
        bar_width = min(100, int(len(group) / max(total, 1) * 100))
        cat_rows += f"""
        <tr>
          <td>{html.escape(cat)}</td>
          <td>{len(group)}</td>
          <td>{cat_crit}</td>
          <td>{cat_high}</td>
          <td><div class="bar" style="width:{bar_width}%"></div></td>
        </tr>"""

    file_rows = ""
    top_files = sorted(by_file.items(), key=lambda x: -len(x[1]))[:15]
    for path, group in top_files:
        fcrit = sum(1 for f in group if f.get("severity", "").upper() == "CRITICAL")
        fhigh = sum(1 for f in group if f.get("severity", "").upper() == "HIGH")
        file_rows += f"""
        <tr>
          <td class="path">{html.escape(path)}</td>
          <td>{len(group)}</td>
          <td>{fcrit}</td>
          <td>{fhigh}</td>
        </tr>"""

    scan_info = ""
    if meta:
        for k, v in meta.items():
            scan_info += f"<div><strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}</div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attestor Security Report - {html.escape(project_name)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0d1117; color: #c9d1d9; line-height: 1.5; padding: 20px; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #58a6ff; margin-bottom: 5px; font-size: 1.8em; }}
h2 {{ color: #58a6ff; margin: 30px 0 15px; font-size: 1.3em; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
.subtitle {{ color: #8b949e; margin-bottom: 20px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
.card .number {{ font-size: 2.5em; font-weight: bold; }}
.card .label {{ color: #8b949e; font-size: 0.9em; }}
.grade {{ font-size: 4em; font-weight: bold; }}
.critical .number {{ color: #f85149; }}
.high .number {{ color: #d29922; }}
.medium .number {{ color: #58a6ff; }}
.low .number {{ color: #8b949e; }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th {{ background: #161b22; color: #58a6ff; text-align: left; padding: 10px; font-weight: 600; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }}
tr:hover {{ background: #161b22; }}
.severity {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
.severity.critical {{ background: #f8514922; color: #f85149; }}
.severity.high {{ background: #d2992222; color: #d29922; }}
.severity.medium {{ background: #58a6ff22; color: #58a6ff; }}
.severity.low {{ background: #8b949e22; color: #8b949e; }}
tr.critical {{ border-left: 3px solid #f85149; }}
tr.high {{ border-left: 3px solid #d29922; }}
tr.medium {{ border-left: 3px solid #58a6ff; }}
tr.low {{ border-left: 3px solid #8b949e; }}
.path {{ font-family: monospace; font-size: 0.85em; color: #79c0ff; word-break: break-all; }}
.tag {{ display: inline-block; padding: 1px 6px; margin: 2px; border-radius: 3px; font-size: 0.75em; }}
.tag.cwe {{ background: #da3633; color: #fff; }}
.tag.mitre {{ background: #8957e5; color: #fff; }}
.tag.cat {{ background: #238636; color: #fff; }}
.tags {{ margin-top: 4px; }}
.fix {{ color: #3fb950; font-size: 0.85em; margin-top: 4px; }}
.bar {{ background: #58a6ff; height: 18px; border-radius: 3px; min-width: 2px; }}
.chart {{ display: flex; align-items: end; gap: 4px; height: 120px; margin: 15px 0; }}
.chart-bar {{ flex: 1; border-radius: 3px 3px 0 0; position: relative; min-width: 40px; }}
.chart-bar .val {{ position: absolute; top: -20px; width: 100%; text-align: center; font-size: 0.8em; }}
.chart-bar .lbl {{ position: absolute; bottom: -20px; width: 100%; text-align: center; font-size: 0.75em; color: #8b949e; }}
.scan-info {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; margin: 15px 0; font-size: 0.9em; }}
.scan-info div {{ margin: 3px 0; }}
footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.85em; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>Attestor Security Report</h1>
  <div class="subtitle">{html.escape(project_name)} &mdash; {now}</div>

  <div class="cards">
    <div class="card">
      <div class="grade" style="color:{grade_color}">{grade}</div>
      <div class="label">Security Grade</div>
    </div>
    <div class="card">
      <div class="number" style="color:#c9d1d9">{total}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card critical">
      <div class="number">{crit}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card high">
      <div class="number">{high}</div>
      <div class="label">High</div>
    </div>
    <div class="card medium">
      <div class="number">{med}</div>
      <div class="label">Medium</div>
    </div>
    <div class="card low">
      <div class="number">{low}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <h2>Severity Distribution</h2>
  <div class="chart">
    <div class="chart-bar" style="height:{max(5, int(crit/max(total,1)*100))}%;background:#f85149">
      <span class="val">{crit}</span><span class="lbl">Critical</span>
    </div>
    <div class="chart-bar" style="height:{max(5, int(high/max(total,1)*100))}%;background:#d29922">
      <span class="val">{high}</span><span class="lbl">High</span>
    </div>
    <div class="chart-bar" style="height:{max(5, int(med/max(total,1)*100))}%;background:#58a6ff">
      <span class="val">{med}</span><span class="lbl">Medium</span>
    </div>
    <div class="chart-bar" style="height:{max(5, int(low/max(total,1)*100))}%;background:#8b949e">
      <span class="val">{low}</span><span class="lbl">Low</span>
    </div>
  </div>

  {"<h2>Scan Information</h2><div class='scan-info'>" + scan_info + "</div>" if scan_info else ""}

  <h2>Findings by Category</h2>
  <table>
    <tr><th>Category</th><th>Count</th><th>Critical</th><th>High</th><th>Distribution</th></tr>
    {cat_rows}
  </table>

  <h2>Top Files by Findings</h2>
  <table>
    <tr><th>File</th><th>Count</th><th>Critical</th><th>High</th></tr>
    {file_rows}
  </table>

  <h2>All Findings ({total})</h2>
  <table>
    <tr><th>Severity</th><th>Location</th><th>Rule</th><th>Description</th></tr>
    {findings_rows}
  </table>

  <footer>
    Generated by Attestor 4.2 &mdash; {now}<br>
    {len(by_file)} files scanned &bull; {total} findings &bull; {len(by_cat)} categories
  </footer>
</div>
</body>
</html>"""


def write_report(
    findings: list[dict],
    output_path: str,
    project_name: str = "Project",
    root: str = ".",
    metadata: dict | None = None,
):
    report_html = generate_html_report(findings, project_name, root, metadata)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)
