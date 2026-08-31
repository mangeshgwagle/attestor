#!/usr/bin/env python3
"""Interactive HTML attack dashboard -- self-contained security report.

Generates a single-file HTML dashboard from Attestor findings with:
- Severity breakdown (donut chart via inline SVG)
- Attack-path visualization (graph rendered as SVG)
- Click-to-expand evidence traces
- Finding detail cards with source/sink/trace
- Secret validation status
- Filter by severity, type, file
- Dark/light theme support

The output is a single .html file with all CSS/JS inlined -- no external
dependencies. Can be opened in any browser or published as an artifact.
"""
from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "MEDIUM").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _donut_svg(counts: dict[str, int]) -> str:
    total = sum(counts.values())
    if total == 0:
        return '<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg"><circle cx="100" cy="100" r="80" fill="none" stroke="#e5e7eb" stroke-width="20"/><text x="100" y="108" text-anchor="middle" font-size="28" fill="currentColor">0</text></svg>'
    segments = []
    offset = 0
    circumference = 2 * 3.14159 * 80
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        if c == 0:
            continue
        pct = c / total
        dash = pct * circumference
        gap = circumference - dash
        segments.append(
            f'<circle cx="100" cy="100" r="80" fill="none" '
            f'stroke="{_SEV_COLORS[sev]}" stroke-width="20" '
            f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" '
            f'transform="rotate(-90 100 100)"/>')
        offset += dash
    return (
        f'<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">'
        + "".join(segments)
        + f'<text x="100" y="108" text-anchor="middle" font-size="28" '
        f'fill="currentColor" font-weight="bold">{total}</text>'
        + '</svg>'
    )


def _finding_card(f: dict, idx: int) -> str:
    sev = (f.get("severity") or "MEDIUM").upper()
    vuln = f.get("sink_type") or f.get("category") or f.get("vulnerability") or "unknown"
    cwe = f.get("cwe") or ""
    sink_file = f.get("sink_file") or f.get("file") or f.get("path") or ""
    sink_line = f.get("sink_line") or f.get("line") or 0
    src_type = f.get("source_type") or ""
    sink_code = f.get("sink_code") or ""
    confidence = f.get("confidence") or "high"
    interproc = f.get("interprocedural", False)
    lang = f.get("language") or "python"
    trace = f.get("trace") or []

    badge_color = _SEV_COLORS.get(sev, "#6b7280")
    base_file = os.path.basename(sink_file) if sink_file else "?"
    interproc_badge = '<span class="badge badge-inter">cross-function</span>' if interproc else ''

    trace_html = ""
    if trace:
        steps = []
        for i, step in enumerate(trace):
            s_file = os.path.basename(step.get("file", "")) if step.get("file") else ""
            s_line = step.get("line", 0)
            s_note = _esc(step.get("note", ""))
            s_code = _esc(step.get("code", ""))
            arrow = "&#x2192;" if i > 0 else "&#x25B6;"
            steps.append(
                f'<div class="trace-step">'
                f'<span class="trace-arrow">{arrow}</span>'
                f'<span class="trace-loc">{_esc(s_file)}:{s_line}</span> '
                f'<span class="trace-note">{s_note}</span>'
                + (f'<div class="trace-code">{s_code}</div>' if s_code else '')
                + '</div>')
        trace_html = (
            f'<div class="trace-container" id="trace-{idx}" style="display:none;">'
            f'<div class="trace-header">Evidence Trace ({len(trace)} step{"s" if len(trace)!=1 else ""})</div>'
            + "".join(steps) + '</div>')

    trace_btn = (
        f'<button class="trace-toggle" onclick="toggleTrace({idx})">'
        f'Show trace ({len(trace)} steps)</button>'
    ) if trace else ''

    return f'''<div class="finding-card" data-severity="{sev}" data-type="{_esc(vuln)}" data-file="{_esc(sink_file)}">
  <div class="card-header">
    <span class="badge" style="background:{badge_color}">{sev}</span>
    <span class="vuln-type">{_esc(vuln)}</span>
    {f'<span class="cwe">{_esc(cwe)}</span>' if cwe else ''}
    {interproc_badge}
    <span class="lang-badge">{_esc(lang)}</span>
  </div>
  <div class="card-body">
    <div class="card-detail"><strong>File:</strong> {_esc(base_file)}:{sink_line}</div>
    {f'<div class="card-detail"><strong>Source:</strong> {_esc(src_type)}</div>' if src_type else ''}
    {f'<div class="card-detail"><strong>Code:</strong> <code>{_esc(sink_code)}</code></div>' if sink_code else ''}
    <div class="card-detail"><strong>Confidence:</strong> {_esc(confidence)}</div>
    {trace_btn}
    {trace_html}
  </div>
</div>'''


def _attack_path_svg(graph: dict | None) -> str:
    if not graph or not graph.get("paths"):
        return '<div class="empty-state">No exploit chains found</div>'
    paths = graph["paths"][:5]
    nodes_map = {n["id"]: n for n in graph.get("nodes", [])}

    svg_parts = []
    y_offset = 0
    for pi, path in enumerate(paths):
        node_ids = path.get("nodes", [])
        if not node_ids:
            continue
        x = 40
        node_positions = {}
        for ni, nid in enumerate(node_ids):
            node = nodes_map.get(nid, {})
            vuln = node.get("vuln_type", "?")
            sev = node.get("severity", "MEDIUM")
            color = _SEV_COLORS.get(sev, "#6b7280")
            cy = y_offset + 40
            rx, ry = 60, 22
            svg_parts.append(
                f'<ellipse cx="{x}" cy="{cy}" rx="{rx}" ry="{ry}" '
                f'fill="{color}22" stroke="{color}" stroke-width="2"/>')
            svg_parts.append(
                f'<text x="{x}" y="{cy+5}" text-anchor="middle" '
                f'font-size="11" fill="currentColor">{_esc(vuln)}</text>')
            node_positions[nid] = (x, cy)
            if ni > 0:
                prev_nid = node_ids[ni - 1]
                px, py = node_positions[prev_nid]
                svg_parts.append(
                    f'<line x1="{px+60}" y1="{py}" x2="{x-60}" y2="{cy}" '
                    f'stroke="currentColor" stroke-width="1.5" marker-end="url(#arrow)"/>')
            x += 180
        impact = _esc(path.get("impact", ""))
        score = path.get("score", 0)
        svg_parts.append(
            f'<text x="40" y="{y_offset+75}" font-size="11" fill="currentColor" '
            f'opacity="0.7">Score: {score:.1f} — {impact}</text>')
        y_offset += 100

    width = max(len(p.get("nodes", [])) for p in paths) * 180 + 40
    height = y_offset + 20
    return (
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:100%;max-width:{width}px;overflow:visible">'
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor"/></marker></defs>'
        + "".join(svg_parts)
        + '</svg>'
    )


def _secret_validation_section(validations: list[dict] | None) -> str:
    if not validations:
        return ""
    live = [v for v in validations if v.get("status") == "live"]
    dead = [v for v in validations if v.get("status") == "dead"]
    expired = [v for v in validations if v.get("status") == "expired"]
    rows = []
    for v in validations:
        status = v.get("status", "?")
        cls = {"live": "status-live", "dead": "status-dead",
               "expired": "status-expired"}.get(status, "status-other")
        rows.append(
            f'<tr>'
            f'<td><span class="status-dot {cls}"></span> {_esc(status)}</td>'
            f'<td>{_esc(v.get("service", "?"))}</td>'
            f'<td><code>{_esc(v.get("secret_redacted", ""))}</code></td>'
            f'<td>{_esc(v.get("detail", ""))}</td>'
            f'<td>{_esc(v.get("identity", ""))}</td>'
            f'</tr>')
    return f'''
    <section class="dashboard-section">
      <h2>Secret Validation</h2>
      <div class="stat-row">
        <div class="stat live-stat"><span class="stat-num">{len(live)}</span><span class="stat-label">Live</span></div>
        <div class="stat dead-stat"><span class="stat-num">{len(dead)}</span><span class="stat-label">Dead</span></div>
        <div class="stat expired-stat"><span class="stat-num">{len(expired)}</span><span class="stat-label">Expired</span></div>
      </div>
      <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Status</th><th>Service</th><th>Secret</th><th>Detail</th><th>Identity</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
      </div>
    </section>'''


def generate(findings: list[dict],
             attack_graph: dict | None = None,
             secret_validations: list[dict] | None = None,
             title: str = "Attestor Security Dashboard",
             target: str = "") -> str:
    counts = _severity_counts(findings)
    total = sum(counts.values())
    donut = _donut_svg(counts)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    sev_legend = "".join(
        f'<div class="legend-item">'
        f'<span class="legend-dot" style="background:{_SEV_COLORS[s]}"></span>'
        f'{s}: {counts[s]}</div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts.get(s, 0) > 0
    )

    vuln_types = sorted({(f.get("sink_type") or f.get("category") or "unknown")
                         for f in findings})
    type_options = "".join(f'<option value="{_esc(t)}">{_esc(t)}</option>' for t in vuln_types)

    finding_cards = "\n".join(_finding_card(f, i) for i, f in enumerate(
        sorted(findings, key=lambda x: _SEV_ORDER.get(
            (x.get("severity") or "MEDIUM").upper(), 9))))

    graph_section = ""
    if attack_graph and attack_graph.get("paths"):
        graph_svg = _attack_path_svg(attack_graph)
        stats = attack_graph.get("stats", {})
        graph_section = f'''
        <section class="dashboard-section">
          <h2>Attack Chains</h2>
          <p class="section-desc">{stats.get("total_paths", 0)} chain(s), max depth {stats.get("max_depth", 0)}</p>
          <div class="graph-container">{graph_svg}</div>
        </section>'''

    secrets_section = _secret_validation_section(secret_validations)

    inter_count = sum(1 for f in findings if f.get("interprocedural"))
    js_count = sum(1 for f in findings if f.get("language") == "javascript")
    py_count = total - js_count

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
:root {{
  --bg: #ffffff; --bg2: #f8fafc; --fg: #1e293b; --fg2: #475569;
  --border: #e2e8f0; --card-bg: #ffffff; --card-shadow: rgba(0,0,0,0.08);
  --code-bg: #f1f5f9; --hover: #f1f5f9;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg: #0f172a; --bg2: #1e293b; --fg: #e2e8f0; --fg2: #94a3b8;
    --border: #334155; --card-bg: #1e293b; --card-shadow: rgba(0,0,0,0.3);
    --code-bg: #334155; --hover: #334155;
  }}
}}
:root[data-theme="dark"] {{
  --bg: #0f172a; --bg2: #1e293b; --fg: #e2e8f0; --fg2: #94a3b8;
  --border: #334155; --card-bg: #1e293b; --card-shadow: rgba(0,0,0,0.3);
  --code-bg: #334155; --hover: #334155;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: var(--bg); color: var(--fg); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
header {{ padding: 24px 0; border-bottom: 2px solid var(--border); margin-bottom: 24px; }}
h1 {{ font-size: 1.8rem; font-weight: 700; }}
.subtitle {{ color: var(--fg2); font-size: 0.9rem; margin-top: 4px; }}
.overview {{ display: grid; grid-template-columns: 200px 1fr; gap: 24px; align-items: center;
             margin-bottom: 32px; }}
.donut-container {{ width: 160px; height: 160px; }}
.donut-container svg {{ width: 100%; height: 100%; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }}
.stat {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px;
         padding: 16px; text-align: center; }}
.stat-num {{ display: block; font-size: 1.8rem; font-weight: 700; }}
.stat-label {{ font-size: 0.8rem; color: var(--fg2); text-transform: uppercase; }}
.stat-num.critical {{ color: {_SEV_COLORS["CRITICAL"]}; }}
.stat-num.high {{ color: {_SEV_COLORS["HIGH"]}; }}
.stat-num.medium {{ color: {_SEV_COLORS["MEDIUM"]}; }}
.legend {{ display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px; }}
.legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 0.85rem; color: var(--fg2); }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
.dashboard-section {{ margin-bottom: 32px; }}
.dashboard-section h2 {{ font-size: 1.3rem; margin-bottom: 12px; padding-bottom: 8px;
                          border-bottom: 1px solid var(--border); }}
.section-desc {{ color: var(--fg2); font-size: 0.9rem; margin-bottom: 12px; }}
.filters {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }}
.filters select, .filters input {{ padding: 6px 12px; border: 1px solid var(--border);
  border-radius: 6px; background: var(--bg2); color: var(--fg); font-size: 0.85rem; }}
.finding-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px;
                 padding: 16px; margin-bottom: 12px; box-shadow: 0 1px 3px var(--card-shadow);
                 transition: box-shadow 0.15s; }}
.finding-card:hover {{ box-shadow: 0 4px 12px var(--card-shadow); }}
.card-header {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }}
.badge {{ padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600;
          color: #fff; text-transform: uppercase; }}
.badge-inter {{ background: #7c3aed; }}
.lang-badge {{ font-size: 0.7rem; color: var(--fg2); border: 1px solid var(--border);
               padding: 1px 6px; border-radius: 4px; }}
.vuln-type {{ font-weight: 600; }}
.cwe {{ color: var(--fg2); font-size: 0.85rem; }}
.card-detail {{ font-size: 0.85rem; margin: 4px 0; color: var(--fg2); }}
.card-detail code {{ background: var(--code-bg); padding: 2px 6px; border-radius: 4px;
                     font-size: 0.8rem; word-break: break-all; }}
.trace-toggle {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
                 padding: 4px 12px; font-size: 0.8rem; color: var(--fg); cursor: pointer;
                 margin-top: 8px; }}
.trace-toggle:hover {{ background: var(--hover); }}
.trace-container {{ margin-top: 12px; padding: 12px; background: var(--bg2); border-radius: 6px;
                    border: 1px solid var(--border); }}
.trace-header {{ font-weight: 600; margin-bottom: 8px; font-size: 0.85rem; }}
.trace-step {{ padding: 4px 0; font-size: 0.82rem; display: flex; align-items: flex-start; gap: 6px; }}
.trace-arrow {{ color: var(--fg2); flex-shrink: 0; }}
.trace-loc {{ font-weight: 600; color: var(--fg); white-space: nowrap; }}
.trace-note {{ color: var(--fg2); }}
.trace-code {{ background: var(--code-bg); padding: 2px 8px; border-radius: 4px; font-family: monospace;
               font-size: 0.78rem; margin-top: 2px; margin-left: 20px; word-break: break-all; }}
.graph-container {{ overflow-x: auto; padding: 16px; background: var(--bg2); border-radius: 8px;
                    border: 1px solid var(--border); }}
.stat-row {{ display: flex; gap: 12px; margin-bottom: 16px; }}
.live-stat .stat-num {{ color: {_SEV_COLORS["CRITICAL"]}; }}
.dead-stat .stat-num {{ color: #22c55e; }}
.expired-stat .stat-num {{ color: var(--fg2); }}
.status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }}
.status-live {{ background: {_SEV_COLORS["CRITICAL"]}; }}
.status-dead {{ background: #22c55e; }}
.status-expired {{ background: var(--fg2); }}
.status-other {{ background: var(--border); }}
.table-wrap {{ overflow-x: auto; }}
.data-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
.data-table th {{ text-align: left; padding: 8px 12px; border-bottom: 2px solid var(--border);
                  color: var(--fg2); font-weight: 600; }}
.data-table td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); }}
.data-table code {{ background: var(--code-bg); padding: 1px 4px; border-radius: 3px; font-size: 0.8rem; }}
.empty-state {{ text-align: center; padding: 40px; color: var(--fg2); font-size: 0.95rem; }}
.theme-toggle {{ position: fixed; top: 12px; right: 12px; background: var(--bg2); border: 1px solid var(--border);
                 border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 0.8rem; color: var(--fg); z-index: 10; }}
@media (max-width: 768px) {{
  .overview {{ grid-template-columns: 1fr; justify-items: center; }}
  .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
}}
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()">Toggle theme</button>
<div class="container">
  <header>
    <h1>{_esc(title)}</h1>
    <div class="subtitle">Generated {now}{f' | Target: {_esc(target)}' if target else ''} | Attestor v4.3</div>
  </header>

  <div class="overview">
    <div class="donut-container">{donut}</div>
    <div>
      <div class="stats-grid">
        <div class="stat"><span class="stat-num critical">{counts["CRITICAL"]}</span><span class="stat-label">Critical</span></div>
        <div class="stat"><span class="stat-num high">{counts["HIGH"]}</span><span class="stat-label">High</span></div>
        <div class="stat"><span class="stat-num medium">{counts["MEDIUM"]}</span><span class="stat-label">Medium</span></div>
        <div class="stat"><span class="stat-num">{total}</span><span class="stat-label">Total</span></div>
        <div class="stat"><span class="stat-num">{inter_count}</span><span class="stat-label">Cross-fn</span></div>
        <div class="stat"><span class="stat-num">{js_count}/{py_count}</span><span class="stat-label">JS / Py</span></div>
      </div>
      <div class="legend">{sev_legend}</div>
    </div>
  </div>

  {graph_section}

  {secrets_section}

  <section class="dashboard-section">
    <h2>Findings ({total})</h2>
    <div class="filters">
      <select id="sevFilter" onchange="filterFindings()">
        <option value="">All severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      <select id="typeFilter" onchange="filterFindings()">
        <option value="">All types</option>
        {type_options}
      </select>
      <input id="fileFilter" type="text" placeholder="Filter by file..." oninput="filterFindings()">
    </div>
    <div id="findings">
      {finding_cards if findings else '<div class="empty-state">No findings</div>'}
    </div>
  </section>
</div>
<script>
function toggleTrace(idx) {{
  var el = document.getElementById('trace-' + idx);
  if (!el) return;
  var btn = el.previousElementSibling;
  if (el.style.display === 'none') {{
    el.style.display = 'block';
    if (btn) btn.textContent = btn.textContent.replace('Show', 'Hide');
  }} else {{
    el.style.display = 'none';
    if (btn) btn.textContent = btn.textContent.replace('Hide', 'Show');
  }}
}}
function filterFindings() {{
  var sev = document.getElementById('sevFilter').value;
  var typ = document.getElementById('typeFilter').value;
  var file = document.getElementById('fileFilter').value.toLowerCase();
  document.querySelectorAll('.finding-card').forEach(function(card) {{
    var show = true;
    if (sev && card.dataset.severity !== sev) show = false;
    if (typ && card.dataset.type !== typ) show = false;
    if (file && !card.dataset.file.toLowerCase().includes(file)) show = false;
    card.style.display = show ? '' : 'none';
  }});
}}
function toggleTheme() {{
  var r = document.documentElement;
  var current = r.getAttribute('data-theme');
  r.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
}}
</script>
</body>
</html>'''


def generate_from_scan(paths: list[str], output: str = "attestor_dashboard.html",
                       title: str = "Attestor Security Dashboard",
                       target: str = "") -> str:
    findings = []
    try:
        import dataflow
        py_findings = dataflow.scan_paths(paths)
        findings += dataflow.to_dict(py_findings)
    except Exception:
        pass
    try:
        import dataflow_js
        js_findings = dataflow_js.scan_paths(paths)
        findings += dataflow_js.to_dict(js_findings)
    except Exception:
        pass

    graph_data = None
    try:
        import attack_graph
        graph = attack_graph.build_graph(findings)
        graph_data = graph.to_dict()
    except Exception:
        pass

    secret_data = None
    try:
        import secret_scanner
        import secret_validator
        for p in paths:
            if os.path.isdir(p):
                sec_findings = secret_scanner.scan_directory(p)
            elif os.path.isfile(p):
                sec_findings = secret_scanner.scan_file(p)
            else:
                continue
            if sec_findings:
                results = secret_validator.validate_findings(sec_findings, dry_run=True)
                secret_data = secret_validator.to_dict(results)
    except Exception:
        pass

    html_content = generate(findings, attack_graph=graph_data,
                            secret_validations=secret_data,
                            title=title, target=target)
    with open(output, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output


def to_json(findings: list[dict], attack_graph: dict | None = None,
            secret_validations: list[dict] | None = None) -> str:
    return json.dumps({
        "findings": findings,
        "attack_graph": attack_graph,
        "secret_validations": secret_validations,
        "generated": datetime.now().isoformat(),
    }, indent=2)
