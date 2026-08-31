#!/usr/bin/env python3
"""Interactive attack graph visualization.

Consumes kill chain output and produces a self-contained HTML file with a
Canvas-rendered node-edge attack graph. MITRE ATT&CK phase lanes, severity
coloring, hover details, click-to-focus, chain highlighting.

    html = render_html(chains_dicts)
    write_html(chains_dicts, "attack-graph.html")
"""
from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


_PHASE_ORDER = [
    "reconnaissance", "initial_access", "execution", "persistence",
    "privilege_escalation", "credential_access", "lateral_movement",
    "collection", "exfiltration", "impact",
]

_PHASE_LABELS = {
    "reconnaissance": "Recon",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Priv Esc",
    "credential_access": "Cred Access",
    "lateral_movement": "Lateral Move",
    "collection": "Collection",
    "exfiltration": "Exfil",
    "impact": "Impact",
}


def _build_graph_data(chains_dicts: list[dict]) -> dict:
    nodes = []
    edges = []
    node_id_map = {}
    nid = 0

    for ci, chain in enumerate(chains_dicts):
        prev_id = None
        for step in chain.get("steps", []):
            key = (step.get("file", ""), step.get("line", 0),
                   step.get("technique", ""), step.get("phase", ""))
            if key in node_id_map:
                cur_id = node_id_map[key]
                for n in nodes:
                    if n["id"] == cur_id and ci not in n["chains"]:
                        n["chains"].append(ci)
            else:
                cur_id = nid
                node_id_map[key] = nid
                nodes.append({
                    "id": nid,
                    "technique": step.get("technique", "?"),
                    "phase": step.get("phase", "initial_access"),
                    "severity": step.get("severity", "MEDIUM"),
                    "cwe": step.get("cwe", ""),
                    "file": os.path.basename(step.get("file", "")),
                    "line": step.get("line", 0),
                    "description": step.get("description", ""),
                    "provides": step.get("provides", []),
                    "preconditions": step.get("preconditions", []),
                    "chains": [ci],
                })
                nid += 1

            if prev_id is not None and prev_id != cur_id:
                edge_provides = []
                for n in nodes:
                    if n["id"] == prev_id:
                        edge_provides = n.get("provides", [])
                        break
                edges.append({
                    "from": prev_id,
                    "to": cur_id,
                    "chain": ci,
                    "capability": ", ".join(edge_provides[:2]) if edge_provides else "",
                })
            prev_id = cur_id

    chain_meta = []
    for ci, chain in enumerate(chains_dicts):
        chain_meta.append({
            "index": ci,
            "name": chain.get("name", f"Chain {ci+1}"),
            "severity": chain.get("severity", "MEDIUM"),
            "impact": chain.get("impact", ""),
            "length": chain.get("length", 0),
            "mitre_tactics": chain.get("mitre_tactics", []),
        })

    return {"nodes": nodes, "edges": edges, "chains": chain_meta}


def render_html(chains_dicts: list[dict]) -> str:
    graph = _build_graph_data(chains_dicts)
    data_json = json.dumps(graph, indent=None, ensure_ascii=True)
    return _HTML_TEMPLATE.replace("%%DATA%%", data_json)


def write_html(chains_dicts: list[dict], path: str) -> str:
    content = render_html(chains_dicts)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return os.path.abspath(path)


def generate(paths: list[str], output: str = "attack-graph.html") -> str:
    import killchain
    chains_obj = killchain.synthesize_from_engines(paths)
    chains_dicts = killchain.to_dict(chains_obj)
    return write_html(chains_dicts, output)


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attestor Attack Graph</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
--bg:#0b1120;--surface:#111b2e;--surface2:#162033;
--text:#dfe6f0;--text2:#6b7a90;--text3:#3d4d63;
--accent:#22d3a7;--red:#ef4444;--amber:#f59e0b;--blue:#3b82f6;
--border:rgba(255,255,255,0.06);
--crit:#ef4444;--high:#f97316;--med:#f59e0b;--low:#22d3a7;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;overflow:hidden;height:100vh}
#app{display:grid;grid-template-columns:1fr 300px;grid-template-rows:auto 1fr;height:100vh}
.topbar{grid-column:1/-1;background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px}
.topbar h1{font-size:15px;font-weight:700;letter-spacing:-0.01em}
.topbar .accent{color:var(--accent)}
.topbar .stats{font-size:12px;color:var(--text2);margin-left:auto;display:flex;gap:16px}
.topbar .stat-val{color:var(--accent);font-weight:700}
canvas{display:block;cursor:grab;background:var(--bg)}
canvas:active{cursor:grabbing}
.sidebar{background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:16px}
.sidebar h2{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--accent);margin-bottom:12px}
.chain-card{background:var(--surface2);border:1px solid var(--border);padding:12px;margin-bottom:8px;cursor:pointer;transition:border-color 0.15s}
.chain-card:hover,.chain-card.active{border-color:var(--accent)}
.chain-card .name{font-size:13px;font-weight:600;margin-bottom:4px}
.chain-card .meta{font-size:11px;color:var(--text2)}
.sev{display:inline-block;padding:1px 6px;font-size:10px;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;border-radius:2px;margin-right:4px}
.sev-CRITICAL{background:rgba(239,68,68,0.15);color:var(--crit)}
.sev-HIGH{background:rgba(249,115,22,0.15);color:var(--high)}
.sev-MEDIUM{background:rgba(245,158,11,0.15);color:var(--med)}
.sev-LOW{background:rgba(34,211,167,0.1);color:var(--low)}
.detail{margin-top:16px}
.detail h2{margin-bottom:8px}
.detail-body{font-size:12px;color:var(--text2);line-height:1.6}
.detail-body .label{color:var(--text3);text-transform:uppercase;font-size:10px;letter-spacing:0.06em;font-weight:700;display:block;margin-top:8px}
.detail-body .value{color:var(--text)}
.cap-chip{display:inline-block;font-size:10px;padding:2px 6px;background:rgba(34,211,167,0.1);color:var(--accent);border:1px solid rgba(34,211,167,0.2);margin:2px 2px 0 0}
.legend{margin-top:20px;padding-top:12px;border-top:1px solid var(--border)}
.legend h2{margin-bottom:8px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--text2);margin-bottom:4px}
.legend-dot{width:10px;height:10px;border-radius:50%}
.controls{font-size:11px;color:var(--text3);margin-top:16px;line-height:1.7}
.empty{grid-column:1/-1;display:flex;align-items:center;justify-content:center;font-size:16px;color:var(--text3);padding:60px}
@media(max-width:700px){
#app{grid-template-columns:1fr;grid-template-rows:auto 1fr auto}
.sidebar{max-height:40vh;border-left:none;border-top:1px solid var(--border)}
}
</style>
</head>
<body>
<div id="app">
<div class="topbar">
<h1>Attestor<span class="accent">.</span> Attack Graph</h1>
<div class="stats">
<span><span class="stat-val" id="s-nodes">0</span> nodes</span>
<span><span class="stat-val" id="s-edges">0</span> edges</span>
<span><span class="stat-val" id="s-chains">0</span> chains</span>
</div>
</div>
<canvas id="c"></canvas>
<div class="sidebar">
<h2>Kill Chains</h2>
<div id="chain-list"></div>
<div class="detail" id="detail" style="display:none">
<h2>Node Detail</h2>
<div class="detail-body" id="detail-body"></div>
</div>
<div class="legend">
<h2>MITRE ATT&CK Phases</h2>
<div id="legend-items"></div>
</div>
<div class="controls">
Scroll to zoom. Drag to pan.<br>
Click a node for details.<br>
Click a chain to highlight.
</div>
</div>
</div>
<script>
var DATA = %%DATA%%;

var PHASE_COLORS = {
reconnaissance:"#64748b",initial_access:"#ef4444",execution:"#f97316",
persistence:"#f59e0b",privilege_escalation:"#eab308",credential_access:"#a855f7",
lateral_movement:"#6366f1",collection:"#3b82f6",exfiltration:"#0ea5e9",impact:"#dc2626"
};
var PHASE_ORDER = ["reconnaissance","initial_access","execution","persistence",
"privilege_escalation","credential_access","lateral_movement","collection",
"exfiltration","impact"];
var PHASE_LABELS = {
reconnaissance:"Recon",initial_access:"Initial Access",execution:"Execution",
persistence:"Persistence",privilege_escalation:"Priv Esc",
credential_access:"Cred Access",lateral_movement:"Lateral Move",
collection:"Collection",exfiltration:"Exfil",impact:"Impact"
};
var SEV_COLORS = {CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#f59e0b",LOW:"#22d3a7"};

var canvas = document.getElementById("c");
var ctx = canvas.getContext("2d");
var W, H;
var cam = {x:0, y:0, zoom:1};
var nodes = DATA.nodes;
var edges = DATA.edges;
var chains = DATA.chains;
var activeChain = -1;
var activeNode = -1;
var dragging = false;
var dragStart = {x:0, y:0, cx:0, cy:0};
var hoveredNode = -1;
var didDrag = false;

if (!nodes.length) {
  document.querySelector("canvas").style.display = "none";
  var emp = document.createElement("div");
  emp.className = "empty";
  emp.textContent = "No attack chains to visualize.";
  document.getElementById("app").insertBefore(emp, document.querySelector(".sidebar"));
}

function layout() {
  var phases = {};
  nodes.forEach(function(n) {
    if (!phases[n.phase]) phases[n.phase] = [];
    phases[n.phase].push(n);
  });

  var usedPhases = PHASE_ORDER.filter(function(p) { return phases[p]; });
  var laneW = Math.max(180, (W - 100) / Math.max(usedPhases.length, 1));

  usedPhases.forEach(function(phase, pi) {
    var group = phases[phase];
    var cx = 80 + pi * laneW + laneW / 2;
    group.forEach(function(n, ni) {
      n.x = cx;
      n.y = 120 + ni * 110;
      n.r = n.severity === "CRITICAL" ? 30 : n.severity === "HIGH" ? 26 : 22;
    });
  });

  cam.x = 40;
  cam.y = 20;
  var totalW = usedPhases.length * laneW + 160;
  cam.zoom = Math.min(1.2, W / totalW);
}

function resize() {
  var app = document.getElementById("app");
  var tb = document.querySelector(".topbar");
  var rect = canvas.getBoundingClientRect();
  W = canvas.width = rect.width;
  H = canvas.height = rect.height;
}

function toScreen(x, y) {
  return [(x + cam.x) * cam.zoom, (y + cam.y) * cam.zoom];
}

function toWorld(sx, sy) {
  return [sx / cam.zoom - cam.x, sy / cam.zoom - cam.y];
}

function drawPhaseLanes() {
  var phases = {};
  nodes.forEach(function(n) { if (!phases[n.phase]) phases[n.phase] = []; phases[n.phase].push(n); });
  var usedPhases = PHASE_ORDER.filter(function(p) { return phases[p]; });
  if (!usedPhases.length) return;

  var laneW = Math.max(180, (W / cam.zoom) / Math.max(usedPhases.length, 1));

  usedPhases.forEach(function(phase, pi) {
    var lx = 80 + pi * laneW;
    var s = toScreen(lx, 0);
    var s2 = toScreen(lx + laneW, 0);
    var sw = s2[0] - s[0];

    ctx.fillStyle = pi % 2 === 0 ? "rgba(255,255,255,0.015)" : "rgba(255,255,255,0.008)";
    ctx.fillRect(s[0], 0, sw, H);

    ctx.save();
    ctx.fillStyle = PHASE_COLORS[phase] || "#666";
    ctx.globalAlpha = 0.5;
    ctx.font = "bold " + Math.max(9, 11 * cam.zoom) + "px system-ui";
    ctx.textAlign = "center";
    var labelY = toScreen(0, 50);
    ctx.fillText((PHASE_LABELS[phase] || phase).toUpperCase(), s[0] + sw / 2, labelY[1]);
    ctx.restore();
  });
}

function drawEdge(e, highlight) {
  var from = nodes[e.from];
  var to = nodes[e.to];
  if (!from || !to) return;

  var p1 = toScreen(from.x, from.y);
  var p2 = toScreen(to.x, to.y);

  ctx.beginPath();
  var cpx = p1[0] + (p2[0] - p1[0]) * 0.5;
  ctx.moveTo(p1[0], p1[1]);
  ctx.bezierCurveTo(cpx, p1[1], cpx, p2[1], p2[0], p2[1]);

  ctx.save();
  if (highlight) {
    ctx.strokeStyle = "#22d3a7";
    ctx.lineWidth = 2.5 * cam.zoom;
    ctx.globalAlpha = 0.9;
  } else {
    ctx.strokeStyle = "rgba(255,255,255,0.1)";
    ctx.lineWidth = 1.5 * cam.zoom;
    ctx.globalAlpha = 0.3;
  }
  ctx.stroke();
  ctx.restore();

  var angle = Math.atan2(p2[1] - p1[1], p2[0] - cpx);
  var aLen = 8 * cam.zoom;
  ctx.beginPath();
  ctx.moveTo(p2[0], p2[1]);
  ctx.lineTo(p2[0] - aLen * Math.cos(angle - 0.35), p2[1] - aLen * Math.sin(angle - 0.35));
  ctx.lineTo(p2[0] - aLen * Math.cos(angle + 0.35), p2[1] - aLen * Math.sin(angle + 0.35));
  ctx.closePath();
  ctx.fillStyle = highlight ? "#22d3a7" : "rgba(255,255,255,0.15)";
  ctx.fill();

  if (highlight && e.capability) {
    var mx = (p1[0] + p2[0]) / 2;
    var my = (p1[1] + p2[1]) / 2 - 10 * cam.zoom;
    ctx.save();
    ctx.font = Math.max(8, 9 * cam.zoom) + "px system-ui";
    ctx.fillStyle = "rgba(34,211,167,0.6)";
    ctx.textAlign = "center";
    ctx.fillText(e.capability, mx, my);
    ctx.restore();
  }
}

function drawNode(n, highlight, hovered) {
  var p = toScreen(n.x, n.y);
  var r = n.r * cam.zoom;
  var sevColor = SEV_COLORS[n.severity] || "#666";
  var phaseColor = PHASE_COLORS[n.phase] || "#666";

  if (highlight || hovered) {
    ctx.beginPath();
    ctx.arc(p[0], p[1], r + 6 * cam.zoom, 0, Math.PI * 2);
    ctx.fillStyle = highlight ? "rgba(34,211,167,0.12)" : "rgba(255,255,255,0.04)";
    ctx.fill();
  }

  ctx.beginPath();
  ctx.arc(p[0], p[1], r, 0, Math.PI * 2);
  var grad = ctx.createRadialGradient(p[0] - r * 0.3, p[1] - r * 0.3, r * 0.1, p[0], p[1], r);
  grad.addColorStop(0, phaseColor);
  grad.addColorStop(1, phaseColor + "66");
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.lineWidth = highlight ? 2.5 * cam.zoom : 1.5 * cam.zoom;
  ctx.strokeStyle = highlight ? "#22d3a7" : sevColor;
  ctx.stroke();

  ctx.fillStyle = "#fff";
  ctx.font = "bold " + Math.max(9, 10 * cam.zoom) + "px system-ui";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  var label = n.technique.length > 16 ? n.technique.slice(0, 14) + ".." : n.technique;
  ctx.fillText(label, p[0], p[1]);

  ctx.font = Math.max(8, 9 * cam.zoom) + "px system-ui";
  ctx.fillStyle = "rgba(255,255,255,0.4)";
  ctx.fillText(n.file ? n.file + ":" + n.line : "", p[0], p[1] + r + 12 * cam.zoom);
}

function draw() {
  ctx.clearRect(0, 0, W, H);
  drawPhaseLanes();

  var hlEdges = {};
  var hlNodes = {};
  if (activeChain >= 0) {
    edges.forEach(function(e, i) { if (e.chain === activeChain) { hlEdges[i] = true; hlNodes[e.from] = true; hlNodes[e.to] = true; } });
    nodes.forEach(function(n, i) { if (n.chains && n.chains.indexOf(activeChain) >= 0) hlNodes[i] = true; });
  }
  if (activeNode >= 0) hlNodes[activeNode] = true;

  edges.forEach(function(e, i) { if (!hlEdges[i]) drawEdge(e, false); });
  edges.forEach(function(e, i) { if (hlEdges[i]) drawEdge(e, true); });

  nodes.forEach(function(n, i) { if (!hlNodes[i]) drawNode(n, false, i === hoveredNode); });
  nodes.forEach(function(n, i) { if (hlNodes[i]) drawNode(n, true, i === hoveredNode); });
}

function hitTest(mx, my) {
  var w = toWorld(mx, my);
  for (var i = nodes.length - 1; i >= 0; i--) {
    var n = nodes[i];
    var dx = w[0] - n.x, dy = w[1] - n.y;
    if (dx * dx + dy * dy < (n.r + 4) * (n.r + 4)) return i;
  }
  return -1;
}

canvas.addEventListener("mousedown", function(e) {
  dragging = true;
  didDrag = false;
  dragStart = {x: e.clientX, y: e.clientY, cx: cam.x, cy: cam.y};
});

canvas.addEventListener("mousemove", function(e) {
  if (dragging) {
    var dx = e.clientX - dragStart.x;
    var dy = e.clientY - dragStart.y;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) didDrag = true;
    cam.x = dragStart.cx + dx / cam.zoom;
    cam.y = dragStart.cy + dy / cam.zoom;
    draw();
  } else {
    var hit = hitTest(e.offsetX, e.offsetY);
    if (hit !== hoveredNode) {
      hoveredNode = hit;
      canvas.style.cursor = hit >= 0 ? "pointer" : "grab";
      draw();
    }
  }
});

canvas.addEventListener("mouseup", function(e) {
  dragging = false;
  if (!didDrag) {
    var hit = hitTest(e.offsetX, e.offsetY);
    if (hit >= 0) {
      activeNode = hit;
      showDetail(hit);
      draw();
    }
  }
});

canvas.addEventListener("wheel", function(e) {
  e.preventDefault();
  var factor = e.deltaY > 0 ? 0.9 : 1.1;
  var newZoom = Math.max(0.2, Math.min(3, cam.zoom * factor));
  var w = toWorld(e.offsetX, e.offsetY);
  cam.zoom = newZoom;
  cam.x = e.offsetX / newZoom - w[0];
  cam.y = e.offsetY / newZoom - w[1];
  draw();
}, {passive: false});

function esc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

function showDetail(idx) {
  var n = nodes[idx];
  var el = document.getElementById("detail");
  var body = document.getElementById("detail-body");
  el.style.display = "block";
  var h = '<span class="sev sev-' + n.severity + '">' + n.severity + '</span>';
  h += '<span class="label">Technique</span><span class="value">' + esc(n.technique) + '</span>';
  h += '<span class="label">Phase</span><span class="value">' + esc(PHASE_LABELS[n.phase] || n.phase) + '</span>';
  if (n.cwe) h += '<span class="label">CWE</span><span class="value">' + esc(n.cwe) + '</span>';
  if (n.file) h += '<span class="label">Location</span><span class="value">' + esc(n.file + ':' + n.line) + '</span>';
  if (n.description) h += '<span class="label">Description</span><span class="value">' + esc(n.description) + '</span>';
  if (n.provides && n.provides.length) {
    h += '<span class="label">Capabilities Gained</span>';
    n.provides.forEach(function(p) { h += '<span class="cap-chip">' + esc(p) + '</span>'; });
  }
  if (n.preconditions && n.preconditions.length) {
    h += '<span class="label">Preconditions</span>';
    n.preconditions.forEach(function(p) { h += '<span class="cap-chip">' + esc(p) + '</span>'; });
  }
  body.innerHTML = h;
}

function buildSidebar() {
  var list = document.getElementById("chain-list");
  chains.forEach(function(c, i) {
    var div = document.createElement("div");
    div.className = "chain-card";
    div.innerHTML = '<div class="name"><span class="sev sev-' + c.severity + '">' + c.severity + '</span>' + esc(c.name) + '</div>'
      + '<div class="meta">' + c.length + ' steps &middot; ' + esc((c.impact || "").slice(0, 60)) + '</div>';
    div.onclick = function() {
      activeChain = activeChain === i ? -1 : i;
      activeNode = -1;
      document.getElementById("detail").style.display = "none";
      var cards = document.querySelectorAll(".chain-card");
      for (var j = 0; j < cards.length; j++) {
        cards[j].classList.toggle("active", j === activeChain);
      }
      draw();
    };
    list.appendChild(div);
  });

  var legendEl = document.getElementById("legend-items");
  var usedPhases = {};
  nodes.forEach(function(n) { usedPhases[n.phase] = true; });
  PHASE_ORDER.filter(function(p) { return usedPhases[p]; }).forEach(function(p) {
    var div = document.createElement("div");
    div.className = "legend-item";
    div.innerHTML = '<span class="legend-dot" style="background:' + (PHASE_COLORS[p] || '#666') + '"></span>' + esc(PHASE_LABELS[p] || p);
    legendEl.appendChild(div);
  });

  document.getElementById("s-nodes").textContent = nodes.length;
  document.getElementById("s-edges").textContent = edges.length;
  document.getElementById("s-chains").textContent = chains.length;
}

window.addEventListener("resize", function() { resize(); layout(); draw(); });
resize();
layout();
buildSidebar();
draw();
</script>
</body>
</html>"""
