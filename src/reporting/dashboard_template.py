"""
Dashboard HTML Template — OSINT Recon
Renders an interactive single-page dark-themed assessment dashboard.

Design: Syne + JetBrains Mono, deep-space dark palette, bento grid,
SVG risk gauge, dot-grid background, glass-morphism cards.

NOTE: All innerHTML usage in the client-side JS renders data that was
serialized from our own Python scoring models (not user input), so it
is safe from XSS.  The dashboard is a local self-contained file.
"""

import json

# ─── Color helpers ───────────────────────────────────────────────
_RISK_ACCENT = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#3b82f6",
}


def render_dashboard(**ctx) -> str:
    """Return complete HTML string for the OSINT dashboard."""

    rc = _RISK_ACCENT.get(ctx["risk_level"], "#22c55e")
    score = ctx["overall_score"]
    # SVG gauge angle: 0-10 mapped to 0-270 degrees
    gauge_angle = min(score / 10.0, 1.0) * 270

    return (
        _head(ctx, rc)
        + _body_open(ctx, rc, score, gauge_angle)
        + _sections(ctx)
        + _scripts(ctx)
        + "\n</body>\n</html>"
    )


# ═════════════════════════════════════════════════════════════════
#  HEAD  –  meta, fonts, CSS
# ═════════════════════════════════════════════════════════════════

def _head(ctx, rc):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT Recon — {ctx['org_name']}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root {{
  --bg:#08080f; --surface:#10111a; --card:#13141f;
  --elevated:#1a1b2e; --border:#1e2035;
  --accent:#D92626; --accent2:#0ea5e9;
  --danger:#ef4444; --warn:#f59e0b; --low:#22c55e;
  --text:#e2e8f0; --text2:#94a3b8; --text3:#475569;
  --mono:'JetBrains Mono',monospace; --display:'Syne',sans-serif;
  --risk:{rc};
}}
*,*::before,*::after {{ margin:0;padding:0;box-sizing:border-box; }}
html {{ scroll-behavior:smooth; }}
body {{
  font-family:var(--mono); background:var(--bg); color:var(--text);
  line-height:1.6; min-height:100vh;
  background-image:radial-gradient(circle,#1e2035 1px,transparent 1px);
  background-size:24px 24px;
}}
.topbar {{
  display:flex;justify-content:space-between;align-items:center;
  padding:1rem 2rem;background:var(--surface);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:100;backdrop-filter:blur(12px);
}}
.topbar-brand {{ font-family:var(--display);font-size:1.35rem;font-weight:800;letter-spacing:-.02em; }}
.topbar-brand em {{ font-style:normal;color:var(--accent); }}
.topbar-meta {{ font-size:.72rem;color:var(--text3);text-align:right;line-height:1.5; }}
.topbar-meta strong {{ color:var(--text2); }}
.wrap {{ max-width:1440px;margin:0 auto;padding:1.5rem 2rem 3rem; }}
.hero {{ display:grid;grid-template-columns:220px 1fr;gap:1.5rem;margin-bottom:1.5rem; }}
@media(max-width:700px) {{ .hero {{ grid-template-columns:1fr; }} }}
.gauge-card {{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:1.5rem 1rem;position:relative;overflow:hidden;
}}
.gauge-card::before {{
  content:'';position:absolute;inset:0;
  background:radial-gradient(circle at 50% 40%,color-mix(in srgb,var(--risk) 12%,transparent),transparent 70%);
  pointer-events:none;
}}
.gauge-svg {{ width:140px;height:140px; }}
.gauge-label {{ font-family:var(--display);font-size:2rem;font-weight:800;margin-top:.5rem;color:var(--risk); }}
.gauge-sublabel {{ font-size:.65rem;text-transform:uppercase;letter-spacing:.12em;color:var(--text3);margin-top:.15rem; }}
.gauge-risk {{
  display:inline-block;margin-top:.6rem;padding:.2rem .7rem;border-radius:4px;
  font-size:.7rem;font-weight:700;text-transform:uppercase;
  background:var(--risk);color:#fff;letter-spacing:.06em;
}}
.stats-grid {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem; }}
.stat {{
  background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:1.1rem 1rem;display:flex;flex-direction:column;gap:.3rem;
  transition:border-color .2s,transform .15s;
}}
.stat:hover {{ border-color:var(--accent);transform:translateY(-2px); }}
.stat-val {{ font-family:var(--display);font-size:1.7rem;font-weight:800;color:var(--text);line-height:1; }}
.stat-label {{ font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text3); }}
.stat-sub {{ font-size:.68rem;color:var(--text3); }}
.card {{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  overflow:hidden;margin-bottom:1.25rem;
}}
.card-head {{
  display:flex;justify-content:space-between;align-items:center;
  padding:.75rem 1.2rem;background:var(--surface);
  border-bottom:1px solid var(--border);cursor:pointer;user-select:none;
}}
.card-head h2 {{
  font-family:var(--display);font-size:.95rem;font-weight:700;color:var(--text);
  display:flex;align-items:center;gap:.5rem;
}}
.card-head h2::before {{
  content:'';display:inline-block;width:3px;height:16px;
  background:var(--accent);border-radius:2px;
}}
.card-head .toggle {{ color:var(--text3);font-size:.8rem;transition:transform .2s; }}
.card-body {{ padding:1.2rem; }}
.summary {{ font-size:.82rem;color:var(--text2);line-height:1.8;border-left:2px solid var(--accent);padding-left:1rem; }}
.chart-grid {{ display:grid;grid-template-columns:1fr 1fr;gap:1.25rem;margin-bottom:1.25rem; }}
.chart-wrap {{ position:relative;height:260px; }}
@media(max-width:800px) {{ .chart-grid {{ grid-template-columns:1fr; }} }}
#pyvis-frame {{ width:100%;height:700px;border:none;border-radius:8px;background:var(--bg); }}
#network-graph {{ width:100%;height:500px;border-radius:8px;background:var(--bg); }}
.tabs {{ display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:1rem; }}
.tab-btn {{
  background:none;border:none;color:var(--text3);padding:.65rem 1.3rem;
  cursor:pointer;font-family:var(--mono);font-size:.78rem;font-weight:500;
  border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s,border-color .15s;
}}
.tab-btn:hover {{ color:var(--text); }}
.tab-btn.on {{ color:var(--accent);border-bottom-color:var(--accent); }}
.tab-pane {{ display:none; }}
.tab-pane.on {{ display:block; }}
table {{ width:100%;border-collapse:collapse;font-size:.78rem; }}
thead th {{
  text-align:left;padding:.6rem .8rem;font-size:.65rem;
  text-transform:uppercase;letter-spacing:.08em;color:var(--text3);
  border-bottom:1px solid var(--border);cursor:pointer;user-select:none;
  font-weight:600;transition:color .15s;
}}
thead th:hover {{ color:var(--accent); }}
tbody td {{ padding:.55rem .8rem;border-bottom:1px solid var(--border); }}
tbody tr {{ transition:background .12s; }}
tbody tr:hover {{ background:var(--elevated); }}
.badge {{
  display:inline-block;padding:.15em .55em;border-radius:4px;
  font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;
}}
.badge-critical {{ background:#ef4444;color:#fff; }}
.badge-high {{ background:#f97316;color:#fff; }}
.badge-medium {{ background:#eab308;color:#111; }}
.badge-low {{ background:#22c55e;color:#fff; }}
.badge-info {{ background:#3b82f6;color:#fff; }}
.expand-btn {{
  background:none;border:1px solid var(--border);border-radius:4px;
  color:var(--text3);width:22px;height:22px;display:inline-flex;
  align-items:center;justify-content:center;cursor:pointer;
  font-size:.75rem;font-weight:700;transition:all .15s;
}}
.expand-btn:hover {{ border-color:var(--accent);color:var(--accent); }}
.detail-row {{ display:none; }}
.detail-row.on {{ display:table-row; }}
.detail-cell {{ padding:.8rem 1.2rem;background:var(--surface);border-bottom:1px solid var(--border); }}
.finding {{
  border-left:3px solid var(--border);padding:.5rem .8rem;
  margin-bottom:.5rem;border-radius:0 6px 6px 0;background:var(--card);
}}
.finding-critical {{ border-left-color:#ef4444; }}
.finding-high {{ border-left-color:#f97316; }}
.finding-medium {{ border-left-color:#eab308; }}
.finding-low {{ border-left-color:#22c55e; }}
.finding h4 {{ font-size:.78rem;font-weight:600;margin-bottom:.2rem; }}
.finding p {{ font-size:.72rem;color:var(--text2);margin-bottom:.15rem; }}
.finding .rem {{ color:var(--accent);font-size:.7rem; }}
.chain {{ display:flex;flex-wrap:wrap;align-items:center;gap:.3rem;margin:.4rem 0; }}
.chain-node {{ background:var(--surface);border:1px solid var(--border);padding:.15rem .5rem;border-radius:4px;font-size:.72rem; }}
.chain-arrow {{ color:var(--danger);font-weight:700;font-size:.7rem; }}
.footer {{ text-align:center;padding:1.5rem;font-size:.65rem;color:var(--text3);border-top:1px solid var(--border);margin-top:2rem; }}
@keyframes gaugeIn {{ from {{ stroke-dashoffset:848; }} }}
@keyframes fadeUp {{ from {{ opacity:0;transform:translateY(12px); }} to {{ opacity:1;transform:translateY(0); }} }}
.card,.stat,.gauge-card {{ animation:fadeUp .4s ease both; }}
.stat:nth-child(2){{animation-delay:.05s}}
.stat:nth-child(3){{animation-delay:.1s}}
.stat:nth-child(4){{animation-delay:.15s}}
.stat:nth-child(5){{animation-delay:.2s}}
</style>
</head>
"""


# ═════════════════════════════════════════════════════════════════
#  BODY — HTML structure
# ═════════════════════════════════════════════════════════════════

def _body_open(ctx, rc, score, gauge_angle):
    gs = ctx["graph_stats"]
    r = 54
    c = 2 * 3.14159 * r
    arc_len = (gauge_angle / 360) * c
    dash = f"{arc_len:.1f} {c:.1f}"

    return f"""<body>
<header class="topbar">
  <div class="topbar-brand">OSINT<em>Recon</em></div>
  <div class="topbar-meta">
    <strong>{ctx['org_name']}</strong> &middot; {ctx['domain'] or 'N/A'}<br>
    {ctx['timestamp']}
  </div>
</header>
<div class="wrap">
<div class="hero">
  <div class="gauge-card">
    <svg class="gauge-svg" viewBox="0 0 140 140">
      <circle cx="70" cy="70" r="{r}" fill="none" stroke="var(--border)"
              stroke-width="10" stroke-dasharray="254.5 339.3"
              transform="rotate(135 70 70)" stroke-linecap="round"/>
      <circle cx="70" cy="70" r="{r}" fill="none" stroke="{rc}"
              stroke-width="10" stroke-dasharray="{dash}"
              transform="rotate(135 70 70)" stroke-linecap="round"
              style="animation:gaugeIn .8s ease both;filter:drop-shadow(0 0 6px {rc}40)"/>
    </svg>
    <div class="gauge-label">{score}</div>
    <div class="gauge-sublabel">out of 10.0</div>
    <span class="gauge-risk">{ctx['risk_level'].upper()}</span>
  </div>
  <div class="stats-grid">
    <div class="stat"><span class="stat-val">{ctx['people_count']}</span>
      <span class="stat-label">People Discovered</span>
      <span class="stat-sub">employees &amp; contributors</span></div>
    <div class="stat"><span class="stat-val">{gs.get('total_nodes',0)}</span>
      <span class="stat-label">Graph Nodes</span>
      <span class="stat-sub">{gs.get('total_edges',0)} edges</span></div>
    <div class="stat"><span class="stat-val">{ctx['hvt_count']}</span>
      <span class="stat-label">High-Value Targets</span>
      <span class="stat-sub">by centrality analysis</span></div>
    <div class="stat"><span class="stat-val">{ctx['attack_path_count']}</span>
      <span class="stat-label">Attack Paths</span>
      <span class="stat-sub">social engineering routes</span></div>
    <div class="stat"><span class="stat-val">{f"{gs.get('density',0):.3f}"}</span>
      <span class="stat-label">Graph Density</span>
      <span class="stat-sub">{gs.get('connected_components',0)} component(s)</span></div>
  </div>
</div>
"""


def _sections(ctx):
    pyvis_or_graph = (
        f"<iframe id='pyvis-frame' src='{ctx['pyvis_data_uri']}'></iframe>"
        if ctx.get("pyvis_data_uri")
        else "<div id='network-graph'></div>"
    )
    return f"""
<div class="card">
  <div class="card-head" onclick="tog(this)"><h2>Executive Summary</h2><span class="toggle">&#9662;</span></div>
  <div class="card-body"><div class="summary">{ctx['summary']}</div></div>
</div>
<div class="chart-grid">
  <div class="card">
    <div class="card-head"><h2>Risk Distribution</h2></div>
    <div class="card-body"><div class="chart-wrap"><canvas id="riskChart"></canvas></div></div>
  </div>
  <div class="card">
    <div class="card-head"><h2>Score Histogram</h2></div>
    <div class="card-body"><div class="chart-wrap"><canvas id="scoreChart"></canvas></div></div>
  </div>
</div>
<div class="card">
  <div class="card-head" onclick="tog(this)"><h2>Network Graph</h2><span class="toggle">&#9662;</span></div>
  <div class="card-body" style="padding:.6rem">{pyvis_or_graph}</div>
</div>
<div class="card">
  <div class="card-body">
    <div class="tabs">
      <button class="tab-btn on" onclick="tab('people',this)">People ({ctx['people_count']})</button>
      <button class="tab-btn" onclick="tab('infra',this)">Infrastructure</button>
      <button class="tab-btn" onclick="tab('paths',this)">Attack Paths ({ctx['attack_path_count']})</button>
    </div>
    <div id="p-people" class="tab-pane on">
      <table id="tbl-people"><thead><tr>
        <th style="width:30px"></th>
        <th onclick="sortT('tbl-people',1)">Name</th>
        <th onclick="sortT('tbl-people',2)">Role</th>
        <th onclick="sortT('tbl-people',3)">Score</th>
        <th onclick="sortT('tbl-people',4)">Risk</th>
        <th onclick="sortT('tbl-people',5)">Findings</th>
      </tr></thead><tbody id="people-tb"></tbody></table>
    </div>
    <div id="p-infra" class="tab-pane"><div id="infra-out"></div></div>
    <div id="p-paths" class="tab-pane"><div id="paths-out"></div></div>
  </div>
</div>
<div class="footer">OSINT Recon v0.1.0 &middot; Author: Elijah Bellamy &middot; {ctx['timestamp']} &middot; CONFIDENTIAL</div>
</div>
"""


# ═════════════════════════════════════════════════════════════════
#  SCRIPTS  –  charts, table rendering, utilities
# ═════════════════════════════════════════════════════════════════

def _scripts(ctx):
    # All data rendered into JS is produced by our own scoring models,
    # not arbitrary user input, so using innerHTML is safe here.
    return f"""
<script>
const people={ctx['people_json']};
const infra={ctx['infra_json']};
const atkPaths={ctx['paths_json']};
const riskDist={ctx['risk_dist_json']};
const visNodes={ctx['vis_nodes_json']};
const visEdges={ctx['vis_edges_json']};

const RC={{critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',info:'#3b82f6'}};
const cf={{family:"'JetBrains Mono',monospace",size:11,color:'#94a3b8'}};
Chart.defaults.font=cf; Chart.defaults.color='#94a3b8';

new Chart(document.getElementById('riskChart'),{{
  type:'doughnut',
  data:{{labels:['Critical','High','Medium','Low','Info'],
    datasets:[{{data:[riskDist.critical,riskDist.high,riskDist.medium,riskDist.low,riskDist.info],
      backgroundColor:['#ef4444','#f97316','#eab308','#22c55e','#3b82f6'],
      borderColor:'#10111a',borderWidth:3,hoverOffset:6}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'68%',
    plugins:{{legend:{{position:'bottom',labels:{{padding:14,usePointStyle:true,pointStyle:'circle'}}}}}}}}
}});

const bk=Array(10).fill(0);
people.forEach(p=>{{const i=Math.min(9,Math.floor(p.score));bk[i]++;}});
new Chart(document.getElementById('scoreChart'),{{
  type:'bar',
  data:{{labels:['0-1','1-2','2-3','3-4','4-5','5-6','6-7','7-8','8-9','9-10'],
    datasets:[{{data:bk,
      backgroundColor:bk.map((_,i)=>i>=8?'#ef4444':i>=6?'#f97316':i>=4?'#eab308':'#22c55e'),
      borderRadius:4,barPercentage:.7}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:'#1e2035'}},ticks:{{font:{{size:10}}}}}},
             y:{{grid:{{color:'#1e2035'}},ticks:{{stepSize:1,font:{{size:10}}}}}}}}}}
}});

/* people table — data is self-generated, safe for innerHTML */
const tb=document.getElementById('people-tb');
people.forEach((p,i)=>{{
  const tr=document.createElement('tr');
  tr.innerHTML='<td><button class="expand-btn" onclick="xpand('+i+')">+</button></td>'
    +'<td>'+p.name+'</td>'
    +'<td style="color:var(--text2)">'+p.role+'</td>'
    +'<td style="font-weight:600">'+p.score+'</td>'
    +'<td><span class="badge badge-'+p.risk+'">'+p.risk.toUpperCase()+'</span></td>'
    +'<td>'+p.finding_count+'</td>';
  tb.appendChild(tr);
  const dr=document.createElement('tr');
  dr.className='detail-row';dr.id='d-'+i;
  const fc=p.findings.map(function(f){{
    return '<div class="finding finding-'+f.risk+'">'
      +'<h4><span class="badge badge-'+f.risk+'">'+f.risk.toUpperCase()+'</span> '+f.title+' ('+f.score+')</h4>'
      +'<p>'+f.description+'</p>'
      +(f.remediation?'<p class="rem">&#8627; '+f.remediation+'</p>':'')
      +'</div>';
  }}).join('');
  dr.innerHTML='<td colspan="6" class="detail-cell">'+(fc||'<p style="color:var(--text3)">No findings.</p>')+'</td>';
  tb.appendChild(dr);
}});

/* infrastructure — data is self-generated, safe for innerHTML */
const iO=document.getElementById('infra-out');
if(!infra.length){{iO.innerHTML='<p style="color:var(--text3);padding:.5rem">No infrastructure findings.</p>';}}
else{{infra.forEach(function(f){{
  iO.innerHTML+='<div class="finding finding-'+f.risk+'" style="margin-bottom:.7rem">'
    +'<h4><span class="badge badge-'+f.risk+'">'+f.risk.toUpperCase()+'</span> '+f.title+' ('+f.score+')</h4>'
    +'<p>'+f.description+'</p>'
    +(f.evidence.length?'<p style="margin-top:.2rem"><strong>Evidence:</strong> '+f.evidence.join(', ')+'</p>':'')
    +(f.remediation?'<p class="rem">&#8627; '+f.remediation+'</p>':'')
    +'</div>';
}});}}

/* attack paths — data is self-generated, safe for innerHTML */
const pO=document.getElementById('paths-out');
if(!atkPaths.length){{pO.innerHTML='<p style="color:var(--text3);padding:.5rem">No attack paths mapped.</p>';}}
else{{atkPaths.forEach(function(ap,i){{
  const ch=ap.path.map(function(n){{return '<span class="chain-node">'+n+'</span>';}}).join('<span class="chain-arrow"> &#8594; </span>');
  const bc=ap.risk_score>.5?'#ef4444':ap.risk_score>.3?'#f97316':'#22c55e';
  pO.innerHTML+='<div class="finding" style="border-left-color:'+bc+';margin-bottom:.7rem">'
    +'<h4>#'+(i+1)+' '+ap.entry+' &#8594; '+ap.target+' &nbsp; '+ap.hops+' hops &nbsp; risk '+ap.risk_score.toFixed(4)+'</h4>'
    +'<div class="chain">'+ch+'</div></div>';
}});}}

function xpand(i){{
  var r=document.getElementById('d-'+i);
  var b=r.previousElementSibling.querySelector('.expand-btn');
  r.classList.toggle('on');
  b.textContent=r.classList.contains('on')?'\u2212':'+';
}}
function tog(h){{
  var b=h.nextElementSibling,a=h.querySelector('.toggle');
  if(b.style.display==='none'){{b.style.display='';a.innerHTML='&#9662;';}}
  else{{b.style.display='none';a.innerHTML='&#9656;';}}
}}
function tab(id,btn){{
  document.querySelectorAll('.tab-pane').forEach(function(p){{p.classList.remove('on');}});
  document.querySelectorAll('.tab-btn').forEach(function(b){{b.classList.remove('on');}});
  document.getElementById('p-'+id).classList.add('on');
  btn.classList.add('on');
}}
function sortT(tid,ci){{
  var t=document.getElementById(tid),tb=t.querySelector('tbody');
  var rows=[].slice.call(tb.querySelectorAll('tr:not(.detail-row)'));
  var d=t.dataset.sd==='a'?'b':'a';t.dataset.sd=d;
  rows.sort(function(a,b){{
    var av=a.cells[ci].textContent.trim(),bv=b.cells[ci].textContent.trim();
    var an=parseFloat(av),bn=parseFloat(bv);
    if(!isNaN(an)&&!isNaN(bn))return d==='a'?an-bn:bn-an;
    return d==='a'?av.localeCompare(bv):bv.localeCompare(av);
  }});
  rows.forEach(function(r){{
    var det=r.nextElementSibling;
    tb.appendChild(r);
    if(det&&det.classList.contains('detail-row'))tb.appendChild(det);
  }});
}}
</script>
"""
