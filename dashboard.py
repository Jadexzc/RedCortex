"""
RedCortex Advanced Dashboard for Viewing Scan Results
Modern interactive web UI with live logo from plugins/logo/RedCortex.txt.
"""

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path

logger = logging.getLogger(__name__)

def load_dashboard_logo():
    logo_path = Path(__file__).parent / "plugins" / "logo" / "RedCortex.txt"
    try:
        with open(logo_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "RedCortex"

class DashboardHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, result_manager=None, **kwargs):
        self.result_manager = result_manager
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/':
            self.serve_index()
        elif parsed_path.path == '/api/scans':
            self.serve_scans_list()
        elif parsed_path.path.startswith('/api/scan/'):
            scan_id = parsed_path.path.split('/')[-1]
            self.serve_scan_detail(scan_id)
        else:
            self.send_error(404, 'Not Found')

    def serve_index(self):
        logo_html = f"<pre style='font-family:monospace;font-size:18px;color:#d32f2f;'>{load_dashboard_logo()}</pre>"
        html = f'''<!DOCTYPE html>
<html>
<head>
<title>RedCortex Dashboard</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: 20px auto; background: white; padding: 24px; border-radius: 10px; box-shadow: 0 4px 30px #8884; }}
h1 {{ color: #d32f2f; font-weight: bold; text-align: left; letter-spacing: 2px; }}
.statbar {{ display: flex; gap: 24px; margin: 18px 0 8px 0; font-size: 16px; }}
.statbox {{ display:inline; border-radius:6px;padding:6px 16px;font-weight:600;margin-right:10px }}
.stat-CRITICAL {{ background:#d32f2f; color:white; }}
.stat-high     {{ background:#ff9800; color:white; }}
.stat-medium   {{ background:#ffc107; }}
.stat-low      {{ background:#2196f3; color:white; }}
#scan-list {{ list-style: none; padding: 0; }}
.scan-item {{ padding: 15px; margin: 10px 0; background: #fafafa; border-left: 4px solid #d32f2f; cursor:pointer; border-radius: 0 8px 8px 0; }}
.scan-item:hover {{ background: #f0f0f0; }}
#scan-detail {{ margin-top:24px; padding:20px; background:#fafafa; border-radius:8px; display:none; }}
.finding-item {{ border-left: 6px solid #2196f3; margin-bottom: 10px; padding: 12px; background: white; border-radius: 0 8px 8px 0; }}
.severity-CRITICAL  {{ color:#d32f2f;font-weight:bold; }}
.severity-high      {{ color:#ff9800;font-weight:bold; }}
.severity-medium    {{ color:#ffc107;font-weight:bold; }}
.severity-low       {{ color:#2196f3;font-weight:bold; }}
.plugin-chip        {{ display:inline-block;padding:1px 8px 2px 8px;margin:0 8px 0 0;background:#ddd;border-radius:10px;font-size:13px }}
@media(max-width:768px){{ .container{{padding:5px}} }}
</style>
</head>
<body>
<div class="container">
{logo_html}
<h1>RedCortex Dashboard</h1>
<div id="statblock" class="statbar"></div>
<section>
  <h2>Recent Scans</h2>
  <button onclick="loadScans()">⟳ Reload</button>
  <ul id="scan-list"></ul>
</section>
<div id="scan-detail">
  <h3>Scan Details</h3>
  <div id="detail-content"></div>
  <button onclick="exportDetail()">Export JSON</button>
</div>
</div>
<script>
let scansCache = [];
function severityColor(sev){ return {{
  'CRITICAL':'#d32f2f', 'high':'#ff9800', 'medium':'#ffc107', 'low':'#2196f3'
}}[sev] || '#666'; }
async function loadScans() {{
  let r = await fetch('/api/scans'); let scans = await r.json();
  scansCache = scans;
  let counts = {{CRITICAL:0,high:0,medium:0,low:0}};
  let plugins = {{}};
  let html = scans.map(scan => {{
    if(scan.findings_breakdown) for(let k in scan.findings_breakdown) counts[k] = (counts[k]||0)+scan.findings_breakdown[k];
    if(scan.plugins) scan.plugins.forEach(p=>plugins[p]=(plugins[p]||0)+1);
    return `<li class="scan-item" onclick="loadScanDetail('${scan.scan_id}')"><strong>${scan.target}</strong>
    <small>(${scan.timestamp})</small><br>
    <span>${Object.entries(scan.findings_breakdown||{{}}).map(([k,v])=>`<span class='statbox stat-${k}'>${k}: ${v}</span>`).join('')}</span>
    </li>`;
  }}).join('');
  document.getElementById('scan-list').innerHTML=html;
  document.getElementById('statblock').innerHTML=Object.entries(counts).map(([k,v])=>`<div class='statbox stat-${k}'>${k}: ${v}</div>`).join(' ');
}}
async function loadScanDetail(scanId){{
  let r=await fetch('/api/scan/'+scanId); let scan=await r.json();
  document.getElementById('scan-detail').style.display='block';
  let byPlugin={{}};
  let html = scan.findings && scan.findings.length?
    scan.findings.map(f=>
      `<div class="finding-item">
        <b style="color:${severityColor(f.severity)}">${f.severity}</b>
        <span class="plugin-chip">${f.plugin}</span>
        <b>${f.param||""}</b> <code>${(f.payload||"").slice(0,50)}</code><br>
        <i>${f.evidence||f.description}</i><br>
        <small>${f.url||""}</small>
      </div>`
    ).join('') : "<p>No findings.</p>";
  document.getElementById('detail-content').innerHTML=`
    <b>Scan ID:</b> ${scan.scan_id}<br>
    <b>Target:</b> ${scan.target}<br>
    <b>Timestamp:</b> ${scan.timestamp}<br>
    <b>Total Findings:</b> ${scan.findings.length || 0}<hr>
    ${html}`;
}}
function exportDetail(){{
  let detail = document.getElementById('detail-content').innerText;
  let blob = new Blob([JSON.stringify(scansCache,null,2)], {{type:"application/json"}});
  let a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download="RedCortex_scan.json"; a.click();
}}
loadScans();
</script>
</body>
</html>
'''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_scans_list(self):
        scans = self.result_manager.list_scans()
        for s in scans:
            s['findings_breakdown'] = s.get('findings_breakdown', {})
            s['plugins'] = list(set(f.get('plugin') for f in s.get('findings', [])))
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(scans).encode())

    def serve_scan_detail(self, scan_id: str):
        scan_data = self.result_manager.load_results(scan_id)
        if scan_data:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(scan_data).encode())
        else:
            self.send_error(404, 'Scan not found')

    def log_message(self, format, *args):
        logger.debug(f"{self.address_string()} - {format % args}")

class Dashboard:
    def __init__(self, result_manager, port: int = 8080):
        self.result_manager = result_manager
        self.port = port
        self.server = None

    def start(self):
        handler = lambda *args, **kwargs: DashboardHandler(*args, result_manager=self.result_manager, **kwargs)
        try:
            self.server = HTTPServer(('localhost', self.port), handler)
            logger.info(f"Dashboard running at http://localhost:{self.port}")
            print(f"\n🌐 Dashboard running at http://localhost:{self.port}")
            print("Press Ctrl+C to stop\n")
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Dashboard stopped by user")
            print("\nDashboard stopped.")
        except Exception as e:
            logger.error(f"Failed to start dashboard: {str(e)}")
            raise

    def stop(self):
        if self.server:
            self.server.shutdown()
            logger.info("Dashboard stopped")
