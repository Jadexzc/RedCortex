"""
RedCortex Advanced Dashboard for Viewing Scan Results.
"""

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
import os
import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def load_dashboard_logo() -> str:
    """Loads the ASCII logo from file or provides a fallback."""
    logo_path = Path(__file__).parent / "plugins" / "logo" / "RedCortex.txt"
    try:
        if logo_path.exists():
            with open(logo_path, "r", encoding="utf-8") as f:
                return f.read()
        else:
            return (
                " ______ __ ________________\n"
                "/ ____// //_// ____/ ___/__\n"
                "/ /__ / ,< / /_ / /__ / _ \\\n"
                "\___//_/|_|\\___/\\___//_//_/\n"
                "RedCortex"
            )
    except Exception:
        return "RedCortex"

class DummyResultManager:
    """Stand-in for demo/testing: implements list_scans/load_results methods with fake data."""
    
    def __init__(self):
        now = datetime.datetime.utcnow()
        self.scan_data: Dict[str, Dict[str, Any]] = {
            '20251103_200000': {
                'scan_id':'20251103_200000','target':'https://prod-api.corp.com','timestamp':(now - datetime.timedelta(hours=1)).isoformat() + 'Z',
                'findings':[
                    {'plugin':'sql_i','severity':'CRITICAL','evidence':'Stacked Query Injection','url':'/user/login','param':'username','payload':'1\' OR 1=1--'},
                    {'plugin':'xss','severity':'high','evidence':'Reflected XSS via Header','url':'/search','param':'User-Agent','payload':'<script>alert(1)</script>'},
                    {'plugin':'misconfig','severity':'medium','evidence':'Weak CORS Policy (Allow: *)','url':'/*'},
                    {'plugin':'info_leak','severity':'low','evidence':'Exposed Server Version','url':'/'}
                ]
            },
            '20251103_220000': {
                'scan_id':'20251103_220000','target':'http://dev-portal.internal','timestamp':(now - datetime.timedelta(hours=5)).isoformat() + 'Z',
                'findings':[
                    {'plugin':'misconfig','severity':'high','evidence':'Default Credentials Found (admin:admin)','url':'/admin/login'},
                    {'plugin':'info_leak','severity':'medium','evidence':'Internal IP Disclosure','url':'/status'},
                    {'plugin':'info_leak','severity':'medium','evidence':'Internal IP Disclosure','url':'/health'},
                    {'plugin':'misconfig','severity':'low','evidence':'HTTP over HTTPS (Minor)','url':'/v1/auth'}
                ]
            },
            '20251102_150000': {
                'scan_id':'20251102_150000','target':'https://legacy-app.old.com','timestamp':(now - datetime.timedelta(days=2)).isoformat() + 'Z',
                'findings':[
                    {'plugin':'ssrf','severity':'CRITICAL','evidence':'SSRF in webhook endpoint','url':'/hooks'},
                    {'plugin':'misconfig','severity':'high','evidence':'Outdated Software (Apache 2.2)','url':'/'},
                    {'plugin':'info_leak','severity':'low','evidence':'Robots.txt contains sensitive paths','url':'/robots.txt'}
                ]
            }
        }
        
    def _calculate_breakdown(self, findings: List[Dict[str, Any]]) -> tuple[Dict[str, int], List[str]]:
        breakdown: Dict[str, int] = {'CRITICAL': 0, 'high': 0, 'medium': 0, 'low': 0}
        plugins: set[str] = set()
        for f in findings:
            sev = f.get('severity', 'low').lower()
            if sev in breakdown:
                breakdown[sev] += 1
            plugins.add(f.get('plugin', ''))
        return breakdown, list(plugins)

    def list_scans(self) -> List[Dict[str, Any]]:
        summary_list = []
        for scan_id, data in self.scan_data.items():
            breakdown, plugins = self._calculate_breakdown(data.get('findings', []))
            summary_list.append({
                'scan_id': scan_id,
                'target': data['target'],
                'timestamp': data['timestamp'],
                'findings_breakdown': breakdown,
                'plugins': plugins,
            })
        return summary_list

    def load_results(self, scan_id: str) -> Dict[str, Any] | None:
        return self.scan_data.get(scan_id)


class DashboardHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, result_manager=None, **kwargs):
        self.result_manager = result_manager
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/':
            self.serve_index_robust()
        elif parsed_path.path == '/api/scans':
            self.serve_scans_list()
        elif parsed_path.path.startswith('/api/scan/'):
            scan_id = parsed_path.path.split('/')[-1]
            self.serve_scan_detail(scan_id)
        else:
            self.send_error(404, 'Not Found')

    def serve_index_robust(self):
        logo_html_content = f"<pre style='font-family:monospace;font-size:18px;color:#ff4444;margin-bottom:0;'>{load_dashboard_logo()}</pre>"

        html_template = '''<!DOCTYPE html>
<html>
<head>
<title>RedCortex Threat Intelligence Console</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
/* --- Core Design: Monospace Dark Red Theme --- */
body { 
    font-family: Consolas, Monaco, 'Courier New', monospace; 
    margin: 0; 
    background: #0c0c12; /* Very Dark Background */
    color: #e0e0e0; /* Light Gray Text */
    line-height: 1.5;
}
.container { 
    max-width: 1400px; 
    margin: 30px auto; 
    background: #191925; /* Slightly Lighter Container */
    padding: 30px; 
    border-radius: 8px; 
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5); 
}
h1 { 
    color: #ff4444; /* Bright Red Accent */
    font-weight: 700; 
    border-bottom: 2px solid #440000; /* Dark Red Separator */
    padding-bottom: 10px; 
    margin-top: 5px; 
}
h2 { 
    color: #ff8800; /* Orange/Warning Accent */
    border-left: 4px solid #ff4444; 
    padding-left: 10px; 
    margin-top: 30px; 
    font-size: 1.4em; 
}
button { 
    background: #cc0000; /* Solid Red for Actions */
    color: white; 
    border: none; 
    padding: 10px 18px; 
    border-radius: 6px; 
    cursor: pointer; 
    transition: background 0.3s, transform 0.1s; 
    font-weight: 600; 
    margin-right: 10px; 
}
button:hover { 
    background: #ff4444; 
    transform: translateY(-1px);
}
code { 
    background: #242433; /* Darker code block background */
    padding: 2px 5px; 
    border-radius: 4px; 
    font-size: 0.9em; 
    color: #ffd700; /* Gold/Yellow for code blocks */
}
hr { border: 0; border-top: 1px solid #440000; margin: 15px 0; }

/* --- Stats Bar --- */
.statbar { display: flex; flex-wrap: wrap; gap: 15px; margin: 18px 0 8px 0; }
.statbox { 
    padding: 8px 15px; 
    border-radius: 4px; 
    font-weight: 600; 
    color: white; 
    min-width: 120px;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    flex-grow: 1;
}
.stat-CRITICAL { background:#b71c1c; } /* Darker Red */
.stat-high     { background:#d84315; } /* Deep Orange */
.stat-medium   { background:#fbc02d; color: #121212; } /* Amber */
.stat-low      { background:#42a5f5; } /* Standard Blue (less urgent) */
#statblock div { margin-top: 5px; }


/* --- Scan List and Items --- */
#scan-list { list-style: none; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px; }
.scan-item { 
    padding: 15px; 
    background: #242433; /* Darker item background */
    border-left: 5px solid #ff4444; /* Bright Red accent border */
    cursor:pointer; 
    border-radius: 0 6px 6px 0; 
    transition: background 0.2s, border-color 0.2s;
}
.scan-item:hover { 
    background: #2c2c3d; 
    border-left-color: #ff8800; /* Orange on hover */
}
.scan-item strong { font-size: 1.1em; color: #fff; }

/* --- Scan Detail --- */
#scan-detail { margin-top:24px; padding:25px; background:#242433; border-radius:8px; display:none; border: 1px solid #440000; }
.finding-item { 
    border-left: 3px solid #ff8800; /* Orange accent */
    margin-bottom: 12px; padding: 12px; 
    background: #191925; 
    border-radius: 0 4px 4px 0; 
    color: #ccc;
}
.finding-item small { color: #999; display: block; margin-top: 5px;}

/* Finding Severity Highlighting */
.severity-CRITICAL  { color:#ff4444;font-weight:bold; }
.severity-high      { color:#ff8800;font-weight:bold; }
.severity-medium    { color:#fbc02d;font-weight:bold; }
.severity-low       { color:#42a5f5;font-weight:bold; }

.plugin-chip        { display:inline-block;padding:3px 10px;margin:0 8px 0 0;background:#440000;border-radius:15px;font-size:12px; color:#e0e0e0; }

/* Responsive adjustments */
@media(max-width:768px){ .container{margin: 10px; padding: 15px;} #scan-list{ grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="container">
{logo_html_placeholder}
<h1>Threat Intelligence Console</h1>

<div id="statblock" class="statbar"></div>
<hr>
<section>
  <h2>Recent Scan Results</h2>
  <div style="margin-bottom: 15px;">
    <button onclick="loadScans()">⟳ Refresh Scan List</button>
    <button onclick="clearDetail()" style="background: #440000;">Clear Detail View</button>
  </div>
  <ul id="scan-list"></ul>
</section>
<div id="scan-detail">
  <h3>Scan Details</h3>
  <div id="detail-content"></div>
  <button onclick="exportDetail()">Export Scan JSON</button>
</div>
</div>
<script>
let scansCache = [];
function severityColor(sev){ return {
  'CRITICAL':'#b71c1c', 'high':'#d84315', 'medium':'#fbc02d', 'low':'#42a5f5'
}[sev] || '#666'; }

async function loadScans() {
  document.getElementById('scan-list').innerHTML = '<li>Loading scan data...</li>';
  try {
    let r = await fetch('/api/scans'); 
    let scans = await r.json();
    scansCache = scans;
    let counts = {CRITICAL:0,high:0,medium:0,low:0};
    let html = scans.map(scan => {
      if(scan.findings_breakdown) for(let k in scan.findings_breakdown) counts[k] = (counts[k]||0)+scan.findings_breakdown[k];
      return `<li class="scan-item" onclick="loadScanDetail('${scan.scan_id}')">
        <strong>${scan.target}</strong>
        <small>${new Date(scan.timestamp).toLocaleString()}</small><br>
        <span style="margin-top: 8px; display: block;">${Object.entries(scan.findings_breakdown||{}).map(([k,v])=>`<span class='statbox stat-${k}' style='display:inline-block; margin-right:5px; font-size:12px;'>${k.toUpperCase()}: ${v}</span>`).join('')}</span>
      </li>`;
    }).join('');
    document.getElementById('scan-list').innerHTML=html || '<li>No scan results found.</li>';
    document.getElementById('statblock').innerHTML=Object.entries(counts).map(([k,v])=>`<div class='statbox stat-${k}'>${k.toUpperCase()}<br><span>${v}</span></div>`).join(' ');
  } catch (e) {
    console.error("Error loading scans:", e);
    document.getElementById('scan-list').innerHTML = '<li>Failed to load scan data. Check the server console.</li>';
  }
}

function clearDetail() {
    document.getElementById('scan-detail').style.display = 'none';
}

async function loadScanDetail(scanId){
  let r=await fetch('/api/scan/'+scanId); 
  let scan=await r.json();

  document.getElementById('scan-detail').style.display='block';
  
  // Group findings by severity for better display structure
  let groupedFindings = {};
  const severityOrder = ['CRITICAL', 'high', 'medium', 'low', 'UNKNOWN'];

  if (scan.findings) {
    scan.findings.forEach(f => {
      const sev = (f.severity || 'low').toLowerCase();
      if (!groupedFindings[sev]) groupedFindings[sev] = [];
      groupedFindings[sev].push(f);
    });
  }

  let detailHtml = '';
  severityOrder.forEach(sev => {
    if (groupedFindings[sev]) {
      detailHtml += `<h4 class='severity-${sev}' style='margin-top:20px; font-size:1.1em;'>${sev.toUpperCase()} (${groupedFindings[sev].length})</h4>`;
      groupedFindings[sev].forEach(f => {
        detailHtml += `<div class="finding-item">
          <span class="plugin-chip">${f.plugin}</span>
          <b style="color: #fff;">${f.evidence||f.description}</b><br>
          <b>Param:</b> <code>${f.param||"N/A"}</code> 
          <b>Payload:</b> <code>${(f.payload||"N/A").slice(0, 120)}${f.payload && f.payload.length > 120 ? '...' : ''}</code><br>
          <small>URL: ${f.url||"N/A"}</small>
        </div>`;
      });
    }
  });

  document.getElementById('detail-content').innerHTML=`
    <b>Target:</b> <code style="font-size: 1.1em; color: #ff4444;">${scan.target}</code><br>
    <b>Scan ID:</b> <code>${scan.scan_id}</code><br>
    <b>Timestamp:</b> <code>${new Date(scan.timestamp).toLocaleString()}</code><br>
    <b>Total Findings:</b> <code>${scan.findings.length || 0}</code>
    <hr>
    ${detailHtml || "<p>No findings for this scan.</p>"}
    `;
}

async function exportDetail(){
  // Locate the Scan ID from the currently displayed details
  const contentDiv = document.getElementById('detail-content');
  const codeElements = contentDiv.querySelectorAll('code');
  // Assuming Scan ID is the second code block (after Target)
  const currentScanId = codeElements.length > 1 ? codeElements[1].textContent.trim() : null;

  if (currentScanId) {
    // Fetch the full data again to ensure complete and accurate export
    let r = await fetch('/api/scan/'+currentScanId); 
    let fullScanData = await r.json();

    let blob = new Blob([JSON.stringify(fullScanData, null, 2)], {type:"application/json"});
    let a = document.createElement('a'); a.href=URL.createObjectURL(blob);
    a.download="RedCortex_scan_" + currentScanId + ".json"; a.click();
  } else {
    alert("No scan detail currently loaded for export.");
  }
}
loadScans();
</script>
</body>
</html>'''
        html = html_template.format(logo_html_placeholder=logo_html_content)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_scans_list(self):
        scans = self.result_manager.list_scans()
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
    def __init__(self, result_manager=None, port: int = 8080):
        self.result_manager = result_manager or DummyResultManager()
        self.port = port
        self.server = None

    def start(self):
        from functools import partial
        handler_class = partial(DashboardHandler, result_manager=self.result_manager)
        
        try:
            logging.basicConfig(level=logging.INFO)
            
            self.server = HTTPServer(('localhost', self.port), handler_class)
            print(f"\n🌐 RedCortex Dashboard running at http://localhost:{self.port}")
            print("Press Ctrl+C to stop\n")
            self.server.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard stopped gracefully.")
        except Exception as e:
            print(f"Failed to start dashboard: {str(e)}")
            if self.server:
                self.server.shutdown()
            raise

    def stop(self):
        if self.server:
            self.server.shutdown()
            print("Dashboard stopped")

if __name__ == "__main__":
    Path("plugins/logo").mkdir(parents=True, exist_ok=True) 
    
    Dashboard().start()
