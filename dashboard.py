"""Simple dashboard for viewing RedCortex scan results.

Provides a basic web interface to view and analyze scan results.
"""
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional
import os


logger = logging.getLogger(__name__)


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""
    
    def __init__(self, *args, result_manager=None, **kwargs):
        """Initialize handler with result manager.
        
        Args:
            result_manager: ResultManager instance for accessing scan data
        """
        self.result_manager = result_manager
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests."""
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
        """Serve the main dashboard HTML page."""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>RedCortex Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
                h1 { color: #d32f2f; }
                .scan-list { list-style: none; padding: 0; }
                .scan-item { padding: 15px; margin: 10px 0; background: #fafafa; border-left: 4px solid #d32f2f; cursor: pointer; }
                .scan-item:hover { background: #f0f0f0; }
                .findings { color: #d32f2f; font-weight: bold; }
                .no-findings { color: #4caf50; }
                #scan-detail { margin-top: 20px; padding: 20px; background: #fafafa; border-radius: 4px; }
                .finding-item { margin: 10px 0; padding: 10px; background: white; border-left: 4px solid #ff9800; }
                .severity { font-weight: bold; text-transform: uppercase; }
                .severity-HIGH { color: #d32f2f; }
                .severity-MEDIUM { color: #ff9800; }
                .severity-LOW { color: #ffc107; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔴 RedCortex Dashboard</h1>
                <h2>Recent Scans</h2>
                <ul class="scan-list" id="scan-list"></ul>
                <div id="scan-detail" style="display:none;"></div>
            </div>
            <script>
                async function loadScans() {
                    const response = await fetch('/api/scans');
                    const scans = await response.json();
                    const list = document.getElementById('scan-list');
                    list.innerHTML = scans.map(scan => `
                        <li class="scan-item" onclick="loadScanDetail('${scan.scan_id}')">
                            <strong>${scan.target}</strong><br>
                            <small>${scan.timestamp}</small><br>
                            ${scan.findings_count > 0 ? 
                                `<span class="findings">${scan.findings_count} findings</span>` :
                                '<span class="no-findings">No findings</span>'}
                        </li>
                    `).join('');
                }
                
                async function loadScanDetail(scanId) {
                    const response = await fetch(`/api/scan/${scanId}`);
                    const scan = await response.json();
                    const detail = document.getElementById('scan-detail');
                    const withFindings = scan.results.filter(r => r.accessible && r.findings && r.findings.length > 0);
                    
                    detail.style.display = 'block';
                    detail.innerHTML = `
                        <h3>Scan Details: ${scan.target}</h3>
                        <p><strong>Scan ID:</strong> ${scan.scan_id}</p>
                        <p><strong>Timestamp:</strong> ${scan.timestamp}</p>
                        <p><strong>Total Scanned:</strong> ${scan.total_scanned}</p>
                        <p><strong>Accessible:</strong> ${scan.accessible_count}</p>
                        <p><strong>Findings:</strong> ${scan.findings_count}</p>
                        <h4>Findings:</h4>
                        ${withFindings.length > 0 ? withFindings.map(result => `
                            <div class="finding-item">
                                <strong>${result.url}</strong> (Status: ${result.status})<br>
                                ${result.findings.map(f => `
                                    <div style="margin-top: 10px;">
                                        <span class="severity severity-${f.severity}">${f.severity}</span>: 
                                        ${f.description}<br>
                                        <small>Plugin: ${f.plugin}</small>
                                    </div>
                                `).join('')}
                            </div>
                        `).join('') : '<p>No findings detected.</p>'}
                    `;
                    detail.scrollIntoView({ behavior: 'smooth' });
                }
                
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
        """Serve list of scans as JSON."""
        scans = self.result_manager.list_scans()
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(scans).encode())
    
    def serve_scan_detail(self, scan_id: str):
        """Serve detailed scan information as JSON.
        
        Args:
            scan_id: ID of scan to retrieve
        """
        scan_data = self.result_manager.load_results(scan_id)
        
        if scan_data:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(scan_data).encode())
        else:
            self.send_error(404, 'Scan not found')
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"{self.address_string()} - {format % args}")


class Dashboard:
    """Dashboard server for viewing scan results."""
    
    def __init__(self, result_manager, port: int = 8080):
        """Initialize dashboard.
        
        Args:
            result_manager: ResultManager instance
            port: Port to run dashboard on
        """
        self.result_manager = result_manager
        self.port = port
        self.server = None
    
    def start(self):
        """Start the dashboard server."""
        # Create handler class with result_manager bound
        handler = lambda *args, **kwargs: DashboardHandler(
            *args, result_manager=self.result_manager, **kwargs
        )
        
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
        """Stop the dashboard server."""
        if self.server:
            self.server.shutdown()
            logger.info("Dashboard stopped")
