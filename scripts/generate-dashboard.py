#!/usr/bin/env python3
"""
Security Dashboard Generator
Creates an interactive HTML dashboard from consolidated security reports
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List


class DashboardGenerator:
    """Generates interactive HTML security dashboard"""
    
    def __init__(self, report_path: str, output_path: str, theme: str = 'auto'):
        self.report_path = Path(report_path)
        self.output_path = Path(output_path)
        self.theme = theme
        self.report_data = None
    
    def load_report(self):
        """Load consolidated security report"""
        with open(self.report_path, 'r') as f:
            self.report_data = json.load(f)
        print(f"✅ Loaded report with {self.report_data['summary']['total']} findings")
    
    def generate_html(self) -> str:
        """Generate complete HTML dashboard"""
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard - {self.report_data['metadata']['scan_date'][:10]}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --critical: #f85149;
            --high: #ff8c42;
            --medium: #f1e05a;
            --low: #7ee787;
            --info: #58a6ff;
        }}
        
        [data-theme="light"] {{
            --bg-primary: #ffffff;
            --bg-secondary: #f6f8fa;
            --bg-tertiary: #ffffff;
            --text-primary: #24292f;
            --text-secondary: #57606a;
            --border-color: #d0d7de;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 0;
            margin-bottom: 30px;
        }}
        
        h1 {{
            font-size: 2rem;
            margin-bottom: 5px;
        }}
        
        .subtitle {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
        
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .theme-toggle {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
        }}
        
        .theme-toggle:hover {{
            background: var(--bg-tertiary);
        }}
        
        .search-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 8px 16px;
            border-radius: 6px;
            width: 300px;
            font-size: 0.9rem;
        }}
        
        .search-box:focus {{
            outline: 2px solid var(--info);
            outline-offset: 2px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            margin: 10px 0;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .score {{
            font-size: 3.5rem;
            font-weight: 700;
            margin: 20px 0;
        }}
        
        .score.excellent {{ color: var(--low); }}
        .score.good {{ color: var(--medium); }}
        .score.poor {{ color: var(--high); }}
        .score.critical {{ color: var(--critical); }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .chart-container {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }}
        
        .chart-title {{
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 15px;
        }}
        
        .findings-table {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .table-header {{
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th {{
            text-align: left;
            padding: 12px 20px;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            font-size: 0.9rem;
        }}
        
        td {{
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        tr:hover {{
            background: var(--bg-tertiary);
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: var(--critical); color: white; }}
        .severity-high {{ background: var(--high); color: white; }}
        .severity-medium {{ background: var(--medium); color: #000; }}
        .severity-low {{ background: var(--low); color: #000; }}
        
        .tool-badge {{
            display: inline-block;
            padding: 4px 10px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 0.8rem;
            margin-right: 5px;
        }}
        
        .filter-buttons {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        
        .filter-btn {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
        }}
        
        .filter-btn:hover {{
            background: var(--bg-tertiary);
        }}
        
        .filter-btn.active {{
            background: var(--info);
            color: white;
            border-color: var(--info);
        }}
        
        .hidden {{
            display: none;
        }}
        
        footer {{
            text-align: center;
            margin-top: 50px;
            padding: 30px 0;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body data-theme="dark">
    <header>
        <div class="container">
            <h1>🔐 Security Dashboard</h1>
            <div class="subtitle">Generated on {self.report_data['metadata']['scan_date']}</div>
        </div>
    </header>

    <div class="container">
        <div class="controls">
            <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search findings...">
            <button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Theme</button>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Security Score</div>
                <div class="score {self._get_score_class()}">{self.report_data['security_score']}/100</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{self.report_data['summary']['total']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical Issues</div>
                <div class="stat-value" style="color: var(--critical)">{self.report_data['summary']['critical']}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Issues</div>
                <div class="stat-value" style="color: var(--high)">{self.report_data['summary']['high']}</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-container">
                <div class="chart-title">Severity Distribution</div>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">Findings by Tool</div>
                <canvas id="toolChart"></canvas>
            </div>
        </div>

        <div class="findings-table">
            <div class="table-header">
                <div class="chart-title">Security Findings</div>
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical</button>
                    <button class="filter-btn" onclick="filterFindings('HIGH')">High</button>
                    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium</button>
                    <button class="filter-btn" onclick="filterFindings('LOW')">Low</button>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Tool</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>File/Location</th>
                    </tr>
                </thead>
                <tbody id="findingsTableBody">
                    {self._generate_findings_rows()}
                </tbody>
            </table>
        </div>
    </div>

    <footer>
        <p>DevSecOps Security Pipeline Dashboard</p>
        <p style="margin-top: 10px; font-size: 0.85rem;">
            Tools: {', '.join(self.report_data['metadata']['tools'])}
        </p>
    </footer>

    <script>
        const findingsData = {json.dumps(self.report_data['findings'])};
        
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [
                        {self.report_data['summary']['critical']},
                        {self.report_data['summary']['high']},
                        {self.report_data['summary']['medium']},
                        {self.report_data['summary']['low']}
                    ],
                    backgroundColor: [
                        '#f85149',
                        '#ff8c42',
                        '#f1e05a',
                        '#7ee787'
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            color: getComputedStyle(document.body).getPropertyValue('--text-primary'),
                            padding: 15
                        }}
                    }}
                }}
            }}
        }});
        
        // Tool Chart
        const toolCounts = {json.dumps(self._get_tool_counts())};
        const toolCtx = document.getElementById('toolChart').getContext('2d');
        new Chart(toolCtx, {{
            type: 'bar',
            data: {{
                labels: Object.keys(toolCounts),
                datasets: [{{
                    label: 'Findings',
                    data: Object.values(toolCounts),
                    backgroundColor: '#58a6ff',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            color: getComputedStyle(document.body).getPropertyValue('--text-secondary')
                        }},
                        grid: {{
                            color: getComputedStyle(document.body).getPropertyValue('--border-color')
                        }}
                    }},
                    x: {{
                        ticks: {{
                            color: getComputedStyle(document.body).getPropertyValue('--text-secondary')
                        }},
                        grid: {{
                            display: false
                        }}
                    }}
                }}
            }}
        }});
        
        // Theme toggle
        function toggleTheme() {{
            const body = document.body;
            const currentTheme = body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            body.setAttribute('data-theme', newTheme);
        }}
        
        // Search functionality
        document.getElementById('searchBox').addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            const rows = document.querySelectorAll('#findingsTableBody tr');
            
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            }});
        }});
        
        // Filter functionality
        let currentFilter = 'all';
        function filterFindings(severity) {{
            currentFilter = severity;
            const rows = document.querySelectorAll('#findingsTableBody tr');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            rows.forEach(row => {{
                if (severity === 'all') {{
                    row.style.display = '';
                }} else {{
                    const rowSeverity = row.getAttribute('data-severity');
                    row.style.display = rowSeverity === severity ? '' : 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""
        
        return html_template
    
    def _get_score_class(self) -> str:
        """Get CSS class based on security score"""
        score = self.report_data['security_score']
        if score >= 90:
            return 'excellent'
        elif score >= 70:
            return 'good'
        elif score >= 50:
            return 'poor'
        else:
            return 'critical'
    
    def _get_tool_counts(self) -> Dict[str, int]:
        """Count findings per tool"""
        tool_counts = {}
        for finding in self.report_data['findings']:
            tool = finding.get('tool', 'Unknown')
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        return tool_counts
    
    def _generate_findings_rows(self) -> str:
        """Generate HTML table rows for findings"""
        rows = []
        for i, finding in enumerate(self.report_data['findings'][:100]):  # Limit to first 100
            severity = finding.get('severity', 'MEDIUM')
            tool = finding.get('tool', 'Unknown')
            finding_type = finding.get('type', 'Unknown')
            title = finding.get('title', 'No title')
            location = finding.get('file', finding.get('url', finding.get('dependency', 'N/A')))
            
            rows.append(f"""
                <tr data-severity="{severity}">
                    <td><span class="severity-badge severity-{severity.lower()}">{severity}</span></td>
                    <td><span class="tool-badge">{tool}</span></td>
                    <td>{finding_type}</td>
                    <td>{title[:80]}...</td>
                    <td>{location[:50] if location else 'N/A'}</td>
                </tr>
            """)
        
        if len(self.report_data['findings']) > 100:
            rows.append(f"""
                <tr>
                    <td colspan="5" style="text-align: center; padding: 20px; color: var(--text-secondary);">
                        Showing first 100 of {len(self.report_data['findings'])} findings. 
                        Download full report for complete list.
                    </td>
                </tr>
            """)
        
        return ''.join(rows)
    
    def save_dashboard(self):
        """Save generated dashboard to file"""
        html_content = self.generate_html()
        
        with open(self.output_path, 'w') as f:
            f.write(html_content)
        
        print(f"✅ Dashboard generated: {self.output_path}")
        print(f"📊 Open in browser: file://{self.output_path.absolute()}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate interactive security dashboard from consolidated report'
    )
    parser.add_argument(
        '--report',
        required=True,
        help='Path to consolidated report JSON file'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output path for HTML dashboard'
    )
    parser.add_argument(
        '--theme',
        default='auto',
        choices=['light', 'dark', 'auto'],
        help='Dashboard theme'
    )
    
    args = parser.parse_args()
    
    generator = DashboardGenerator(args.report, args.output, args.theme)
    generator.load_report()
    generator.save_dashboard()


if __name__ == '__main__':
    main()
