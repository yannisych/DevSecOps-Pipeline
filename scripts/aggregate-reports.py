#!/usr/bin/env python3
"""
Security Reports Aggregator
Consolidates multiple security scan results into a unified report
"""

import json
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import glob


class SecurityReportAggregator:
    """Aggregates security reports from various scanning tools"""
    
    def __init__(self, input_dir: str, output_dir: str):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.consolidated_report = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "version": "1.0",
                "tools": []
            },
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0
            },
            "findings": [],
            "tool_reports": {}
        }
    
    def parse_sonarqube_report(self, filepath: Path) -> Dict:
        """Parse SonarQube JSON report"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            findings = []
            for issue in data.get('issues', []):
                severity = self._map_severity(issue.get('severity', 'INFO'))
                findings.append({
                    "tool": "SonarQube",
                    "type": "SAST",
                    "severity": severity,
                    "title": issue.get('message', 'Unknown issue'),
                    "description": issue.get('message', ''),
                    "file": issue.get('component', ''),
                    "line": issue.get('line', 0),
                    "rule": issue.get('rule', ''),
                    "remediation": issue.get('debt', 'No remediation available')
                })
                self._increment_severity(severity)
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            print(f"Warning: Failed to parse SonarQube report: {e}")
            return {"findings": [], "count": 0}
    
    def parse_dependency_check_report(self, filepath: Path) -> Dict:
        """Parse OWASP Dependency-Check JSON report"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            findings = []
            for dependency in data.get('dependencies', []):
                for vuln in dependency.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'MEDIUM').upper()
                    findings.append({
                        "tool": "OWASP Dependency-Check",
                        "type": "SCA",
                        "severity": severity,
                        "title": vuln.get('name', 'Unknown vulnerability'),
                        "description": vuln.get('description', ''),
                        "cve": vuln.get('name', ''),
                        "cvss": vuln.get('cvssv3', {}).get('baseScore', 0),
                        "dependency": dependency.get('fileName', ''),
                        "remediation": f"Update to version {vuln.get('fixedVersion', 'latest')}"
                    })
                    self._increment_severity(severity)
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            print(f"Warning: Failed to parse Dependency-Check report: {e}")
            return {"findings": [], "count": 0}
    
    def parse_trivy_report(self, filepath: Path) -> Dict:
        """Parse Trivy JSON report"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            findings = []
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    severity = vuln.get('Severity', 'MEDIUM').upper()
                    findings.append({
                        "tool": "Trivy",
                        "type": "Container",
                        "severity": severity,
                        "title": vuln.get('Title', vuln.get('VulnerabilityID', 'Unknown')),
                        "description": vuln.get('Description', ''),
                        "cve": vuln.get('VulnerabilityID', ''),
                        "cvss": vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0),
                        "package": vuln.get('PkgName', ''),
                        "installed_version": vuln.get('InstalledVersion', ''),
                        "fixed_version": vuln.get('FixedVersion', 'Not available'),
                        "remediation": f"Update {vuln.get('PkgName', '')} to {vuln.get('FixedVersion', 'latest')}"
                    })
                    self._increment_severity(severity)
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            print(f"Warning: Failed to parse Trivy report: {e}")
            return {"findings": [], "count": 0}
    
    def parse_trufflehog_report(self, filepath: Path) -> Dict:
        """Parse TruffleHog JSON report"""
        try:
            findings = []
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        findings.append({
                            "tool": "TruffleHog",
                            "type": "Secrets",
                            "severity": "CRITICAL",
                            "title": f"Exposed secret: {data.get('detector_name', 'Unknown')}",
                            "description": f"Secret detected in {data.get('source_name', 'unknown source')}",
                            "file": data.get('source_metadata', {}).get('file', ''),
                            "line": data.get('source_metadata', {}).get('line', 0),
                            "secret_type": data.get('detector_name', 'Unknown'),
                            "verified": data.get('verified', False),
                            "remediation": "Rotate the exposed secret immediately and remove from git history"
                        })
                        self._increment_severity("CRITICAL")
                    except json.JSONDecodeError:
                        continue
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            print(f"Warning: Failed to parse TruffleHog report: {e}")
            return {"findings": [], "count": 0}
    
    def parse_zap_report(self, filepath: Path) -> Dict:
        """Parse OWASP ZAP JSON report"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            findings = []
            for site in data.get('site', []):
                for alert in site.get('alerts', []):
                    risk = alert.get('riskcode', '2')
                    severity = self._map_zap_risk(risk)
                    
                    findings.append({
                        "tool": "OWASP ZAP",
                        "type": "DAST",
                        "severity": severity,
                        "title": alert.get('name', 'Unknown'),
                        "description": alert.get('desc', ''),
                        "url": alert.get('url', ''),
                        "risk": alert.get('risk', 'Medium'),
                        "confidence": alert.get('confidence', 'Medium'),
                        "cwe": alert.get('cweid', ''),
                        "solution": alert.get('solution', 'No solution available'),
                        "remediation": alert.get('solution', 'Review and fix the vulnerability')
                    })
                    self._increment_severity(severity)
            
            return {"findings": findings, "count": len(findings)}
        except Exception as e:
            print(f"Warning: Failed to parse ZAP report: {e}")
            return {"findings": [], "count": 0}
    
    def _map_severity(self, severity: str) -> str:
        """Map various severity formats to standard levels"""
        severity = severity.upper()
        mapping = {
            'BLOCKER': 'CRITICAL',
            'CRITICAL': 'CRITICAL',
            'MAJOR': 'HIGH',
            'HIGH': 'HIGH',
            'MINOR': 'MEDIUM',
            'MEDIUM': 'MEDIUM',
            'INFO': 'LOW',
            'LOW': 'LOW'
        }
        return mapping.get(severity, 'MEDIUM')
    
    def _map_zap_risk(self, risk_code: str) -> str:
        """Map ZAP risk codes to severity levels"""
        mapping = {
            '3': 'CRITICAL',
            '2': 'HIGH',
            '1': 'MEDIUM',
            '0': 'LOW'
        }
        return mapping.get(str(risk_code), 'MEDIUM')
    
    def _increment_severity(self, severity: str):
        """Increment severity counter"""
        severity = severity.lower()
        if severity in self.consolidated_report['summary']:
            self.consolidated_report['summary'][severity] += 1
            self.consolidated_report['summary']['total'] += 1
    
    def aggregate_all_reports(self):
        """Scan input directory and aggregate all reports"""
        print(f"🔍 Scanning for reports in: {self.input_dir}")
        
        # Define report patterns and parsers
        report_patterns = {
            '**/sonar*.json': self.parse_sonarqube_report,
            '**/dependency-check*.json': self.parse_dependency_check_report,
            '**/trivy*.json': self.parse_trivy_report,
            '**/trufflehog*.json': self.parse_trufflehog_report,
            '**/zap*.json': self.parse_zap_report,
        }
        
        for pattern, parser in report_patterns.items():
            files = list(self.input_dir.glob(pattern))
            for filepath in files:
                print(f"  📄 Processing: {filepath.name}")
                result = parser(filepath)
                
                tool_name = filepath.stem
                self.consolidated_report['tool_reports'][tool_name] = result
                self.consolidated_report['findings'].extend(result['findings'])
                
                if result['count'] > 0:
                    self.consolidated_report['metadata']['tools'].append(tool_name)
        
        # Calculate security score
        self.consolidated_report['security_score'] = self._calculate_security_score()
        
        print(f"\n✅ Aggregation complete:")
        print(f"   Total findings: {self.consolidated_report['summary']['total']}")
        print(f"   Critical: {self.consolidated_report['summary']['critical']}")
        print(f"   High: {self.consolidated_report['summary']['high']}")
        print(f"   Medium: {self.consolidated_report['summary']['medium']}")
        print(f"   Low: {self.consolidated_report['summary']['low']}")
        print(f"   Security Score: {self.consolidated_report['security_score']}/100")
    
    def _calculate_security_score(self) -> int:
        """Calculate overall security score (0-100)"""
        summary = self.consolidated_report['summary']
        
        # Weighted scoring (worse findings have higher penalty)
        penalties = {
            'critical': 20,
            'high': 10,
            'medium': 5,
            'low': 1
        }
        
        total_penalty = sum(summary[sev] * penalties[sev] for sev in penalties.keys())
        
        # Start from 100 and subtract penalties
        score = max(0, 100 - total_penalty)
        
        return score
    
    def save_consolidated_report(self):
        """Save consolidated report to JSON file"""
        output_file = self.output_dir / 'consolidated-report.json'
        
        with open(output_file, 'w') as f:
            json.dump(self.consolidated_report, f, indent=2)
        
        print(f"\n💾 Consolidated report saved: {output_file}")
        
        # Also create a summary text file
        self._save_summary_text()
    
    def _save_summary_text(self):
        """Save human-readable summary"""
        output_file = self.output_dir / 'security-summary.txt'
        
        summary = self.consolidated_report['summary']
        score = self.consolidated_report['security_score']
        
        with open(output_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("SECURITY SCAN SUMMARY\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Scan Date: {self.consolidated_report['metadata']['scan_date']}\n")
            f.write(f"Tools Used: {', '.join(self.consolidated_report['metadata']['tools'])}\n\n")
            f.write(f"Security Score: {score}/100\n\n")
            f.write(f"Total Findings: {summary['total']}\n")
            f.write(f"  🔴 Critical: {summary['critical']}\n")
            f.write(f"  🟠 High:     {summary['high']}\n")
            f.write(f"  🟡 Medium:   {summary['medium']}\n")
            f.write(f"  🟢 Low:      {summary['low']}\n")
            f.write("\n" + "=" * 60 + "\n")
        
        print(f"📄 Summary saved: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Aggregate security scan reports from multiple tools'
    )
    parser.add_argument(
        '--input-dir',
        required=True,
        help='Directory containing security scan reports'
    )
    parser.add_argument(
        '--output-dir',
        required=True,
        help='Directory to save consolidated reports'
    )
    
    args = parser.parse_args()
    
    aggregator = SecurityReportAggregator(args.input_dir, args.output_dir)
    aggregator.aggregate_all_reports()
    aggregator.save_consolidated_report()
    
    # Exit with error code if critical vulnerabilities found
    if aggregator.consolidated_report['summary']['critical'] > 0:
        print("\n⚠️  CRITICAL vulnerabilities detected!")
        sys.exit(1)
    
    print("\n✅ Aggregation completed successfully")
    sys.exit(0)


if __name__ == '__main__':
    main()
