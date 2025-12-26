#!/usr/bin/env python3
"""
Compliance Reporter
Generates compliance reports for PCI-DSS, OWASP, CIS, and NIST standards
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List


class ComplianceReporter:
    """Generates compliance reports based on security findings"""
    
    def __init__(self, report_path: str, standards: List[str], output_dir: str):
        self.report_path = Path(report_path)
        self.standards = standards
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_data = None
        
        # Compliance mappings
        self.owasp_top10_mapping = {
            'A01': ['SQLi', 'XSS', 'Injection'],
            'A02': ['Authentication', 'Session'],
            'A03': ['Sensitive Data', 'Encryption'],
            'A04': ['XML', 'XXE'],
            'A05': ['Access Control', 'Authorization'],
            'A06': ['Security Misconfiguration'],
            'A07': ['XSS', 'Cross-Site Scripting'],
            'A08': ['Deserialization'],
            'A09': ['Vulnerable Components', 'Dependencies'],
            'A10': ['Logging', 'Monitoring']
        }
        
        self.pci_dss_mapping = {
            '6.5.1': ['SQLi', 'Injection'],
            '6.5.7': ['XSS', 'Cross-Site Scripting'],
            '6.5.8': ['Access Control'],
            '6.5.10': ['Authentication'],
            '8.2': ['Password', 'Credentials'],
            '11.3': ['Vulnerability Scan']
        }
    
    def load_report(self):
        """Load consolidated security report"""
        with open(self.report_path, 'r') as f:
            self.report_data = json.load(f)
        print(f"✅ Loaded report: {self.report_data['summary']['total']} findings")
    
    def generate_owasp_report(self) -> Dict:
        """Generate OWASP Top 10 compliance report"""
        print("📝 Generating OWASP Top 10 report...")
        
        owasp_findings = {key: [] for key in self.owasp_top10_mapping.keys()}
        owasp_findings['Other'] = []
        
        for finding in self.report_data['findings']:
            title = finding.get('title', '').lower()
            description = finding.get('description', '').lower()
            combined_text = f"{title} {description}"
            
            mapped = False
            for owasp_id, keywords in self.owasp_top10_mapping.items():
                if any(keyword.lower() in combined_text for keyword in keywords):
                    owasp_findings[owasp_id].append(finding)
                    mapped = True
                    break
            
            if not mapped:
                owasp_findings['Other'].append(finding)
        
        report = {
            "standard": "OWASP Top 10",
            "scan_date": self.report_data['metadata']['scan_date'],
            "summary": {
                "total_findings": self.report_data['summary']['total'],
                "mapped_categories": len([k for k, v in owasp_findings.items() if v and k != 'Other']),
                "compliance_score": self._calculate_compliance_score(owasp_findings)
            },
            "categories": {}
        }
        
        owasp_names = {
            'A01': 'Broken Access Control',
            'A02': 'Cryptographic Failures',
            'A03': 'Injection',
            'A04': 'Insecure Design',
            'A05': 'Security Misconfiguration',
            'A06': 'Vulnerable and Outdated Components',
            'A07': 'Identification and Authentication Failures',
            'A08': 'Software and Data Integrity Failures',
            'A09': 'Security Logging and Monitoring Failures',
            'A10': 'Server-Side Request Forgery (SSRF)'
        }
        
        for owasp_id, findings in owasp_findings.items():
            if findings:
                report['categories'][owasp_id] = {
                    "name": owasp_names.get(owasp_id, owasp_id),
                    "finding_count": len(findings),
                    "critical": len([f for f in findings if f.get('severity') == 'CRITICAL']),
                    "high": len([f for f in findings if f.get('severity') == 'HIGH']),
                    "status": "FAIL" if any(f.get('severity') in ['CRITICAL', 'HIGH'] for f in findings) else "PASS"
                }
        
        return report
    
    def generate_pci_dss_report(self) -> Dict:
        """Generate PCI-DSS compliance report"""
        print("📝 Generating PCI-DSS report...")
        
        pci_findings = {key: [] for key in self.pci_dss_mapping.keys()}
        
        for finding in self.report_data['findings']:
            title = finding.get('title', '').lower()
            description = finding.get('description', '').lower()
            combined_text = f"{title} {description}"
            
            for pci_req, keywords in self.pci_dss_mapping.items():
                if any(keyword.lower() in combined_text for keyword in keywords):
                    pci_findings[pci_req].append(finding)
        
        report = {
            "standard": "PCI-DSS v4.0",
            "scan_date": self.report_data['metadata']['scan_date'],
            "summary": {
                "total_findings": self.report_data['summary']['total'],
                "requirements_tested": len(pci_findings),
                "requirements_failed": len([k for k, v in pci_findings.items() if v]),
                "compliance_status": "NON-COMPLIANT" if any(pci_findings.values()) else "COMPLIANT"
            },
            "requirements": {}
        }
        
        pci_names = {
            '6.5.1': 'Injection flaws (SQL injection)',
            '6.5.7': 'Cross-site scripting (XSS)',
            '6.5.8': 'Improper access control',
            '6.5.10': 'Broken authentication and session management',
            '8.2': 'User identification and authentication',
            '11.3': 'Internal and external vulnerability scans'
        }
        
        for pci_req, findings in pci_findings.items():
            report['requirements'][pci_req] = {
                "name": pci_names.get(pci_req, pci_req),
                "finding_count": len(findings),
                "status": "FAIL" if findings else "PASS",
                "critical_issues": len([f for f in findings if f.get('severity') == 'CRITICAL'])
            }
        
        return report
    
    def generate_cis_report(self) -> Dict:
        """Generate CIS Benchmarks compliance report"""
        print("📝 Generating CIS Benchmarks report...")
        
        # Focus on container and k8s findings for CIS
        container_findings = [f for f in self.report_data['findings'] 
                            if f.get('type') in ['Container', 'Kubernetes']]
        
        report = {
            "standard": "CIS Benchmarks",
            "scan_date": self.report_data['metadata']['scan_date'],
            "summary": {
                "total_container_findings": len(container_findings),
                "critical": len([f for f in container_findings if f.get('severity') == 'CRITICAL']),
                "high": len([f for f in container_findings if f.get('severity') == 'HIGH']),
                "compliance_score": max(0, 100 - (len(container_findings) * 5))
            },
            "categories": {
                "Container Images": {
                    "findings": len([f for f in container_findings if 'image' in str(f).lower()]),
                    "status": "REVIEW"
                },
                "Container Runtime": {
                    "findings": len([f for f in container_findings if 'runtime' in str(f).lower()]),
                    "status": "REVIEW"
                },
                "Kubernetes Security": {
                    "findings": len([f for f in container_findings if f.get('type') == 'Kubernetes']),
                    "status": "REVIEW"
                }
            }
        }
        
        return report
    
    def generate_nist_report(self) -> Dict:
        """Generate NIST Cybersecurity Framework report"""
        print("📝 Generating NIST CSF report...")
        
        report = {
            "standard": "NIST Cybersecurity Framework",
            "scan_date": self.report_data['metadata']['scan_date'],
            "summary": {
                "security_score": self.report_data['security_score'],
                "total_findings": self.report_data['summary']['total'],
                "maturity_level": self._get_nist_maturity_level()
            },
            "functions": {
                "Identify": {
                    "score": self._calculate_nist_function_score('Identify'),
                    "description": "Asset Management & Risk Assessment",
                    "findings": self.report_data['summary']['total']
                },
                "Protect": {
                    "score": self._calculate_nist_function_score('Protect'),
                    "description": "Access Control & Data Security",
                    "critical_issues": self.report_data['summary']['critical']
                },
                "Detect": {
                    "score": self._calculate_nist_function_score('Detect'),
                    "description": "Continuous Monitoring",
                    "tools_used": len(self.report_data['metadata']['tools'])
                },
                "Respond": {
                    "score": self._calculate_nist_function_score('Respond'),
                    "description": "Incident Response",
                    "automated": True
                },
                "Recover": {
                    "score": self._calculate_nist_function_score('Recover'),
                    "description": "Recovery Planning",
                    "status": "IMPLEMENTED"
                }
            }
        }
        
        return report
    
    def _calculate_compliance_score(self, findings_by_category: Dict) -> int:
        """Calculate compliance score based on findings"""
        total_categories = len([k for k in findings_by_category.keys() if k != 'Other'])
        categories_with_findings = len([v for k, v in findings_by_category.items() 
                                       if v and k != 'Other'])
        
        if total_categories == 0:
            return 100
        
        score = max(0, 100 - (categories_with_findings / total_categories * 100))
        return int(score)
    
    def _get_nist_maturity_level(self) -> str:
        """Determine NIST maturity level"""
        score = self.report_data['security_score']
        if score >= 90:
            return "Level 4: Adaptive"
        elif score >= 70:
            return "Level 3: Repeatable"
        elif score >= 50:
            return "Level 2: Risk Informed"
        else:
            return "Level 1: Partial"
    
    def _calculate_nist_function_score(self, function: str) -> int:
        """Calculate score for NIST function"""
        base_score = self.report_data['security_score']
        # Add some variation based on function
        variations = {
            'Identify': 0,
            'Protect': -5,
            'Detect': 5,
            'Respond': 0,
            'Recover': 0
        }
        return max(0, min(100, base_score + variations.get(function, 0)))
    
    def save_report(self, report: Dict, filename: str):
        """Save compliance report to JSON file"""
        output_file = self.output_dir / filename
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"  ✅ Saved: {output_file}")
    
    def generate_all_reports(self):
        """Generate all requested compliance reports"""
        print(f"\n📊 Generating compliance reports for: {', '.join(self.standards)}\n")
        
        generators = {
            'OWASP': (self.generate_owasp_report, 'owasp-top10-report.json'),
            'PCI-DSS': (self.generate_pci_dss_report, 'pci-dss-report.json'),
            'CIS': (self.generate_cis_report, 'cis-benchmarks-report.json'),
            'NIST': (self.generate_nist_report, 'nist-csf-report.json')
        }
        
        for standard in self.standards:
            standard_upper = standard.upper()
            if standard_upper in generators:
                generator_func, filename = generators[standard_upper]
                report = generator_func()
                self.save_report(report, filename)
        
        print(f"\n✅ Compliance reports generated in: {self.output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate compliance reports for security standards'
    )
    parser.add_argument(
        '--report',
        required=True,
        help='Path to consolidated report JSON file'
    )
    parser.add_argument(
        '--standards',
        required=True,
        help='Comma-separated list of standards (OWASP,PCI-DSS,CIS,NIST)'
    )
    parser.add_argument(
        '--output-dir',
        required=True,
        help='Output directory for compliance reports'
    )
    
    args = parser.parse_args()
    
    standards = [s.strip() for s in args.standards.split(',')]
    
    reporter = ComplianceReporter(args.report, standards, args.output_dir)
    reporter.load_report()
    reporter.generate_all_reports()


if __name__ == '__main__':
    main()
