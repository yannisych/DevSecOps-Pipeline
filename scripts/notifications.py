#!/usr/bin/env python3
"""
Multi-Channel Notification System
Sends security scan results to Slack, Teams, Email, and GitHub Issues
"""

import json
import os
import argparse
from pathlib import Path
from typing import Dict, List
import requests
from datetime import datetime


class NotificationService:
    """Handles multi-channel notifications for security scan results"""
    
    def __init__(self, report_path: str):
        self.report_path = Path(report_path)
        self.report_data = None
        self.config = {
            'slack_webhook': os.getenv('SLACK_WEBHOOK'),
            'teams_webhook': os.getenv('TEAMS_WEBHOOK'),
            'sendgrid_api_key': os.getenv('SENDGRID_API_KEY'),
            'github_token': os.getenv('GITHUB_TOKEN'),
            'github_repo': os.getenv('GITHUB_REPOSITORY')
        }
    
    def load_report(self):
        """Load consolidated security report"""
        with open(self.report_path, 'r') as f:
            self.report_data = json.load(f)
        print(f"✅ Loaded report: {self.report_data['summary']['total']} findings")
    
    def send_slack_notification(self) -> bool:
        """Send notification to Slack"""
        if not self.config['slack_webhook']:
            print("⏭️  Slack webhook not configured, skipping")
            return False
        
        summary = self.report_data['summary']
        score = self.report_data['security_score']
        
        # Choose color based on severity
        if summary['critical'] > 0:
            color = "#f85149"
            status = "CRITICAL"
        elif summary['high'] > 0:
            color = "#ff8c42"
            status = "WARNING"
        else:
            color = "#7ee787"
            status = "PASSED"
        
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🔐 Security Scan Complete - {status}",
                "text": f"Security Score: *{score}/100*",
                "fields": [
                    {
                        "title": "Critical",
                        "value": str(summary['critical']),
                        "short": True
                    },
                    {
                        "title": "High",
                        "value": str(summary['high']),
                        "short": True
                    },
                    {
                        "title": "Medium",
                        "value": str(summary['medium']),
                        "short": True
                    },
                    {
                        "title": "Low",
                        "value": str(summary['low']),
                        "short": True
                    },
                    {
                        "title": "Total Findings",
                        "value": str(summary['total']),
                        "short": True
                    },
                    {
                        "title": "Tools Used",
                        "value": ", ".join(self.report_data['metadata']['tools']),
                        "short": False
                    }
                ],
                "footer": "DevSecOps Pipeline",
                "ts": int(datetime.now().timestamp())
            }]
        }
        
        try:
            response = requests.post(
                self.config['slack_webhook'],
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            print("✅ Slack notification sent")
            return True
        except Exception as e:
            print(f"❌ Failed to send Slack notification: {e}")
            return False
    
    def send_teams_notification(self) -> bool:
        """Send notification to Microsoft Teams"""
        if not self.config['teams_webhook']:
            print("⏭️  Teams webhook not configured, skipping")
            return False
        
        summary = self.report_data['summary']
        score = self.report_data['security_score']
        
        # Adaptive Card format
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": "Security Scan Results",
            "sections": [{
                "activityTitle": "🔐 Security Scan Complete",
                "activitySubtitle": f"Score: {score}/100",
                "facts": [
                    {"name": "Critical", "value": str(summary['critical'])},
                    {"name": "High", "value": str(summary['high'])},
                    {"name": "Medium", "value": str(summary['medium'])},
                    {"name": "Low", "value": str(summary['low'])},
                    {"name": "Total", "value": str(summary['total'])}
                ],
                "markdown": True
            }]
        }
        
        try:
            response = requests.post(
                self.config['teams_webhook'],
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            print("✅ Teams notification sent")
            return True
        except Exception as e:
            print(f"❌ Failed to send Teams notification: {e}")
            return False
    
    def send_email_notification(self, recipients: List[str]) -> bool:
        """Send email notification via SendGrid"""
        if not self.config['sendgrid_api_key']:
            print("⏭️  SendGrid API key not configured, skipping")
            return False
        
        summary = self.report_data['summary']
        score = self.report_data['security_score']
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background: #0d1117; color: white; padding: 20px; }}
                .content {{ padding: 20px; }}
                .stat {{ display: inline-block; margin: 10px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .critical {{ color: #f85149; font-weight: bold; }}
                .high {{ color: #ff8c42; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 Security Scan Results</h1>
            </div>
            <div class="content">
                <h2>Security Score: {score}/100</h2>
                <p>Scan completed on {self.report_data['metadata']['scan_date']}</p>
                
                <div>
                    <div class="stat">
                        <div class="critical">Critical: {summary['critical']}</div>
                    </div>
                    <div class="stat">
                        <div class="high">High: {summary['high']}</div>
                    </div>
                    <div class="stat">
                        <div>Medium: {summary['medium']}</div>
                    </div>
                    <div class="stat">
                        <div>Low: {summary['low']}</div>
                    </div>
                </div>
                
                <h3>Tools Used:</h3>
                <p>{', '.join(self.report_data['metadata']['tools'])}</p>
                
                <p>Please review the full dashboard for detailed findings.</p>
            </div>
        </body>
        </html>
        """
        
        payload = {
            "personalizations": [
                {
                    "to": [{"email": email} for email in recipients],
                    "subject": f"Security Scan Results - Score: {score}/100"
                }
            ],
            "from": {"email": "security@yourdomain.com", "name": "DevSecOps Pipeline"},
            "content": [
                {
                    "type": "text/html",
                    "value": html_content
                }
            ]
        }
        
        headers = {
            "Authorization": f"Bearer {self.config['sendgrid_api_key']}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers=headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            print(f"✅ Email sent to {len(recipients)} recipients")
            return True
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False
    
    def create_github_issue(self) -> bool:
        """Create GitHub issue if critical vulnerabilities found"""
        if not self.config['github_token'] or not self.config['github_repo']:
            print("⏭️  GitHub credentials not configured, skipping")
            return False
        
        summary = self.report_data['summary']
        
        # Only create issue if critical or high vulnerabilities found
        if summary['critical'] == 0 and summary['high'] == 0:
            print("⏭️  No critical/high vulnerabilities, skipping GitHub issue")
            return False
        
        title = f"🚨 Security Alert: {summary['critical']} Critical, {summary['high']} High Vulnerabilities"
        
        body = f"""## Security Scan Results
        
**Scan Date:** {self.report_data['metadata']['scan_date']}
**Security Score:** {self.report_data['security_score']}/100

### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary['critical']} |
| 🟠 High | {summary['high']} |
| 🟡 Medium | {summary['medium']} |
| 🟢 Low | {summary['low']} |
| **Total** | **{summary['total']}** |

### Tools Used

{', '.join(self.report_data['metadata']['tools'])}

### Action Required

Please review the security dashboard and address the critical and high severity findings immediately.

---
*This issue was automatically created by the DevSecOps Pipeline*
"""
        
        api_url = f"https://api.github.com/repos/{self.config['github_repo']}/issues"
        
        payload = {
            "title": title,
            "body": body,
            "labels": ["security", "automated", "urgent"]
        }
        
        headers = {
            "Authorization": f"token {self.config['github_token']}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.post(
                api_url,
                headers=headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            issue_url = response.json()['html_url']
            print(f"✅ GitHub issue created: {issue_url}")
            return True
        except Exception as e:
            print(f"❌ Failed to create GitHub issue: {e}")
            return False
    
    def send_all_notifications(self, email_recipients: List[str] = None):
        """Send notifications to all configured channels"""
        print("\n📢 Sending notifications...")
        
        results = {
            'slack': self.send_slack_notification(),
            'teams': self.send_teams_notification(),
            'github': self.create_github_issue()
        }
        
        if email_recipients:
            results['email'] = self.send_email_notification(email_recipients)
        
        print(f"\n📊 Notification Summary:")
        for channel, success in results.items():
            status = "✅ Sent" if success else "❌ Failed"
            print(f"  {channel.capitalize()}: {status}")


def main():
    parser = argparse.ArgumentParser(
        description='Send security scan notifications to multiple channels'
    )
    parser.add_argument(
        '--report',
        required=True,
        help='Path to consolidated report JSON file'
    )
    parser.add_argument(
        '--recipients',
        help='Comma-separated list of email recipients'
    )
    parser.add_argument(
        '--type',
        choices=['slack', 'teams', 'email', 'github', 'all'],
        default='all',
        help='Notification channel to use'
    )
    
    args = parser.parse_args()
    
    service = NotificationService(args.report)
    service.load_report()
    
    email_list = args.recipients.split(',') if args.recipients else None
    
    if args.type == 'slack':
        service.send_slack_notification()
    elif args.type == 'teams':
        service.send_teams_notification()
    elif args.type == 'email' and email_list:
        service.send_email_notification(email_list)
    elif args.type == 'github':
        service.create_github_issue()
    else:
        service.send_all_notifications(email_list)


if __name__ == '__main__':
    main()
