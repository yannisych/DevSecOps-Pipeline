#!/usr/bin/env python3
"""
Automatic Vulnerability Remediation
Analyzes security findings and creates automated fixes
"""

import json
import os
import argparse
import re
from pathlib import Path
from typing import Dict, List, Tuple
import subprocess


class AutoRemediator:
    """Automatically fixes common security vulnerabilities"""
    
    def __init__(self, report_path: str, output_dir: str):
        self.report_path = Path(report_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_data = None
        self.fixes_applied = []
        
        # Remediation rules
        self.remediation_rules = {
            'dependency': self._fix_vulnerable_dependency,
            'dockerfile': self._fix_dockerfile_issues,
            'secrets': self._fix_exposed_secrets,
            'security_headers': self._add_security_headers,
            'weak_crypto': self._fix_weak_cryptography
        }
    
    def load_report(self):
        """Load consolidated security report"""
        with open(self.report_path, 'r') as f:
            self.report_data = json.load(f)
        print(f"✅ Loaded report: {self.report_data['summary']['total']} findings")
    
    def analyze_fixable_issues(self) -> List[Dict]:
        """Identify automatically fixable security issues"""
        fixable = []
        
        for finding in self.report_data['findings']:
            fix_type = self._determine_fix_type(finding)
            if fix_type:
                fixable.append({
                    'finding': finding,
                    'fix_type': fix_type,
                    'confidence': self._calculate_fix_confidence(finding)
                })
        
        print(f"🔍 Found {len(fixable)} potentially fixable issues")
        return fixable
    
    def _determine_fix_type(self, finding: Dict) -> str:
        """Determine the type of fix needed"""
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        finding_type = finding.get('type', '')
        
        # Dependency updates
        if 'dependency' in title or 'outdated' in title or finding_type == 'SCA':
            if finding.get('fixed_version'):
                return 'dependency'
        
        # Dockerfile fixes
        if finding_type == 'Container' and finding.get('file', '').endswith('Dockerfile'):
            return 'dockerfile'
        
        # Exposed secrets
        if finding_type == 'Secrets':
            return 'secrets'
        
        # Security headers
        if 'header' in title or 'csp' in title or 'hsts' in title:
            return 'security_headers'
        
        # Weak cryptography
        if 'md5' in title or 'sha1' in title or 'weak' in description and 'crypto' in description:
            return 'weak_crypto'
        
        return None
    
    def _calculate_fix_confidence(self, finding: Dict) -> str:
        """Calculate confidence level for automated fix"""
        # High confidence for dependency updates with known fixed version
        if finding.get('fixed_version') and finding.get('fixed_version') != 'Not available':
            return 'HIGH'
        
        # Medium confidence for Dockerfile fixes
        if finding.get('file', '').endswith('Dockerfile'):
            return 'MEDIUM'
        
        # Low confidence for other fixes
        return 'LOW'
    
    def _fix_vulnerable_dependency(self, finding: Dict) -> Tuple[bool, str]:
        """Update vulnerable dependencies"""
        package = finding.get('package') or finding.get('dependency')
        fixed_version = finding.get('fixed_version')
        
        if not package or not fixed_version or fixed_version == 'Not available':
            return False, "Missing package or fixed version information"
        
        # Detect package manager
        if Path('requirements.txt').exists():
            return self._update_python_dependency(package, fixed_version)
        elif Path('package.json').exists():
            return self._update_npm_dependency(package, fixed_version)
        elif Path('go.mod').exists():
            return self._update_go_dependency(package, fixed_version)
        
        return False, "Unsupported package manager"
    
    def _update_python_dependency(self, package: str, version: str) -> Tuple[bool, str]:
        """Update Python dependency in requirements.txt"""
        req_file = Path('requirements.txt')
        if not req_file.exists():
            return False, "requirements.txt not found"
        
        try:
            content = req_file.read_text()
            
            # Match package name (case-insensitive) with any version specifier
            pattern = re.compile(f'^{re.escape(package)}[>=<]=.*$', re.MULTILINE | re.IGNORECASE)
            
            if pattern.search(content):
                new_content = pattern.sub(f'{package}>={version}', content)
                
                # Save to fixes directory
                fix_file = self.output_dir / 'requirements.txt'
                fix_file.write_text(new_content)
                
                return True, f"Updated {package} to >={version}"
            else:
                return False, f"Package {package} not found in requirements.txt"
        
        except Exception as e:
            return False, f"Error updating dependency: {e}"
    
    def _update_npm_dependency(self, package: str, version: str) -> Tuple[bool, str]:
        """Update NPM dependency"""
        try:
            # Use npm to update specific package
            result = subprocess.run(
                ['npm', 'install', f'{package}@{version}', '--save'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return True, f"Updated {package} to {version}"
            else:
                return False, f"npm update failed: {result.stderr}"
        
        except Exception as e:
            return False, f"Error updating npm dependency: {e}"
    
    def _update_go_dependency(self, package: str, version: str) -> Tuple[bool, str]:
        """Update Go dependency"""
        try:
            result = subprocess.run(
                ['go', 'get', f'{package}@{version}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return True, f"Updated {package} to {version}"
            else:
                return False, f"go get failed: {result.stderr}"
        
        except Exception as e:
            return False, f"Error updating go dependency: {e}"
    
    def _fix_dockerfile_issues(self, finding: Dict) -> Tuple[bool, str]:
        """Fix common Dockerfile security issues"""
        dockerfile = finding.get('file')
        if not dockerfile or not Path(dockerfile).exists():
            return False, "Dockerfile not found"
        
        try:
            content = Path(dockerfile).read_text()
            original_content = content
            fixes = []
            
            # Add USER instruction if missing (don't run as root)
            if 'USER' not in content and 'FROM' in content:
                # Insert USER before CMD/ENTRYPOINT
                if 'CMD' in content:
                    content = content.replace('CMD', 'USER appuser\nCMD', 1)
                    fixes.append("Added non-root USER")
                elif 'ENTRYPOINT' in content:
                    content = content.replace('ENTRYPOINT', 'USER appuser\nENTRYPOINT', 1)
                    fixes.append("Added non-root USER")
            
            # Add HEALTHCHECK if missing
            if 'HEALTHCHECK' not in content:
                healthcheck = '\nHEALTHCHECK --interval=30s --timeout=3s --retries=3 \\\n  CMD curl -f http://localhost/ || exit 1\n'
                content = content.rstrip() + '\n' + healthcheck
                fixes.append("Added HEALTHCHECK")
            
            # Use --no-cache-dir for pip
            content = re.sub(
                r'pip install(?! --no-cache-dir)',
                'pip install --no-cache-dir',
                content
            )
            if 'pip install --no-cache-dir' in content and 'pip install --no-cache-dir' not in original_content:
                fixes.append("Added --no-cache-dir to pip")
            
            if content != original_content:
                # Save fixed Dockerfile
                fix_file = self.output_dir / Path(dockerfile).name
                fix_file.write_text(content)
                return True, f"Applied fixes: {', '.join(fixes)}"
            
            return False, "No applicable fixes found"
        
        except Exception as e:
            return False, f"Error fixing Dockerfile: {e}"
    
    def _fix_exposed_secrets(self, finding: Dict) -> Tuple[bool, str]:
        """Create warning file for exposed secrets"""
        # Can't automatically rotate secrets, but create instructions
        secret_type = finding.get('secret_type', 'Unknown')
        file_path = finding.get('file', 'Unknown')
        
        instructions = f"""# SECURITY ALERT: Exposed Secret Detected

**Type:** {secret_type}
**Location:** {file_path}
**Severity:** CRITICAL

## Immediate Actions Required:

1. **Rotate the Secret:**
   - Generate a new {secret_type}
   - Update all systems using this credential
   - Revoke the old credential

2. **Remove from Git History:**
   ```bash
   # Use BFG Repo-Cleaner or git-filter-repo
   git filter-branch --force --index-filter \\
     'git rm --cached --ignore-unmatch {file_path}' \\
     --prune-empty --tag-name-filter cat -- --all
   ```

3. **Add to .gitignore:**
   - Ensure secrets files are in .gitignore
   - Use environment variables instead

4. **Scan Again:**
   - Run secrets scanner after cleanup
   - Verify removal from git history

## Prevention:

- Use pre-commit hooks with secrets detection
- Store secrets in environment variables or secret managers
- Never commit API keys, passwords, or tokens

---
*This file was auto-generated by the security pipeline*
"""
        
        fix_file = self.output_dir / 'SECRET_ROTATION_REQUIRED.md'
        fix_file.write_text(instructions)
        
        return True, f"Created rotation instructions for {secret_type}"
    
    def _add_security_headers(self, finding: Dict) -> Tuple[bool, str]:
        """Generate security headers configuration"""
        headers_config = """# Security Headers Configuration

## For Nginx:
```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

## For Apache:
```apache
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

## For Express.js (Node):
```javascript
const helmet = require('helmet');
app.use(helmet());
```

## For Flask (Python):
```python
from flask_talisman import Talisman
Talisman(app)
```
"""
        
        fix_file = self.output_dir / 'security-headers-config.md'
        fix_file.write_text(headers_config)
        
        return True, "Created security headers configuration"
    
    def _fix_weak_cryptography(self, finding: Dict) -> Tuple[bool, str]:
        """Generate recommendations for fixing weak cryptography"""
        crypto_guide = """# Fix Weak Cryptography

## Replace MD5/SHA1 with SHA-256 or better:

### Python:
```python
# WEAK (Don't use)
import hashlib
hash = hashlib.md5(data).hexdigest()

# STRONG (Use this)
import hashlib
hash = hashlib.sha256(data).hexdigest()

# BEST (For passwords)
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### Node.js:
```javascript
// WEAK (Don't use)
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(data).digest('hex');

// STRONG (Use this)
const hash = crypto.createHash('sha256').update(data).digest('hex');

// BEST (For passwords)
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);
```

### Java:
```java
// Use SHA-256 or better
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));

// For passwords, use bcrypt or PBKDF2
```

## Key Points:
- Never use MD5 or SHA1 for security-critical operations
- Use bcrypt, scrypt, or Argon2 for password hashing
- Use SHA-256 or SHA-3 for general hashing
- Add salt to all hashes
"""
        
        fix_file = self.output_dir / 'crypto-fixes.md'
        fix_file.write_text(crypto_guide)
        
        return True, "Created cryptography fix guide"
    
    def apply_fixes(self, max_fixes: int = 10):
        """Apply automatic fixes to identified issues"""
        print("\n🔧 Analyzing and applying fixes...\n")
        
        fixable_issues = self.analyze_fixable_issues()
        
        # Sort by severity and confidence
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        fixable_issues.sort(
            key=lambda x: (
                severity_order.get(x['finding'].get('severity', 'LOW'), 0),
                {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x['confidence'], 0)
            ),
            reverse=True
        )
        
        # Apply fixes up to max_fixes
        for i, issue in enumerate(fixable_issues[:max_fixes]):
            finding = issue['finding']
            fix_type = issue['fix_type']
            
            print(f"[{i+1}/{min(len(fixable_issues), max_fixes)}] Fixing: {finding.get('title')[:60]}...")
            print(f"    Type: {fix_type}, Confidence: {issue['confidence']}")
            
            if fix_type in self.remediation_rules:
                success, message = self.remediation_rules[fix_type](finding)
                
                if success:
                    print(f"    ✅ {message}")
                    self.fixes_applied.append({
                        'finding': finding.get('title'),
                        'fix_type': fix_type,
                        'message': message,
                        'severity': finding.get('severity')
                    })
                else:
                    print(f"    ❌ {message}")
            
            print()
        
        self._generate_summary()
    
    def _generate_summary(self):
        """Generate remediation summary"""
        summary = {
            "remediation_date": datetime.now().isoformat(),
            "total_fixes_attempted": len(self.fixes_applied),
            "fixes": self.fixes_applied
        }
        
        summary_file = self.output_dir / 'remediation-summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Create markdown summary
        md_content = f"""# Remediation Summary

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Fixes Applied:** {len(self.fixes_applied)}

## Applied Fixes

"""
        for i, fix in enumerate(self.fixes_applied, 1):
            md_content += f"{i}. **{fix['finding']}**\n"
            md_content += f"   - Type: {fix['fix_type']}\n"
            md_content += f"   - Severity: {fix['severity']}\n"
            md_content += f"   - Action: {fix['message']}\n\n"
        
        md_file = self.output_dir / 'REMEDIATION_SUMMARY.md'
        md_file.write_text(md_content)
        
        print(f"✅ Remediation complete: {len(self.fixes_applied)} fixes applied")
        print(f"📄 Summary saved to: {summary_file}")
        print(f"📄 Markdown summary: {md_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Automatically remediate security vulnerabilities'
    )
    parser.add_argument(
        '--report',
        required=True,
        help='Path to consolidated report JSON file'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output directory for fixes and remediation files'
    )
    parser.add_argument(
        '--max-fixes',
        type=int,
        default=10,
        help='Maximum number of fixes to apply (default: 10)'
    )
    
    args = parser.parse_args()
    
    remediator = AutoRemediator(args.report, args.output)
    remediator.load_report()
    remediator.apply_fixes(args.max_fixes)


if __name__ == '__main__':
    from datetime import datetime
    main()
