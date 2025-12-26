# 🚀 Quick Start Guide

Get your DevSecOps pipeline running in **5 minutes**!

## ⚡ Fast Track (For the Impatient)

```bash
# 1. Clone the repo
git clone https://github.com/yannisych/DevSecOps-Pipeline.git
cd DevSecOps-Pipeline

# 2. Configure GitHub Secrets
# Go to: Settings → Secrets → Actions → New secret
# Add: SONAR_TOKEN (get from sonarcloud.io)

# 3. Update workflow configuration
# Edit .github/workflows/security-pipeline.yml lines 15-16
# Replace 'your-org' and 'your-project-key' with your SonarCloud values

# 4. Push and watch magic happen!
git add .
git commit -m "Configure pipeline"
git push
```

That's it! Go to **Actions** tab to see your pipeline running.

---

## 📋 Detailed Setup

### Step 1: Prerequisites (2 minutes)

**Required:**
- [x] GitHub account
- [x] Git installed
- [x] SonarCloud account (free for public repos)

**Optional:**
- [ ] Docker Desktop (for local testing)
- [ ] Python 3.11+ (for running scripts locally)

### Step 2: Get SonarCloud Token (2 minutes)

1. Go to [SonarCloud.io](https://sonarcloud.io)
2. Click **Log in** → **With GitHub**
3. Click your profile photo → **My Account**
4. Go to **Security** tab
5. Generate new token:
   - Name: `DevSecOps Pipeline`
   - Type: **User Token**
   - Expiration: **30 days** (or longer)
6. **Copy the token** (you won't see it again!)

### Step 3: Configure GitHub Repository (3 minutes)

#### A. Add GitHub Secret

1. Go to your repo on GitHub
2. **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add:
   - Name: `SONAR_TOKEN`
   - Value: *(paste your SonarCloud token)*
5. Click **Add secret**

#### B. Update Workflow File

Edit `.github/workflows/security-pipeline.yml`:

```yaml
# Lines 15-16 - Replace with your values
env:
  SONAR_ORGANIZATION: 'yannisych'        # Your SonarCloud org
  SONAR_PROJECT_KEY: 'yannisych_DevSecOps-Pipeline'  # Your project key
```

To find these values:
1. Go to [SonarCloud.io](https://sonarcloud.io)
2. Click **+** → **Analyze new project**
3. Select your repository
4. Copy the **Organization** and **Project Key** shown

### Step 4: Test the Pipeline (1 minute)

```bash
# Commit and push
git add .github/workflows/security-pipeline.yml
git commit -m "Configure SonarCloud"
git push

# Watch the pipeline
# Go to: GitHub → Actions → Security Pipeline
```

You should see:
```
✅ Setup
✅ SAST
✅ SCA
✅ Container Scan
✅ Secrets Detection
✅ DAST
✅ SBOM Generation
✅ Aggregate Reports
✅ Notifications
```

### Step 5: View Results (30 seconds)

1. Click on the completed workflow
2. Scroll to **Artifacts** section
3. Download **security-reports**
4. Open `security-dashboard.html` in your browser

🎉 **Done!** You now have a fully functional DevSecOps pipeline!

---

## 🔧 Optional Enhancements

### Enable Additional Notifications

#### Slack

1. Create Slack webhook:
   - Slack → Apps → Incoming Webhooks → Add to Slack
   - Choose channel → Copy webhook URL

2. Add to GitHub Secrets:
   - Name: `SLACK_WEBHOOK`
   - Value: Your webhook URL

#### Email (SendGrid)

1. Get SendGrid API key:
   - [SendGrid.com](https://sendgrid.com) → Settings → API Keys → Create

2. Add to GitHub Secrets:
   - Name: `SENDGRID_API_KEY`
   - Value: Your API key

#### Microsoft Teams

1. Create Teams webhook:
   - Teams → Apps → Incoming Webhook → Configure
   - Copy webhook URL

2. Add to GitHub Secrets:
   - Name: `TEAMS_WEBHOOK`
   - Value: Your webhook URL

### Configure Security Policy

Edit `security-policy.json` to customize:

```json
{
  "quality_gates": {
    "critical_vulnerabilities": {
      "max_count": 0,        // ← Change this
      "action": "block"      // ← Or this
    }
  }
}
```

### Enable Auto-Remediation

In `security-policy.json`:

```json
{
  "auto_remediation": {
    "enabled": true,         // ← Set to true
    "auto_merge": false,     // ← Keep false for safety
    "max_fixes_per_pr": 5
  }
}
```

---

## 🧪 Local Testing

### Test Individual Tools

```bash
# Start SonarQube
docker-compose up -d sonarqube sonarqube-db

# Wait 2-3 minutes, then access
open http://localhost:9000
# Login: admin / admin

# Test container scanning
docker build -t test:latest ./sample-app
docker run --rm aquasec/trivy image test:latest

# Test secrets detection
docker run --rm -v $(pwd):/repo trufflesecurity/trufflehog \
  git file:///repo --json

# Test DAST
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:8080
```

### Test Python Scripts

```bash
# Install dependencies
pip install -r scripts/requirements.txt

# Test report aggregation
python scripts/aggregate-reports.py \
  --input-dir ./test-reports \
  --output-dir ./output

# Test dashboard generation
python scripts/generate-dashboard.py \
  --report ./output/consolidated-report.json \
  --output ./dashboard.html

# Open dashboard
open ./dashboard.html
```

---

## 🐛 Troubleshooting

### Pipeline Fails on SAST

**Problem:** SonarCloud scan fails with authentication error

**Solution:**
1. Verify `SONAR_TOKEN` is set in GitHub Secrets
2. Check token hasn't expired
3. Verify `SONAR_ORGANIZATION` and `SONAR_PROJECT_KEY` are correct

### No Artifacts Generated

**Problem:** Can't find security reports

**Solution:**
1. Check pipeline completed successfully
2. Look in **Actions** → Click run → Scroll to **Artifacts**
3. Wait for "Aggregate Reports" job to finish

### Container Scan Fails

**Problem:** Can't build Docker image

**Solution:**
1. Ensure `Dockerfile` exists in project root or `sample-app/`
2. Check Docker image builds locally:
   ```bash
   docker build -t test ./sample-app
   ```

### Secrets Detected (False Positive)

**Problem:** Pipeline fails on test secrets

**Solution:**
Add to `security-policy.json`:
```json
{
  "secrets_detection": {
    "allowed_patterns": [
      ".*_TEST_.*",
      ".*_EXAMPLE_.*"
    ]
  }
}
```

---

## 📚 Next Steps

1. ✅ **Customize security policy** (`security-policy.json`)
2. ✅ **Add your code** to the repository
3. ✅ **Review security dashboard** regularly
4. ✅ **Enable notifications** (Slack, Teams, Email)
5. ✅ **Set up scheduled scans** (already configured for 2 AM daily)
6. ✅ **Integrate with your workflow** (branch protection, etc.)

---

## 💡 Pro Tips

### Faster Pipelines

- Use `scan_type: 'quick'` for draft PRs
- Enable caching (already enabled)
- Run DAST only on important branches

### Better Security

- Review compliance reports weekly
- Act on critical findings within 24 hours
- Keep dependencies updated
- Enable auto-remediation (carefully)

### Team Collaboration

- Add security policy to onboarding docs
- Schedule security review meetings
- Celebrate security improvements
- Share dashboard in team channels

---

## 🆘 Need Help?

- 📖 **Full Documentation**: [README.md](../README.md)
- 🐛 **Report Issues**: [GitHub Issues](https://github.com/yannisych/DevSecOps-Pipeline/issues)
- 💬 **Ask Questions**: [GitHub Discussions](https://github.com/yannisych/DevSecOps-Pipeline/discussions)
- 🔒 **Security Concerns**: [SECURITY.md](SECURITY.md)

---

**Happy Securing! 🔐**
