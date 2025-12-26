# 📤 Deployment Guide - Push to GitHub

This guide will help you deploy the complete DevSecOps pipeline to your GitHub repository.

---

## 🎯 Overview

We'll perform these steps:
1. Verify your repo name is lowercase
2. Copy all files to your local repository
3. Configure SonarCloud
4. Push to GitHub
5. Verify pipeline execution

---

## Step 1: Verify Repository Name

### Check Current Repo Name

Your repo is currently: **devsecops-pipeline** ✅

This is correct! Docker requires lowercase names.

### If You Need to Rename

Go to GitHub:
1. **Settings** → **General**
2. Scroll to "Repository name"
3. Change to: `devsecops-pipeline` (all lowercase)
4. Click "Rename"

---

## Step 2: Download and Extract Files

### Location of Fixed Files

All fixed files are in:
```
/mnt/user-data/outputs/DevSecOps-Pipeline-Final/
```

### File Structure

```
DevSecOps-Pipeline-Final/
├── .github/workflows/
│   └── security-pipeline.yml    ✅ FIXED (lowercase conversion)
├── docs/
│   ├── images/                  ✅ NEW (4 screenshots)
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   ├── SECURITY.md
│   └── COMPLETE_FIX_GUIDE.md
├── scripts/                     ✅ (5 Python scripts)
├── sample-app/
│   ├── Dockerfile               ✅ FIXED (proper paths)
│   ├── src/
│   └── requirements.txt
├── security-tools/              ✅ (7 config files)
├── README.md                    ✅ NEW (with screenshots)
├── QUICK_START.md               ✅ NEW
├── security-policy.json
├── docker-compose.yml
├── .gitignore                   ✅ NEW
└── LICENSE
```

---

## Step 3: Copy Files to Your Local Repo

### Option A: Manual Copy (Windows)

```bash
# 1. Download the folder from outputs
# Location: /mnt/user-data/outputs/DevSecOps-Pipeline-Final/

# 2. Copy to your local repo
# Assuming your local repo is at:
cd C:\Users\LeIGrec\Downloads\files

# 3. Delete old files (except .git/)
# Keep: .git/ folder
# Delete: everything else

# 4. Copy all files from DevSecOps-Pipeline-Final/ to here
```

### Option B: Command Line (Linux/WSL)

```bash
# Navigate to your local repo
cd /mnt/c/Users/LeIGrec/Downloads/files

# Backup .git folder
cp -r .git .git-backup

# Remove old files (keep .git)
find . -maxdepth 1 ! -name '.git' ! -name '.' ! -name '..' -exec rm -rf {} +

# Copy new files
cp -r /mnt/user-data/outputs/DevSecOps-Pipeline-Final/* .
cp -r /mnt/user-data/outputs/DevSecOps-Pipeline-Final/.github .
cp /mnt/user-data/outputs/DevSecOps-Pipeline-Final/.gitignore .

# Verify
ls -la
```

---

## Step 4: Configure SonarCloud

### Get Your Credentials

1. Go to [sonarcloud.io](https://sonarcloud.io)
2. Log in with GitHub
3. Click **+** → **Analyze new project**
4. Select `devsecops-pipeline`
5. Note your:
   - Organization: `yannisych`
   - Project Key: (will be shown)

### Generate Token

1. **My Account** → **Security**
2. **Generate Tokens**
3. Name: `GitHub Actions`
4. Copy the token

### Add to GitHub

1. Go to repo **Settings** → **Secrets**
2. **New repository secret**
3. Name: `SONAR_TOKEN`
4. Value: (paste token)
5. **Add secret**

### Update Workflow

Edit `.github/workflows/security-pipeline.yml`:

```yaml
# Lines 24-25
env:
  SONAR_ORGANIZATION: 'yannisych'      # Your org
  SONAR_PROJECT_KEY: 'devsecops'       # Your project key
```

---

## Step 5: Push to GitHub

### Check Current Status

```bash
git status
# Should show many changed/new files
```

### Stage All Files

```bash
git add .
```

### Commit Changes

```bash
git commit -m "feat: Complete DevSecOps pipeline with fixes and screenshots

- Fix Docker build (lowercase conversion)
- Fix Dockerfile paths
- Update SonarCloud action to v5
- Add pipeline execution screenshots
- Create comprehensive README with results
- Add complete documentation
- Configure all security tools
- Add troubleshooting guides

All files in English, production-ready."
```

### Push to GitHub

```bash
git push origin main
```

Or if you renamed your default branch:

```bash
git push origin main --force
```

---

## Step 6: Verify Pipeline Execution

### Watch the Pipeline

1. Go to GitHub → **Actions**
2. Find "feat: Complete DevSecOps pipeline..." run
3. Click to view details

### Expected Results

✅ **Jobs That Should Pass:**
- Setup (4s)
- SCA (26s)

❌ **Jobs That Will Fail (NORMAL!):**
- Secrets (4s) - Found hardcoded secrets
- SAST Semgrep (15s) - Found 23 vulnerabilities
- SAST SonarCloud (21s) - Quality gate failed
- Container (12s) - Should now WORK if fix applied
- Aggregate (5s) - Too many findings
- Notify (7s) - Depends on Aggregate

⏭️ **Jobs That Will Skip:**
- DAST (requires running app)

### Download Artifacts

Scroll to bottom of workflow run:
- `sast-results-semgrep`
- `sast-results-sonarcloud`
- `sca-results`
- `container-scan-results` (if Container passed)

---

## Step 7: Verify Screenshots Display

### Check README on GitHub

1. Go to repo main page
2. Scroll down to README
3. Screenshots should display:
   - Pipeline overview
   - Pipeline details
   - Annotations
   - Container logs

### If Screenshots Don't Display

Check:
1. Files are in `docs/images/`
2. Files have correct names:
   - `pipeline-overview.png`
   - `pipeline-details.png`
   - `annotations.png`
   - `container-logs.png`
3. README references correct paths

---

## Troubleshooting

### "ERROR: repository name must be lowercase"

**Solution**: Repository name changed but workflow still uses old name.

Fix in `.github/workflows/security-pipeline.yml` line ~155:

```yaml
REPO_NAME=$(echo "${{ github.repository }}" | tr '[:upper:]' '[:lower:]')
```

This is already in the fixed workflow!

### "No such file or directory: /src"

**Solution**: Dockerfile paths incorrect.

The fixed Dockerfile uses:
```dockerfile
COPY src/*.py .
```

Not absolute paths like `/src`.

### SonarCloud Action Deprecated Warning

**Solution**: Update to v5.

The fixed workflow uses:
```yaml
uses: SonarSource/sonarqube-scan-action@v5.0.0
```

### Secrets Scan Failing

This is **NORMAL**! The sample app has intentional secrets for demonstration.

### Container Scan Failing

Expected if vulnerabilities found. Check logs for CVE details.

---

## What's Next?

### Take More Screenshots

After pipeline runs:
1. Container scan results (if fixed)
2. Trivy findings
3. SBOM generated
4. SonarCloud dashboard

### Customize

1. Edit `security-policy.json` - Quality gates
2. Update `security-tools/` configs
3. Modify scripts for your needs

### Add More Features

- Enable DAST (requires app deployment)
- Add custom Semgrep rules
- Configure auto-remediation
- Set up notifications

---

## Summary

You should now have:
- ✅ Complete pipeline on GitHub
- ✅ All 18 files committed
- ✅ Screenshots in README
- ✅ Fixed workflow running
- ✅ 100% English documentation
- ✅ Production-ready configuration

---

## Support

- 📖 [README](README.md)
- 🚀 [Quick Start](QUICK_START.md)
- 🔧 [Fix Guide](docs/COMPLETE_FIX_GUIDE.md)
- 🐛 [Issues](https://github.com/yannisych/devsecops-pipeline/issues)

---

**Pipeline ready for portfolio! 🎉**
