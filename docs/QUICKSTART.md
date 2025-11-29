# Quick Start Guide

## Getting Started with Attack Surface Reconnaissance Tool

### Step 1: Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/google-powered-attack-surface-recon.git
cd google-powered-attack-surface-recon

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: API Configuration

#### Get Google Custom Search API Key

1. Visit [Google Cloud Console](https://console.developers.google.com/)
2. Create a new project
3. Enable "Custom Search API"
4. Go to "Credentials" → "Create Credentials" → "API Key"
5. Copy the API key

#### Create Custom Search Engine

1. Go to [Programmable Search Engine](https://programmablesearchengine.google.com/)
2. Click "Add" to create new search engine
3. For "Sites to search", enter: `www.example.com/*` (replace with your use case)
4. Select "Search the entire web"
5. Copy the Search Engine ID (CSE ID)

#### Get GitHub Personal Access Token

1. Go to [GitHub Settings](https://github.com/settings/tokens)
2. Click "Generate new token" → "Generate new token (classic)"
3. Give it a descriptive name: "Attack Surface Recon Tool"
4. Select scopes: `public_repo`, `read:user`
5. Click "Generate token"
6. Copy the token immediately (you won't see it again!)

#### Configure Environment Variables

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your keys
# Use your favorite editor (notepad, nano, vim, etc.)
notepad .env  # Windows
nano .env     # Linux/Mac
```

Add your credentials:
```env
GOOGLE_API_KEY=AIzaSyABC123...
GOOGLE_CSE_ID=abc123xyz...
GITHUB_TOKEN=ghp_ABC123...
```

### Step 3: Run Your First Scan

```bash
# Basic scan
python src/main.py --target example.com

# With custom output directory
python src/main.py --target example.com --output ./my_results

# Verbose output for debugging
python src/main.py --target example.com --verbose
```

### Step 4: Review Results

The tool creates three JSON files in the output directory:

1. **`google_recon_*.json`** - Google dorking results
2. **`github_leaks_*.json`** - GitHub scanning results
3. **`correlated_report_*.json`** - Correlation analysis with risk scores

Open these files with any JSON viewer or text editor.

### Example Workflow

```bash
# 1. Scan a target
python src/main.py --target company.com -v

# 2. Review the output
cd output/
ls -la

# 3. Open correlation report
cat correlated_report_company_com_*.json | jq .

# 4. Check high-severity findings
cat correlated_report_company_com_*.json | jq '.correlations[] | select(.severity=="critical")'
```

## Common Use Cases

### Bug Bounty Hunting

```bash
# Full scan of target
python src/main.py --target bugcrowd-target.com --output ./bounty_results

# Google dorking only (for initial recon)
python src/main.py --target bugcrowd-target.com --google-only
```

### VAPT Engagement

```bash
# Complete assessment
python src/main.py --target client-domain.com --output ./vapt_engagement

# Review critical findings
grep -r "critical" output/
```

### Red Team Operation

```bash
# Full external reconnaissance
python src/main.py --target target-org.com --verbose

# Analyze API exposures specifically
python src/main.py --target target-org.com | grep -i "api"
```

## Troubleshooting

### API Rate Limits

**Google API:**
- Free tier: 100 queries/day
- Solution: Reduce number of dork categories or upgrade plan

**GitHub API:**
- Authenticated: 5000 requests/hour
- Solution: Wait for rate limit reset or use multiple tokens

### No Results Found

Check:
1. Target domain is correctly spelled
2. Target has public presence (Google indexed, GitHub repos)
3. API keys are valid and active
4. Network connectivity

### Permission Errors

```bash
# On Linux/Mac, you might need permissions for output directory
chmod 755 output/
```

## Tips for Best Results

1. **Use Specific Targets**: `api.example.com` is better than `example.com`
2. **Run Regularly**: Create a cron job for continuous monitoring
3. **Combine with Other Tools**: Use alongside Amass, Subfinder, etc.
4. **Document Findings**: Keep notes of what you discover
5. **Follow Responsible Disclosure**: Report findings ethically

## Next Steps

- Read the full [README.md](../README.md)
- Review [PRD.md](./PRD.md) for detailed features
- Check out example reports in `docs/examples/`
- Contribute improvements via pull requests

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/google-powered-attack-surface-recon/issues)
- **Documentation**: See `docs/` directory
- **Community**: Join discussions on GitHub

---

Happy hunting! 🔍🛡️
