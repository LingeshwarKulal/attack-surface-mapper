# 🔍 Attack Surface Mapper

A comprehensive Python-based OSINT reconnaissance platform that combines Google Search API, GitHub leak detection, subdomain enumeration, port scanning, and intelligent correlation analysis to identify an organization's complete attack surface.

## 🎯 Overview

**Attack Surface Mapper** automates professional security reconnaissance by discovering exposure patterns that traditional scanners miss. It performs deep reconnaissance on target domains without direct interaction with internal systems, making it fully external and ethical OSINT-driven - perfect for VAPT engagements, bug bounty hunting, and security audits.

## ✨ Key Features

### 1. **🔎 Google Search API Reconnaissance**
- Intelligent Google dorking through official API
- Detects admin panels, login pages, and debug interfaces
- Identifies exposed files (PDF, DOCX, SQL, ENV, LOG)
- Finds publicly indexed API documentation
- Discovers cloud storage misconfigurations (AWS S3, Azure Blob, GCS)
- Automatic severity classification

### 2. **🐙 GitHub API Secret & Leak Scanner**
- Scans public repositories for sensitive information
- Detects hardcoded credentials and API keys
- Identifies exposed environment variables
- Analyzes commit history for leaked secrets
- Pattern-based detection for 15+ secret types
- AWS keys, database credentials, JWT tokens, etc.

### 3. **🌐 Subdomain Enumeration (NEW!)**
- Certificate Transparency log queries (crt.sh)
- DNS brute-force on common subdomains
- Wildcard DNS detection
- Intelligent categorization by purpose:
  - Admin panels & management interfaces
  - Development/staging environments
  - API endpoints
  - Mail servers & webmail
  - CDN resources
  - VPN/Remote access points

### 4. **🔌 Port Scanner (NEW!)**
- Multi-threaded concurrent scanning
- 24+ common service ports detection
- Service identification and banner grabbing
- Discovers: Web servers, SSH, databases, RDP, VNC, etc.
- Fast and efficient scanning

### 5. **🔗 Correlation Engine**
- Merges findings from all reconnaissance sources
- Identifies critical combinations (endpoints + leaked credentials)
- Correlates login panels with exposed passwords
- Links cloud storage URLs with GitHub configs
- Intelligent risk scoring (0-100)

### 6. **📊 Beautiful HTML Reports (NEW!)**
- Professional, styled HTML output
- Executive summary with statistics
- Color-coded severity indicators
- Comprehensive findings breakdown
- Actionable security recommendations
- Client-ready presentation format

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Google Custom Search API key and CSE ID
- GitHub Personal Access Token

### Quick Setup

1. **Clone the repository:**
```bash
git clone https://github.com/LingeshwarKulal/attack-surface-mapper.git
cd attack-surface-mapper
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure API keys:**
```bash
cp .env.example .env
# Edit .env with your API credentials
```

## 🔑 API Key Setup

### Google Custom Search API

1. Go to [Google Cloud Console](https://console.developers.google.com/)
2. Create a new project or select existing
3. Enable "Custom Search API"
4. Create credentials (API Key)
5. Create a Custom Search Engine at [Programmable Search Engine](https://programmablesearchengine.google.com/)
6. Note your CSE ID from the setup page

### GitHub Personal Access Token

1. Go to [GitHub Settings > Tokens](https://github.com/settings/tokens)
2. Generate new token (classic)
3. Required scopes: `public_repo`, `read:user`
4. Copy the generated token

## 📖 Usage

### Basic Scan
```bash
python src/main.py -t example.com
```

### Complete Reconnaissance (All Features)
```bash
python src/main.py -t example.com --with-subdomains --with-portscan --html-report
```

### Subdomain Enumeration Only
```bash
python src/main.py -t example.com --with-subdomains --skip-google --skip-github
```

### Quick Scan (Skip Rate-Limited APIs)
```bash
python src/main.py -t example.com --skip-google --with-subdomains --html-report
```

### Advanced Options

```bash
# Specify output directory
python src/main.py -t example.com -o ./custom-output

# Run only Google dorking
python src/main.py -t example.com --google-only

# Run only GitHub scanning
python src/main.py -t example.com --github-only

# Verbose logging
python src/main.py -t example.com -v

# Generate HTML report
python src/main.py -t example.com --html-report
```

### All Command Line Options

```
Required:
  -t, --target              Target domain (e.g., example.com)

Optional:
  -c, --config              Path to configuration file
  -o, --output              Output directory (default: output/)
  -v, --verbose             Enable verbose logging
  
Scan Control:
  --skip-google             Skip Google dorking
  --skip-github             Skip GitHub scanning
  --google-only             Run only Google dorking
  --github-only             Run only GitHub scanning
  
New Features:
  --with-subdomains         Enable subdomain enumeration
  --with-portscan           Enable port scanning
  --html-report             Generate beautiful HTML report
```

## 📊 Output Files

The tool generates comprehensive output in the `output/` directory:

1. **`google_recon_<target>_<timestamp>.json`**
   - Google dorking results by category
   - Severity classifications (Critical/High/Medium/Low)
   - Risk indicators and snippets

2. **`github_leaks_<target>_<timestamp>.json`**
   - GitHub repository scan results
   - Detected secrets and leaked credentials
   - Commit history analysis

3. **`subdomains_<target>_<timestamp>.json`** *(NEW)*
   - All discovered subdomains
   - Categorized by purpose (admin, dev, api, mail, etc.)
   - Wildcard DNS detection status

4. **`port_scan_<target>_<timestamp>.json`** *(NEW)*
   - Open ports per host
   - Service identification
   - Banner information

5. **`correlated_report_<target>_<timestamp>.json`**
   - Cross-referenced findings from all sources
   - Risk scores (0-100)
   - Severity-based prioritization
   - Actionable security recommendations

6. **`report_<target>_<timestamp>.html`** *(NEW)*
   - Beautiful, professional HTML report
   - Executive summary with statistics
   - All findings in one place
   - Ready for client presentation

### Sample Output Structure

```json
{
  "target": "example.com",
  "timestamp": "2025-11-29T10:30:00Z",
  "correlations": [
    {
      "type": "api_endpoint_credential_leak",
      "risk_score": 95,
      "severity": "critical",
      "description": "Exposed API endpoint with leaked credentials",
      "impact": "Attackers can potentially access the API using leaked credentials"
    }
  ],
  "risk_summary": {
    "total_correlations": 15,
    "by_severity": {
      "critical": 3,
      "high": 7,
      "medium": 4,
      "low": 1
    }
  },
  "recommendations": [...]
}
```

## 🎓 Use Cases

- **VAPT Engagements**: Initial reconnaissance phase
- **Bug Bounty Hunting**: Asset discovery and exposure detection
- **Red Team Operations**: External attack surface mapping
- **Security Audits**: Identifying public data leaks
- **Continuous Monitoring**: Regular security posture assessment

## 🔒 Security & Ethics

⚠️ **Important**: This tool is designed for:
- Authorized security assessments
- Bug bounty programs with proper scope
- Your own organization's assets
- Educational and research purposes

**DO NOT** use this tool to:
- Target organizations without permission
- Violate terms of service
- Engage in illegal activities

## 🛠️ Project Structure

```
attack-surface-mapper/
├── src/
│   ├── __init__.py
│   ├── main.py                      # Main entry point
│   ├── reconnaissance/
│   │   ├── __init__.py
│   │   └── google_dorking.py        # Google Search API module
│   ├── github/
│   │   ├── __init__.py
│   │   └── leak_scanner.py          # GitHub API scanner
│   ├── subdomain/                   # NEW
│   │   ├── __init__.py
│   │   └── subdomain_enum.py        # Subdomain enumeration
│   ├── ports/                       # NEW
│   │   ├── __init__.py
│   │   └── port_scanner.py          # Port scanning module
│   ├── correlation/
│   │   ├── __init__.py
│   │   └── analyzer.py              # Correlation engine
│   ├── reporting/                   # NEW
│   │   ├── __init__.py
│   │   └── report_generator.py      # HTML report generator
│   └── utils/
│       ├── __init__.py
│       └── config.py                # Configuration management
├── tests/                           # Unit tests
├── docs/
│   ├── PRD.md                       # Product Requirements
│   └── QUICKSTART.md                # Quick start guide
├── examples/
│   └── usage_examples.py
├── output/                          # Scan results (gitignored)
├── requirements.txt
├── setup.py
├── .env.example                     # Example config
├── .gitignore
└── README.md
```

## 🧪 Testing

Run the test suite:

```bash
pytest tests/
```

With coverage:

```bash
pytest tests/ --cov=src --cov-report=html
```

## 📧 Contact & Support

**Developer:** Lingeshwar Kulal

**GitHub:** [@LingeshwarKulal](https://github.com/LingeshwarKulal)

**Project Repository:** [attack-surface-mapper](https://github.com/LingeshwarKulal/attack-surface-mapper)

For questions, issues, or feature requests:
- 🐛 Open an issue on [GitHub Issues](https://github.com/LingeshwarKulal/attack-surface-mapper/issues)
- 💬 Start a discussion on [GitHub Discussions](https://github.com/LingeshwarKulal/attack-surface-mapper/discussions)
- ⭐ Star the repo if you find it useful!

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new features
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Google Custom Search API
- GitHub REST API
- Certificate Transparency Project (crt.sh)
- Python security and OSINT community

## ⚠️ Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. 

**Legal Notice:**
- Only use on targets you own or have explicit written permission to test
- Respect all applicable laws and regulations
- Follow responsible disclosure practices
- The authors are not responsible for misuse or damage caused by this program

**Always ensure you have explicit authorization before scanning any target.**

---

<div align="center">

**Made with ❤️ by Lingeshwar Kulal**

⭐ **Star this repo if you find it useful!** ⭐

[Report Bug](https://github.com/LingeshwarKulal/attack-surface-mapper/issues) · [Request Feature](https://github.com/LingeshwarKulal/attack-surface-mapper/issues) · [Documentation](https://github.com/LingeshwarKulal/attack-surface-mapper/wiki)

</div>