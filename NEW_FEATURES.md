# 🚀 New Features Added to Attack Surface Recon Tool

## Summary of Enhancements

Three major new modules have been added to enhance the reconnaissance capabilities:

---

## 1. 🌐 Subdomain Enumeration Module

**Location**: `src/subdomain/subdomain_enum.py`

### Features:
- **Certificate Transparency Logs**: Queries crt.sh for subdomains from SSL certificates
- **DNS Brute Force**: Tests common subdomain names (www, mail, admin, api, dev, etc.)
- **Wildcard Detection**: Identifies if target has wildcard DNS configured
- **Intelligent Categorization**: Groups subdomains by purpose:
  - Admin panels
  - Development/staging environments
  - API endpoints
  - Mail servers
  - CDN resources
  - VPN/Remote access
  - Other services

### Usage:
```bash
python src/main.py -t example.com --with-subdomains
```

### Results for certifiedhacker.com:
- ✅ **49 subdomains discovered**
- 3 admin-related subdomains
- 8 development environments
- 2 API endpoints
- 3 mail servers
- 33 other subdomains
- No wildcard DNS detected

---

## 2. 🔌 Port Scanner Module

**Location**: `src/ports/port_scanner.py`

### Features:
- **Multi-threaded Scanning**: Fast concurrent port scanning
- **Common Ports**: Scans 24 common service ports:
  - Web: 80, 443, 8080, 8443
  - SSH/Telnet: 22, 23
  - Mail: 25, 110, 143, 465, 587, 993, 995
  - Databases: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis)
  - Remote Access: 3389 (RDP), 5900 (VNC)
  - Other: FTP (21), DNS (53), SMB (445), Elasticsearch (9200)
- **Banner Grabbing**: Attempts to capture service banners
- **Service Identification**: Maps ports to known services

### Usage:
```bash
python src/main.py -t example.com --with-subdomains --with-portscan
```

### Output:
- Lists all open ports per host
- Identifies services running
- Captures service banners when available

---

## 3. 📊 HTML Report Generator

**Location**: `src/reporting/report_generator.py`

### Features:
- **Beautiful HTML Reports**: Professional, styled HTML output
- **Comprehensive Coverage**: Includes all scan phases:
  - Google reconnaissance findings
  - GitHub leak detection
  - Subdomain enumeration
  - Port scanning results
  - Correlation analysis
- **Visual Elements**:
  - Executive summary with statistics cards
  - Color-coded severity indicators (Critical/High/Medium/Low)
  - Organized tables for port scan results
  - Categorized findings sections
  - Security recommendations
- **Responsive Design**: Mobile-friendly layout
- **Actionable Insights**: Clear recommendations and next steps

### Usage:
```bash
python src/main.py -t example.com --html-report
```

### Report Sections:
1. **Executive Summary** - Key statistics at a glance
2. **Google Reconnaissance** - OSINT findings with severity
3. **GitHub Leaks** - Secret detection results
4. **Subdomain Enumeration** - Discovered subdomains by category
5. **Port Scanning** - Open ports and services
6. **Correlation Analysis** - Cross-referenced findings
7. **Security Recommendations** - Actionable remediation steps

---

## 📋 Updated Command-Line Options

### New Arguments:
- `--with-subdomains` - Enable subdomain enumeration
- `--with-portscan` - Enable port scanning on discovered subdomains
- `--html-report` - Generate beautiful HTML report

### Complete Usage Examples:

#### Basic scan with all features:
```bash
python src/main.py -t example.com --with-subdomains --with-portscan --html-report
```

#### Subdomain enumeration only:
```bash
python src/main.py -t example.com --with-subdomains --skip-google --skip-github
```

#### Full reconnaissance with HTML report:
```bash
python src/main.py -t example.com --html-report
```

#### Quick scan without Google/GitHub:
```bash
python src/main.py -t example.com --with-subdomains --skip-google --skip-github --html-report
```

---

## 📦 New Dependencies

Added to `requirements.txt`:
- `dnspython>=2.4.0` - For DNS resolution and subdomain enumeration

---

## 🎯 Benefits of New Features

1. **More Complete Attack Surface Mapping**
   - Discovers hidden subdomains that may not appear in Google/GitHub
   - Identifies all exposed services via port scanning

2. **Better Threat Assessment**
   - Port scanning reveals actual attack vectors
   - Subdomain categorization helps prioritize targets

3. **Professional Reporting**
   - HTML reports suitable for presenting to clients/management
   - Visual severity indicators make risk clear
   - Comprehensive view of entire attack surface

4. **Flexible Scanning Options**
   - Can run individual modules independently
   - Combine features as needed for specific assessments

---

## 🔥 Live Test Results

**Target**: certifiedhacker.com (Test Run)

✅ **Subdomain Enumeration**: 49 subdomains found
- 3 admin panels
- 8 dev/staging environments  
- 2 API endpoints
- 3 mail servers

✅ **HTML Report**: Generated successfully
- Professional styling
- All sections populated
- Ready for viewing in browser

---

## 🚀 Next Steps

The tool now provides enterprise-grade reconnaissance capabilities:
- Complete attack surface discovery
- Multi-source intelligence gathering
- Professional reporting
- Actionable security insights

Use the HTML report feature to present findings professionally!
