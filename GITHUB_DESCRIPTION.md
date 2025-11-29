# Attack Surface Mapper

🔍 **A comprehensive OSINT reconnaissance platform** for security professionals, penetration testers, and bug bounty hunters.

## 🚀 Quick Start

```bash
git clone https://github.com/LingeshwarKulal/attack-surface-mapper.git
cd attack-surface-mapper
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
python src/main.py -t example.com --with-subdomains --html-report
```

## ✨ Features

- 🔎 **Google Dorking** - OSINT via Google Custom Search API
- 🐙 **GitHub Leak Scanner** - Detect exposed secrets and credentials
- 🌐 **Subdomain Enumeration** - Certificate transparency + DNS brute-force
- 🔌 **Port Scanner** - Multi-threaded service discovery
- 🔗 **Correlation Engine** - Intelligent cross-referencing
- 📊 **HTML Reports** - Beautiful, client-ready reports

## 📖 Documentation

See [README.md](README.md) for complete documentation.

## 👤 Author

**Lingeshwar Kulal**
- GitHub: [@LingeshwarKulal](https://github.com/LingeshwarKulal)

## ⭐ Support

If you find this tool useful, please give it a star!

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.
