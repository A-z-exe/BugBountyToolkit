# 🛡️ Advanced Bug Bounty Security Assessment Tool

A comprehensive security assessment tool designed for bug bounty hunters, penetration testers, and security researchers.

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for educational and authorized testing purposes only. Users must:
- Only test systems they own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Respect bug bounty program rules and scope
- Never use this tool for malicious purposes

Unauthorized access to computer systems is illegal. Users are solely responsible for legal compliance.

## 🚀 Features

### 🔍 Information Gathering
- Domain WHOIS lookup
- DNS enumeration
- Subdomain discovery
- SSL certificate analysis
- robots.txt retrieval

### 🛡️ Vulnerability Scanning
- Network port scanning
- Web vulnerability assessment
- Common misconfiguration detection
- Security headers analysis

### ⚔️ Attack Testing
- SQL injection testing (safe mode)
- Directory and file fuzzing
- XSS payload generation
- CORS misconfiguration testing

### 🔌 API & Mobile Security
- HTTP security headers analysis
- CORS configuration testing
- API documentation discovery
- JWT analysis guidelines

### 📊 Comprehensive Reporting
- Detailed markdown reports
- JSON summaries for automation
- Structured findings documentation
- Actionable recommendations

## 📋 Requirements

### Required Tools
```bash
# Ubuntu/Debian installation
sudo apt-get update
sudo apt-get install whois dnsutils nmap nikto curl openssl

# Additional tools (install separately)
# Subfinder: https://github.com/projectdiscovery/subfinder
# SQLMap: https://github.com/sqlmapproject/sqlmap
# Wfuzz: pip install wfuzz
```

### Python Dependencies
```bash
pip install requests pathlib
```

## 🔧 Installation

1. **Clone the repository**
```bash
git clone https://github.com/a-z-exe/BugBountyToolkit.git
cd BugBountyToolkit
```

2. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

3. **Install system tools**
```bash
sudo apt-get install whois dnsutils nmap nikto curl openssl
```

4. **Install additional tools**
```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# SQLMap
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
pip install -r requirements.txt

# Wfuzz
pip install wfuzz
```

## 💻 Usage

### Command Line Mode

```bash
# Full comprehensive scan
python bugbounty_tool.py -t https://example.com -m full

# Information gathering only
python bugbounty_tool.py -t example.com -m info

# Vulnerability scanning
python bugbounty_tool.py -t https://example.com -m vuln

# Attack testing
python bugbounty_tool.py -t https://example.com -m attack

# API security review
python bugbounty_tool.py -t https://api.example.com -m api
```

### Interactive Mode

```bash
python bugbounty_tool.py
```

### Command Line Options

```bash
usage: bugbounty_tool.py [-h] [-t TARGET] [-m {info,vuln,attack,api,full}] [--skip-legal] [--timeout TIMEOUT]

options:
  -h, --help            Show help message
  -t, --target TARGET   Target URL or domain
  -m, --mode MODE       Scan mode: info, vuln, attack, api, or full
  --skip-legal          Skip legal disclaimer (use responsibly)
  --timeout TIMEOUT     Command timeout in seconds (default: 30)
```

## 📁 Output Structure

```
results_example.com_20240830_143022/
├── SECURITY_REPORT.md          # Main assessment report
├── scan_summary.json           # JSON summary for automation
├── whois_output.txt           # Domain information
├── dig_output.txt             # DNS records
├── subfinder_output.txt       # Discovered subdomains
├── ssl_info.txt               # SSL certificate details
├── robots.txt                 # Retrieved robots.txt
├── nmap_output.txt            # Port scan results
├── nikto_output.txt           # Web vulnerability scan
├── misconfiguration_checks.json # Configuration issues
├── sqlmap_output.txt          # SQL injection test results
├── wfuzz_output.txt           # Directory fuzzing results
├── xss_payloads.txt           # XSS test payloads
├── headers_analysis.json      # Security headers analysis
├── cors_analysis.json         # CORS configuration test
├── jwt_analysis.md            # JWT testing guidelines
└── api_docs_discovery.json    # API documentation findings
```

## 🔒 Security Features

- **Input Validation**: All user inputs are sanitized and validated
- **Safe Command Execution**: No shell injection vulnerabilities
- **Rate Limiting**: Respectful request timing
- **Error Handling**: Comprehensive exception management
- **Legal Safeguards**: Built-in legal disclaimer and warnings

## 🎯 Best Practices

1. **Always get permission** before testing any system
2. **Start with information gathering** to understand the target
3. **Review all findings manually** - automated tools can have false positives
4. **Follow responsible disclosure** for any vulnerabilities found
5. **Keep detailed notes** of your testing methodology

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 coding standards
- Add proper error handling
- Include security considerations
- Update documentation for new features
- Test thoroughly before submitting

## 🐛 Bug Reports

If you find a bug or security issue:
1. **DO NOT** open a public issue for security vulnerabilities
2. Contact the maintainer privately for security issues
3. For general bugs, open a GitHub issue with:
   - Python version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior

## 📚 Educational Resources

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**AmirHossein Zarei (A-z-exe)**
- 🌐 GitHub: [github.com/a-z-exe](https://github.com/a-z-exe)
- 📱 Telegram: [t.me/A_Z_exe](https://t.me/A_Z_exe)
- 📷 Instagram: [instagram.com/A_Z_exe](https://instagram.com/A_Z_exe)

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for excellent security tools
- [OWASP](https://owasp.org/) for security guidelines and resources
- The bug bounty and security research community

## 📋 TODO

- [ ] Add support for custom wordlists
- [ ] Implement multithreading for faster scans
- [ ] Add Docker container support
- [ ] Create web interface
- [ ] Add more API security tests
- [ ] Implement custom vulnerability checks
- [ ] Add integration with popular bug bounty platforms

---

**⚠️ Remember**: This tool is only as good as the person using it. Always combine automated testing with manual security review!