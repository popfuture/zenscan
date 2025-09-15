# 🛡️ ZenScan - OWASP ZAP Security Scanner CLI Tool

ZenScan is a powerful command-line security scanner that leverages OWASP ZAP to crawl websites and generate comprehensive HTML security reports. It follows OWASP security testing principles and provides detailed vulnerability assessments.

## ✨ Features

- **Automated Website Crawling**: Uses OWASP ZAP spider to discover all accessible pages
- **Active Security Scanning**: Performs comprehensive vulnerability testing
- **Beautiful HTML Reports**: Generates professional, easy-to-read security reports
- **Risk-based Categorization**: Organizes findings by risk level (High, Medium, Low, Informational)
- **Command-line Interface**: Simple and intuitive CLI for easy integration
- **Detailed Logging**: Comprehensive logging for debugging and audit trails
- **Flexible Configuration**: Customizable ZAP proxy settings

## 🚀 Quick Start

### Prerequisites

1. **Python 3.7+** installed on your system
2. **OWASP ZAP** running and accessible (see installation guide below)

### Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd zenscan
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Start OWASP ZAP:
```bash
# Option 1: Download and run ZAP GUI
# Download from: https://www.zaproxy.org/download/
# Start ZAP and ensure it's running on port 8080

# Option 2: Run ZAP in daemon mode (headless)
zap.sh -daemon -port 8080 -host 0.0.0.0
```

### Basic Usage

```bash
# Scan a website (basic)
python zenscan.py https://example.com

# Scan with custom output file
python zenscan.py https://example.com -o my_report.html

# Scan with custom ZAP proxy
python zenscan.py https://example.com --zap-proxy http://localhost:8080

# Enable verbose logging
python zenscan.py https://example.com -v
```

## 📋 Command Line Options

```bash
usage: zenscan.py [-h] [-o OUTPUT] [--zap-proxy ZAP_PROXY] [-v] url

ZenScan - OWASP ZAP Security Scanner CLI Tool

positional arguments:
  url                   Target URL to scan (e.g., https://example.com)

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output HTML file path (default: security_report.html)
  --zap-proxy ZAP_PROXY
                        ZAP proxy URL (default: http://127.0.0.1:8080)
  -v, --verbose         Enable verbose logging
```

## 🔧 OWASP ZAP Setup

### Method 1: GUI Mode
1. Download OWASP ZAP from [zaproxy.org](https://www.zaproxy.org/download/)
2. Start ZAP application
3. Go to Tools → Options → Local Proxies
4. Ensure it's running on `127.0.0.1:8080`

### Method 2: Daemon Mode (Recommended for Automation)
```bash
# Download ZAP (example for Linux/macOS)
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_unix.sh
chmod +x ZAP_2.14.0_unix.sh
./ZAP_2.14.0_unix.sh

# Start ZAP in daemon mode
./ZAP_2.14.0/zap.sh -daemon -port 8080 -host 0.0.0.0
```

### Method 3: Docker
```bash
# Run ZAP in Docker container
docker run -d -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -port 8080 -host 0.0.0.0
```

## 📊 Report Features

The generated HTML reports include:

- **Executive Summary**: High-level overview with risk distribution
- **Risk-based Organization**: Issues grouped by severity level
- **Detailed Findings**: Complete vulnerability descriptions
- **Remediation Guidance**: Specific solutions for each issue
- **Professional Styling**: Clean, modern interface for easy reading
- **Responsive Design**: Works on desktop and mobile devices

### Sample Report Sections

- 🚨 **High Risk Issues**: Critical vulnerabilities requiring immediate attention
- ⚠️ **Medium Risk Issues**: Important security concerns to address
- ℹ️ **Low Risk Issues**: Minor security improvements
- 📋 **Informational Issues**: Best practices and recommendations

## 🛠️ Advanced Usage

### Custom ZAP Configuration

You can customize ZAP behavior by modifying the scan methods in `zenscan.py`:

```python
# Example: Configure spider parameters
self.zap.spider.set_max_depth(5)
self.zap.spider.set_thread_count(5)

# Example: Configure active scan parameters
self.zap.ascan.set_max_scan_time_in_minutes(60)
```

### Integration with CI/CD

```bash
# Example for GitHub Actions or similar
python zenscan.py https://your-app.com -o security_report.html
if [ $? -eq 0 ]; then
    echo "Security scan completed successfully"
    # Upload report to artifact storage
else
    echo "Security scan failed"
    exit 1
fi
```

## 🔍 Security Testing Coverage

ZenScan performs comprehensive security testing including:

- **Injection Attacks**: SQL, NoSQL, LDAP, OS command injection
- **Broken Authentication**: Session management vulnerabilities
- **Sensitive Data Exposure**: Information disclosure issues
- **XML External Entities (XXE)**: XML processing vulnerabilities
- **Broken Access Control**: Authorization bypasses
- **Security Misconfiguration**: Default configurations and errors
- **Cross-Site Scripting (XSS)**: Reflected, stored, and DOM-based XSS
- **Insecure Deserialization**: Object injection vulnerabilities
- **Known Vulnerable Components**: Outdated library detection
- **Insufficient Logging**: Monitoring and logging gaps

## 📝 Logging

ZenScan provides comprehensive logging:

- **Console Output**: Real-time scan progress and results
- **Log File**: Detailed logs saved to `zenscan.log`
- **Verbose Mode**: Additional debugging information with `-v` flag

## ⚠️ Important Notes

1. **Legal Compliance**: Only scan websites you own or have explicit permission to test
2. **Rate Limiting**: Be respectful of target servers and implement appropriate delays
3. **Resource Usage**: ZAP scans can be resource-intensive; monitor system performance
4. **Network Access**: Ensure ZAP has proper network access to target URLs
5. **False Positives**: Review all findings manually; automated tools may produce false positives

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests (when available)
pytest

# Format code
black zenscan.py

# Lint code
flake8 zenscan.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP ZAP](https://www.zaproxy.org/) - The powerful security testing tool that makes this possible
- [OWASP Foundation](https://owasp.org/) - For their invaluable security testing guidelines
- The security community for continuous improvement of testing methodologies

## 📞 Support

If you encounter any issues or have questions:

1. Check the [troubleshooting section](#troubleshooting) below
2. Review the logs in `zenscan.log`
3. Ensure ZAP is running and accessible
4. Verify network connectivity to target URLs

### Troubleshooting

**Common Issues:**

1. **"Failed to connect to ZAP"**
   - Ensure ZAP is running on the specified port (default: 8080)
   - Check firewall settings
   - Verify proxy URL is correct

2. **"Invalid URL"**
   - Include protocol (http:// or https://)
   - Check URL format and accessibility

3. **"Scan failed"**
   - Check network connectivity
   - Review logs for specific error messages
   - Ensure target website is accessible

4. **Empty or no report generated**
   - Verify ZAP completed scans successfully
   - Check if target website has crawlable content
   - Review ZAP logs for any blocking or errors

---

**Happy Security Scanning! 🔒**
