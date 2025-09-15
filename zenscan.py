#!/usr/bin/env python3
"""
ZenScan - OWASP ZAP Security Scanner CLI Tool
A command line tool that crawls websites using OWASP ZAP and generates HTML security reports.
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, Any

import requests
from zapv2 import ZAPv2


class ZenScan:
    """Main class for the ZenScan security scanner."""
    
    def __init__(self, zap_proxy: str = "http://127.0.0.1:8080"):
        """
        Initialize ZenScan with ZAP proxy configuration.
        
        Args:
            zap_proxy: URL of the ZAP proxy (default: http://127.0.0.1:8080)
        """
        self.zap_proxy = zap_proxy
        self.zap = ZAPv2(proxies={'http': zap_proxy, 'https': zap_proxy})
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('zenscan.log')
            ]
        )
        return logging.getLogger(__name__)
    
    def check_zap_connection(self) -> bool:
        """Check if ZAP is running and accessible."""
        try:
            self.logger.info("Checking ZAP connection...")
            version = self.zap.core.version
            self.logger.info(f"Connected to ZAP version: {version}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to ZAP: {e}")
            self.logger.error("Please ensure ZAP is running on the specified proxy address")
            return False
    
    def validate_url(self, url: str) -> str:
        """
        Validate and normalize the target URL.
        
        Args:
            url: The URL to validate
            
        Returns:
            Normalized URL string
            
        Raises:
            ValueError: If URL is invalid
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")
            
        return url
    
    def start_spider(self, target_url: str) -> str:
        """
        Start ZAP spider scan on the target URL.
        
        Args:
            target_url: The URL to scan
            
        Returns:
            Spider scan ID
        """
        self.logger.info(f"Starting spider scan on: {target_url}")
        
        # Configure spider
        self.zap.spider.scan(target_url)
        
        # Wait for spider to complete
        while int(self.zap.spider.status()) < 100:
            self.logger.info(f"Spider progress: {self.zap.spider.status()}%")
            time.sleep(2)
            
        self.logger.info("Spider scan completed")
        return self.zap.spider.status()
    
    def start_active_scan(self, target_url: str) -> str:
        """
        Start ZAP active scan on the target URL.
        
        Args:
            target_url: The URL to scan
            
        Returns:
            Active scan ID
        """
        self.logger.info(f"Starting active scan on: {target_url}")
        
        # Configure and start active scan
        self.zap.ascan.scan(target_url)
        
        # Wait for active scan to complete
        while int(self.zap.ascan.status()) < 100:
            self.logger.info(f"Active scan progress: {self.zap.ascan.status()}%")
            time.sleep(5)
            
        self.logger.info("Active scan completed")
        return self.zap.ascan.status()
    
    def get_alerts(self) -> list:
        """
        Retrieve security alerts from ZAP.
        
        Returns:
            List of security alerts
        """
        self.logger.info("Retrieving security alerts...")
        alerts = self.zap.core.alerts()
        self.logger.info(f"Found {len(alerts)} security alerts")
        return alerts
    
    def generate_html_report(self, alerts: list, target_url: str, output_file: str) -> None:
        """
        Generate HTML security report from ZAP alerts.
        
        Args:
            alerts: List of security alerts from ZAP
            target_url: The scanned target URL
            output_file: Path to output HTML file
        """
        self.logger.info(f"Generating HTML report: {output_file}")
        
        # Group alerts by risk level
        high_risk = [alert for alert in alerts if alert['risk'] == 'High']
        medium_risk = [alert for alert in alerts if alert['risk'] == 'Medium']
        low_risk = [alert for alert in alerts if alert['risk'] == 'Low']
        info_risk = [alert for alert in alerts if alert['risk'] == 'Informational']
        
        html_content = self._create_html_template(
            target_url, high_risk, medium_risk, low_risk, info_risk, len(alerts)
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        self.logger.info(f"HTML report saved to: {output_file}")
    
    def _create_html_template(self, target_url: str, high_risk: list, medium_risk: list, 
                            low_risk: list, info_risk: list, total_alerts: int) -> str:
        """Create HTML template for the security report."""
        
        def format_alert(alert: dict) -> str:
            """Format individual alert for HTML display."""
            return f"""
            <div class="alert-item">
                <h4>{alert['name']}</h4>
                <p><strong>Risk:</strong> {alert['risk']}</p>
                <p><strong>URL:</strong> {alert['url']}</p>
                <p><strong>Description:</strong> {alert['description']}</p>
                <p><strong>Solution:</strong> {alert['solution']}</p>
                <p><strong>Reference:</strong> {alert['reference']}</p>
            </div>
            """
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZenScan Security Report - {target_url}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .header h1 {{
            color: #2c3e50;
            margin: 0;
        }}
        .header p {{
            color: #7f8c8d;
            margin: 5px 0;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }}
        .high-risk {{ background-color: #e74c3c; }}
        .medium-risk {{ background-color: #f39c12; }}
        .low-risk {{ background-color: #f1c40f; color: #333; }}
        .info-risk {{ background-color: #3498db; }}
        .total {{ background-color: #2c3e50; }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 2em;
        }}
        .summary-card p {{
            margin: 0;
            font-size: 1.1em;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
        }}
        .alert-item {{
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        .alert-item h4 {{
            margin: 0 0 15px 0;
            color: #2c3e50;
        }}
        .alert-item p {{
            margin: 8px 0;
        }}
        .no-alerts {{
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
            padding: 40px;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ZenScan Security Report</h1>
            <p><strong>Target URL:</strong> {target_url}</p>
            <p><strong>Scan Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card total">
                <h3>{total_alerts}</h3>
                <p>Total Issues</p>
            </div>
            <div class="summary-card high-risk">
                <h3>{len(high_risk)}</h3>
                <p>High Risk</p>
            </div>
            <div class="summary-card medium-risk">
                <h3>{len(medium_risk)}</h3>
                <p>Medium Risk</p>
            </div>
            <div class="summary-card low-risk">
                <h3>{len(low_risk)}</h3>
                <p>Low Risk</p>
            </div>
            <div class="summary-card info-risk">
                <h3>{len(info_risk)}</h3>
                <p>Informational</p>
            </div>
        </div>
        
        {f'<div class="section"><h2>🚨 High Risk Issues ({len(high_risk)})</h2>' + ''.join([format_alert(alert) for alert in high_risk]) + '</div>' if high_risk else ''}
        
        {f'<div class="section"><h2>⚠️ Medium Risk Issues ({len(medium_risk)})</h2>' + ''.join([format_alert(alert) for alert in medium_risk]) + '</div>' if medium_risk else ''}
        
        {f'<div class="section"><h2>ℹ️ Low Risk Issues ({len(low_risk)})</h2>' + ''.join([format_alert(alert) for alert in low_risk]) + '</div>' if low_risk else ''}
        
        {f'<div class="section"><h2>📋 Informational Issues ({len(info_risk)})</h2>' + ''.join([format_alert(alert) for alert in info_risk]) + '</div>' if info_risk else ''}
        
        {f'<div class="no-alerts"><h2>✅ No Security Issues Found</h2><p>Congratulations! No security vulnerabilities were detected in this scan.</p></div>' if total_alerts == 0 else ''}
        
        <div class="footer">
            <p>Generated by ZenScan - OWASP ZAP Security Scanner</p>
        </div>
    </div>
</body>
</html>
        """
        return html
    
    def scan_website(self, target_url: str, output_file: str) -> bool:
        """
        Perform complete security scan of a website.
        
        Args:
            target_url: The URL to scan
            output_file: Path to output HTML file
            
        Returns:
            True if scan completed successfully, False otherwise
        """
        try:
            # Validate URL
            target_url = self.validate_url(target_url)
            
            # Check ZAP connection
            if not self.check_zap_connection():
                return False
            
            # Start spider scan
            self.start_spider(target_url)
            
            # Start active scan
            self.start_active_scan(target_url)
            
            # Get alerts
            alerts = self.get_alerts()
            
            # Generate HTML report
            self.generate_html_report(alerts, target_url, output_file)
            
            self.logger.info("Scan completed successfully!")
            return True
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return False


def main():
    """Main entry point for the ZenScan CLI tool."""
    parser = argparse.ArgumentParser(
        description="ZenScan - OWASP ZAP Security Scanner CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python zenscan.py https://example.com
  python zenscan.py example.com -o report.html
  python zenscan.py https://example.com --zap-proxy http://localhost:8080
        """
    )
    
    parser.add_argument(
        'url',
        help='Target URL to scan (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='security_report.html',
        help='Output HTML file path (default: security_report.html)'
    )
    
    parser.add_argument(
        '--zap-proxy',
        default='http://127.0.0.1:8080',
        help='ZAP proxy URL (default: http://127.0.0.1:8080)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create ZenScan instance
    scanner = ZenScan(zap_proxy=args.zap_proxy)
    
    # Perform scan
    success = scanner.scan_website(args.url, args.output)
    
    if success:
        print(f"\n✅ Scan completed successfully!")
        print(f"📄 Report saved to: {args.output}")
        sys.exit(0)
    else:
        print("\n❌ Scan failed. Check the logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()

