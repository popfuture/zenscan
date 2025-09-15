#!/usr/bin/env python3
"""
Setup script for ZenScan - OWASP ZAP Security Scanner CLI Tool
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def check_python_version():
    """Check if Python version is 3.7 or higher."""
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True


def install_requirements():
    """Install Python requirements."""
    try:
        print("📦 Installing Python dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def check_zap_installation():
    """Check if OWASP ZAP is installed and accessible."""
    print("\n🔍 Checking OWASP ZAP installation...")
    
    # Try to connect to ZAP
    try:
        import requests
        response = requests.get("http://127.0.0.1:8080", timeout=5)
        if response.status_code == 200:
            print("✅ OWASP ZAP is running and accessible")
            return True
    except:
        pass
    
    print("⚠️  OWASP ZAP is not running or not accessible")
    print("   Please install and start OWASP ZAP:")
    print("   1. Download from: https://www.zaproxy.org/download/")
    print("   2. Start ZAP and ensure it's running on port 8080")
    print("   3. Or run: zap.sh -daemon -port 8080 -host 0.0.0.0")
    return False


def create_sample_script():
    """Create a sample script for testing."""
    sample_script = """#!/usr/bin/env python3
# Sample ZenScan usage script

from zenscan import ZenScan

def test_scan():
    # Initialize scanner
    scanner = ZenScan()
    
    # Test URL (replace with your target)
    test_url = "https://httpbin.org"
    
    print(f"Testing scan on: {test_url}")
    
    # Perform scan
    success = scanner.scan_website(test_url, "test_report.html")
    
    if success:
        print("✅ Test scan completed successfully!")
        print("📄 Check test_report.html for results")
    else:
        print("❌ Test scan failed")

if __name__ == "__main__":
    test_scan()
"""
    
    with open("test_scan.py", "w") as f:
        f.write(sample_script)
    
    os.chmod("test_scan.py", 0o755)
    print("✅ Created test_scan.py for testing")


def main():
    """Main setup function."""
    print("🛡️  ZenScan Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Check ZAP installation
    zap_available = check_zap_installation()
    
    # Create sample script
    create_sample_script()
    
    print("\n🎉 Setup completed!")
    print("\nNext steps:")
    print("1. Ensure OWASP ZAP is running (if not already)")
    print("2. Test the installation:")
    print("   python test_scan.py")
    print("3. Run your first scan:")
    print("   python zenscan.py https://example.com")
    
    if not zap_available:
        print("\n⚠️  Remember to start OWASP ZAP before running scans!")


if __name__ == "__main__":
    main()
