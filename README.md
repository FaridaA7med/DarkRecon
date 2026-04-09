# 🔐 DarkRecon - Advanced Web Reconnaissance Tool

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-Educational-green)](LICENSE)

DarkRecon is a comprehensive Python tool for **passive and active web reconnaissance**, designed for ethical hacking and penetration testing.

## ✨ Features

### 🔍 Passive Reconnaissance (No direct contact)
- **WHOIS lookup** - Domain registration information
- **DNS enumeration** - A, MX, NS, TXT, CNAME, SOA records
- **SSL/TLS analysis** - Certificate details & SANs extraction
- **External OSINT tools** - Subfinder, Amass, Assetfinder integration

### ⚡ Active Reconnaissance (Direct interaction)
- **Port scanning** - Multi-threaded TCP connect scan
- **Banner grabbing** - Service version detection
- **Directory fuzzing** - Hidden path discovery
- **HTTP header analysis** - Security headers audit

### 🛡️ Advanced Intelligence
- **Shodan integration** - IP intelligence & exposed services
- **CVE vulnerability lookup** - Automatic CVE detection
- **Google Dorks generator** - OSINT search queries
- **Wayback Machine** - Archived URLs discovery

### 📊 Reporting
- **JSON output** - Machine-readable format
- **Markdown reports** - Human-readable format
- **Professional reports** - Risk ratings & recommendations

### 🎮 Interactive Mode
- Ask before each module (Y/n)
- Colored terminal output
- Progress tracking
### Usage

# Interactive full scan
python3 main.py example.com --mode full --interactive

# Passive scan only
python3 main.py example.com --mode passive

# Active scan with custom ports
python3 main.py example.com --mode active --ports 80,443,8080

# With Shodan API
export SHODAN_API_KEY="your_api_key"
python3 main.py example.com --mode full --interactive

## 📦 Installation

```bash
git clone https://github.com/FaridaA7med/DarkRecon.git
cd DarkRecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
