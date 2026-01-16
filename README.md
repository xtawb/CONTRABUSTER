<p align="center">
  <img src="/img/logo.png" alt="CONTRABUSTER Logo" width="200">
</p>

<h1 align="center">ＣＯＮＴＲＡＢＵＳＴＥＲ</h1>

<h3 align="center">Advanced Container Intelligence Scanner</h3>

<p align="center">
  <b>Professional reconnaissance tool for deep analysis of public containers, CDNs, and directory listings</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.1-red" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen" alt="Status">
</p>

<p align="center">
  <a href="#Overview">Overview</a> •
  <a href="#Key Features">Features</a> •
  <a href="#Installation">Installation</a> •
  <a href="#Usage">Usage</a> •
  <a href="#Practical Examples">Examples</a> •
  <a href="#Technical Architecture">Architecture</a> •
  <a href="#Contributing">Contributing</a> •
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/xtawb/CONTRABUSTER/main/assets/demo.gif" alt="CONTRABUSTER Demo" width="800">
</p>

## Overview

**CONTRABUSTER** is an elite security reconnaissance tool designed for professional bug bounty hunters, penetration testers, and security researchers. It performs deep, intelligent analysis of public containers, CDNs, and directory listings to uncover:

- 🔐 **Exposed Secrets & Credentials** (AWS keys, API tokens, database credentials)
- 🔗 **Hidden Attack Vectors** (misconfigurations, exposed endpoints, sensitive files)
- 🎯 **Impact Assessment** (severity ranking, exploitability analysis, attack scenarios)
- 📊 **Professional Reporting** (bug bounty ready reports with clear evidence)

Unlike traditional scanners, CONTRABUSTER combines:
- **Static Code Analysis** (JavaScript, JSON, config files)
- **Entropy-based Detection** (high-entropy string identification)
- **Context-Aware Pattern Matching** (reduced false positives)
- **Attack Scenario Generation** (multi-step exploitation paths)

## Key Features

### 🔍 **Advanced Discovery Engine**
- **Recursive Directory Scanning** - Fully automated directory traversal
- **Smart File Classification** - Intelligent filtering of irrelevant files
- **Pagination Support** - Automatic handling of paginated listings
- **Path Exclusion** - Configurable ignore patterns for common directories

### 🎯 **Intelligent Secret Detection**
- **50+ Secret Patterns** - Comprehensive coverage of cloud providers, APIs, databases
- **Entropy Analysis** - Shannon entropy calculation for high-entropy strings
- **Context Validation** - Context-aware matching to reduce false positives
- **Provider Validation** - Format validation for AWS, GCP, Azure keys

### 🚀 **JavaScript Analysis Engine**
- **Endpoint Extraction** - Automatic discovery of API endpoints, GraphQL, WebSockets
- **Auth Logic Analysis** - Identification of authentication mechanisms
- **IDOR Candidates** - Detection of potential IDOR vulnerabilities
- **Feature Flag Discovery** - Identification of debug flags and environment switches

### 📈 **Impact Assessment System**
- **Severity Classification** - Informational → Critical with clear criteria
- **Exploitability Scoring** - Likelihood of successful exploitation
- **Attack Scenario Generation** - Multi-step attack paths from findings
- **Confidence Scoring** - 0-100% confidence ratings for each finding

### 🎨 **Professional Interface**
- **Color-Coded Output** - Severity-based color system (Critical=Red, High=Orange, etc.)
- **Live Progress Updates** - Real-time scanning status with progress bars
- **Interactive CLI** - Professional interface without distracting emojis
- **Multiple Output Formats** - JSON, HTML, TXT reports

### 🔄 **Auto-Update System**
- **Version Checking** - Automatic update notifications
- **Safe Update Process** - Backup and verification before updates
- **Changelog Display** - What's new in each update
- **User Consent** - Always asks before updating

## Installation

### Prerequisites
- Python 3.8 or higher
- pip 20.0+
- Internet connection (for auto-updates)

### Quick Installation

#### Method 1: Direct Download
```bash
# Download the tool
curl -L https://raw.githubusercontent.com/xtawb/CONTRABUSTER/main/contrabuster.py -o contrabuster.py

# Make executable
chmod +x contrabuster.py

# Run with --help to see options
python3 contrabuster.py --help
```

#### Method 2: From Source
```bash
# Clone the repository
git clone https://github.com/xtawb/CONTRABUSTER.git
cd CONTRABUSTER

# Create virtual environment (recommended)
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 contrabuster.py --help
```

#### Method 3: Global Installation
```bash
# Make globally executable
sudo cp contrabuster.py /usr/local/bin/contrabuster
sudo chmod +x /usr/local/bin/contrabuster

# Run from anywhere
contrabuster --help
```

### Verification
```bash
# Test installation
python3 contrabuster.py --version
# Output: CONTRABUSTER v1.0.1

# Check for updates
python3 contrabuster.py --check-update
```

## Usage

### Basic Scanning
```bash
# Basic scan of a public container
python3 contrabuster.py -u https://s3.amazonaws.com/example-bucket/

# Scan with custom extensions
python3 contrabuster.py -u https://cdn.example.com/ --extensions js,json,env

# Scan with increased threads for performance
python3 contrabuster.py -u https://example.com/assets/ -t 20

# Save results to file
python3 contrabuster.py -u https://target.com/ -o scan_results
```

### Advanced Scanning
```bash
# Deep scan with recursion (up to 5 levels)
python3 contrabuster.py -u https://target.com/ --max-depth 5

# Scan ignoring specific extensions
python3 contrabuster.py -u https://target.com/ --ignore-extensions jpg,png,mp4

# Force scan of non-text files
python3 contrabuster.py -u https://target.com/ --force

# Verbose mode with detailed output
python3 contrabuster.py -u https://target.com/ --verbose

# Quiet mode (minimal output)
python3 contrabuster.py -u https://target.com/ --quiet -o results
```

### Update Management
```bash
# Check for updates without scanning
python3 contrabuster.py --check-update

# Force update to latest version
python3 contrabuster.py --force-update

# Disable auto-update check
python3 contrabuster.py --no-update -u https://target.com/
```

### Output Options
```bash
# Generate JSON report only
python3 contrabuster.py -u https://target.com/ --json-only -o report

# Generate HTML report only
python3 contrabuster.py -u https://target.com/ --html-only -o report

# Filter by minimum severity
python3 contrabuster.py -u https://target.com/ --min-severity HIGH
```

## Practical Examples

### Example 1: Bug Bounty Reconnaissance
```bash
# Comprehensive scan of a target's CDN with full reporting
python3 contrabuster.py \
  -u https://assets.target-company.com/ \
  -t 25 \
  --extensions js,json,env,config,yml \
  --verbose \
  -o bugbounty_report_$(date +%Y%m%d)
```

### Example 2: Cloud Storage Security Audit
```bash
# Security audit of AWS S3 bucket
python3 contrabuster.py \
  -u https://s3.amazonaws.com/company-backups/ \
  --max-depth 3 \
  --ignore-extensions log,tmp,bak \
  --min-severity MEDIUM \
  -o s3_audit_report
```

### Example 3: JavaScript Application Analysis
```bash
# Deep analysis of JavaScript files
python3 contrabuster.py \
  -u https://app.example.com/static/js/ \
  --extensions js,map \
  --force \
  -o js_analysis
```

## 🔧 Command Reference

### Required Arguments
| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | URL of public container or directory listing | `-u https://example.com/assets/` |

### Scan Configuration
| Option | Description | Default |
|--------|-------------|---------|
| `-e, --extensions` | File extensions to scan | `js,json,txt,env,config,yml,yaml,xml,ini,conf` |
| `--ignore-extensions` | Extensions to ignore | None |
| `--ignore-paths` | Paths to ignore | `.git, node_modules, vendor` |
| `-t, --threads` | Concurrent threads | `10` |
| `--max-depth` | Maximum recursion depth | `10` |
| `--max-size` | Maximum file size (bytes) | `52428800` (50MB) |

### Update Options
| Option | Description |
|--------|-------------|
| `--no-update` | Disable auto-update check |
| `--check-update` | Check for updates without scanning |
| `--force-update` | Force update to latest version |

### Output Options
| Option | Description |
|--------|-------------|
| `-o, --output` | Output base name for reports |
| `--json-only` | Output only JSON report |
| `--html-only` | Output only HTML report |
| `--min-severity` | Minimum severity to report | `LOW` |

### Mode Selection
| Option | Description |
|--------|-------------|
| `-q, --quiet` | Quiet mode - minimal output |
| `-v, --verbose` | Verbose mode - detailed information |
| `-d, --debug` | Debug mode - show debug information |
| `--force` | Force scan of non-text files |

## 📊 Output Samples

### Console Output
```
╔══════════════════════════════════════════════════════════════╗
║                        SCAN SUMMARY                           ║
╚══════════════════════════════════════════════════════════════╝

Files Discovered: 247
Files Scanned:    203
Scan Duration:    42.3 seconds

Findings Breakdown:
  Critical: 2
  High:     5
  Medium:   12
  Low:      8
  Informational: 15

═══════════════════════════════════════════════════════════════
CRITICAL SEVERITY FINDINGS (2)
═══════════════════════════════════════════════════════════════

[+] File: config.json
    Type: AWS_ACCESS_KEY
    Description: AWS Access Key ID
    Severity: Critical
    Confidence: 90.0%
    Exploitability: High - Direct impact, immediate action required
    Match: AKIAIOSFODNN7EXAMPLE...
    Recommendation: Immediately rotate AWS keys and audit usage
```

### JSON Report Excerpt
```json
{
  "metadata": {
    "generated_at": "2025-01-16T10:30:00",
    "tool": "CONTRABUSTER - Advanced Container Intelligence Scanner",
    "version": "1.0.1",
    "developer": "xtawb",
    "contact": "https://linktr.ee/xtawb"
  },
  "statistics": {
    "total_files": 247,
    "scanned_files": 203,
    "critical_findings": 2,
    "high_findings": 5,
    "medium_findings": 12
  },
  "findings": [
    {
      "file_url": "https://s3.amazonaws.com/bucket/config.json",
      "file_name": "config.json",
      "rule_name": "AWS_ACCESS_KEY",
      "description": "AWS Access Key ID",
      "severity": "Critical",
      "match": "AKIAIOSFODNN7EXAMPLE...",
      "confidence": 0.9,
      "recommendation": "Immediately rotate AWS keys and audit usage"
    }
  ]
}
```

### HTML Report Preview
![HTML Report](https://raw.githubusercontent.com/xtawb/CONTRABUSTER/main/assets/html_report.png)

## Technical Architecture

```mermaid
graph TB
    A[User Input] --> B[Update Manager]
    B --> C{Update Available?}
    C -->|Yes| D[Update Notification]
    C -->|No| E[Discovery Engine]
    
    D --> F{Update?}
    F -->|Yes| G[Download & Apply]
    F -->|No| E
    
    E --> H[File Discovery]
    H --> I[File Classification]
    I --> J[Content Fetching]
    J --> K[Secret Detection Engine]
    
    subgraph "Analysis Pipeline"
        K --> L[Pattern Matching]
        K --> M[Entropy Analysis]
        K --> N[JS Analysis Engine]
        L --> O[Findings]
        M --> O
        N --> P[JS Features]
    end
    
    O --> Q[Impact Assessment]
    P --> Q
    Q --> R[Report Generator]
    R --> S[JSON Report]
    R --> T[HTML Report]
    R --> U[CLI Output]
    
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style O fill:#ff9999,stroke:#333,stroke-width:2px
    style S fill:#99ff99,stroke:#333,stroke-width:2px
```

### Core Components

1. **Discovery Engine** - Recursive directory traversal with smart filtering
2. **Secret Detection Engine** - 50+ patterns with entropy and context analysis
3. **JS Analysis Engine** - JavaScript static analysis for endpoints and logic
4. **Impact Engine** - Severity assessment and attack scenario generation
5. **Report Generator** - Multi-format reporting (JSON, HTML, TXT)
6. **Update Manager** - Automatic version checking and updates
7. **CLI Interface** - Professional, color-coded user interface

## 🔍 Detection Capabilities

### Cloud Providers
- **AWS**: Access Keys, Secret Keys, Session Tokens
- **Google Cloud**: API Keys, Service Accounts, OAuth Tokens
- **Azure**: Storage Keys, Connection Strings, SAS Tokens
- **Firebase**: Database URLs, API Keys, Configurations

### Authentication & Tokens
- JWT Tokens, Bearer Tokens, OAuth Secrets
- Session Cookies, API Keys, Private Keys
- SSH Keys, SSL Certificates, PGP Keys

### Database & Services
- MySQL, PostgreSQL, MongoDB, Redis URLs
- Elasticsearch, Memcached, RabbitMQ connections
- AWS RDS, DynamoDB, S3 configurations

### Communication Services
- Slack Tokens & Webhooks, Discord Bots & Webhooks
- Telegram Bots, Twilio SIDs, SendGrid API Keys
- Mailgun, Postmark, SendinBlue credentials

### CI/CD & Version Control
- GitHub Tokens, GitLab Tokens, Bitbucket Credentials
- Jenkins, CircleCI, Travis CI, GitLab CI tokens
- Docker Hub, Container Registry credentials

### Payment Processors
- Stripe (Live/Test Keys), PayPal (Access Tokens)
- Braintree, Square, Authorize.net credentials

## 🛡️ Security & Ethics

### Important Notice
**CONTRABUSTER** is designed for:
- ✅ Authorized security testing
- ✅ Bug bounty programs with written permission
- ✅ Security audits of your own systems
- ✅ Educational purposes in controlled environments

**Never use this tool for:**
- ❌ Unauthorized testing of systems you don't own
- ❌ Malicious activities
- ❌ Violating terms of service
- ❌ Any illegal purposes

### Safety Features
- **Read-Only Operations** - No exploitation, only discovery
- **Rate Limiting** - Built-in delays to avoid overwhelming targets
- **Legal Warnings** - Clear disclaimer at startup
- **Responsible Disclosure** - Encouraged in all findings

## Contributing

We welcome contributions from the security community! Here's how you can help:

### How to Contribute
1. **Fork the Repository**
   ```bash
   git fork https://github.com/xtawb/CONTRABUSTER.git
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Add new secret patterns
   - Improve analysis algorithms
   - Enhance reporting capabilities
   - Fix bugs or improve performance

4. **Test Your Changes**
   ```bash
   python3 -m pytest tests/
   python3 contrabuster.py --test
   ```

5. **Submit a Pull Request**
   - Clear description of changes
   - Reference any related issues
   - Include tests if applicable

### Contribution Areas
- **New Patterns**: Add detection for additional services
- **Performance**: Optimize scanning algorithms
- **Documentation**: Improve guides and examples
- **Testing**: Expand test coverage
- **Internationalization**: Add multi-language support

### Code Standards
- Follow PEP 8 guidelines
- Use type hints for all functions
- Write comprehensive docstrings
- Include unit tests for new features
- Maintain backward compatibility

## 📚 Documentation

### Additional Resources
- **[Wiki](https://github.com/xtawb/CONTRABUSTER/wiki)** - Detailed documentation
- **[Pattern Guide](https://github.com/xtawb/CONTRABUSTER/wiki/Patterns)** - Custom pattern creation
- **[API Reference](https://github.com/xtawb/CONTRABUSTER/wiki/API)** - Integration guide
- **[Troubleshooting](https://github.com/xtawb/CONTRABUSTER/wiki/Troubleshooting)** - Common issues

### Quick Links
- [Installation Guide](https://github.com/xtawb/CONTRABUSTER/wiki/Installation)
- [Usage Examples](https://github.com/xtawb/CONTRABUSTER/wiki/Examples)
- [Configuration Options](https://github.com/xtawb/CONTRABUSTER/wiki/Configuration)
- [Report Format](https://github.com/xtawb/CONTRABUSTER/wiki/Reports)

## 🐛 Troubleshooting

### Common Issues

#### Issue: "ModuleNotFoundError"
**Solution:**
```bash
# Install missing dependencies
pip install -r requirements.txt

# Or install specific module
pip install aiohttp regex entropy
```

#### Issue: Slow Scanning
**Solution:**
```bash
# Increase threads
python3 contrabuster.py -u https://target.com/ -t 30

# Limit file size
python3 contrabuster.py -u https://target.com/ --max-size 10485760  # 10MB

# Skip large files
python3 contrabuster.py -u https://target.com/ --ignore-extensions mp4,zip,iso
```

#### Issue: Too Many False Positives
**Solution:**
```bash
# Increase minimum severity
python3 contrabuster.py -u https://target.com/ --min-severity MEDIUM

# Use verbose mode to see context
python3 contrabuster.py -u https://target.com/ --verbose
```

### Getting Help
1. Check the [Wiki](https://github.com/xtawb/CONTRABUSTER/wiki) first
2. Search [Issues](https://github.com/xtawb/CONTRABUSTER/issues)
3. Create a new issue with:
   - Error message
   - Command used
   - Python version
   - Operating system

## Acknowledgments

- **Security Researchers** - For inspiration and methodologies
- **Open Source Community** - For tools and libraries that made this possible
- **Bug Bounty Platforms** - For providing legitimate testing grounds
- **Contributors** - Everyone who helps improve this tool

## 📞 Contact & Support

### Developer
- **Name**: xtawb
- **Contact**: https://linktr.ee/xtawb

### Support Channels
- **GitHub Issues**: [Report Bugs](https://github.com/xtawb/CONTRABUSTER/issues)
- **Security Issues**: Please report via GitHub Security Advisory

### Community
- Join the discussion on security forums
- Share your findings and improvements
- Contribute patterns and detection rules


