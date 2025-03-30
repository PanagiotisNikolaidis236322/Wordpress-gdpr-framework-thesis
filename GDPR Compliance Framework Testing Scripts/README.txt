# GDPR Compliance Testing Scripts

This repository contains a set of testing scripts designed to validate and assess GDPR compliance features in WordPress installations. These scripts provide automated testing for key GDPR requirements, helping developers and administrators ensure their WordPress sites meet privacy and data protection regulations.

## Overview

The GDPR Compliance Framework Testing Scripts evaluate several aspects of GDPR compliance:

1. **Consent Management** - Tests for proper implementation of user consent collection, storage, and validation.
2. **Security and Authentication** - Validates encryption, access control, and data protection mechanisms.
3. **User Rights Fulfillment** - Checks for proper implementation of data access, rectification, deletion, and portability rights.
4. **Audit Logging** - Verifies that tamper-proof, complete audit logs are maintained.
5. **API Security** - Tests API authentication, authorization, and security controls.

## Requirements

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)
- WordPress installation to test

### Dependencies

Install the required Python packages:

```bash
pip install requests beautifulsoup4 selenium faker pycryptodome
```

For GUI-based testing (Selenium):
- Chrome or Firefox browser
- Matching WebDriver (chromedriver or geckodriver)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/PanagiotisNikolaidis236322/Wordpress-gdpr-framework-thesis.git
cd Wordpress-gdpr-framework-thesis
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make scripts executable:
```bash
chmod +x *.py
```

## Usage

### Consent Validation Tester

Tests GDPR consent implementation (banners, storage, revocation):

```bash
./consent_validation.py https://your-wordpress-site.com [--output report.json] [--visible]
```

Options:
- `--output` / `-o`: Save results to a JSON file
- `--visible` / `-v`: Run in visible mode (not headless)

### GDPR Security Scanner

Assesses security aspects of GDPR implementation:

```bash
./gdpr_security_scanner.py https://your-wordpress-site.com [--output report.json] [--no-verify]
```

Options:
- `--output` / `-o`: Save results to a JSON file
- `--no-verify`: Disable SSL verification for testing
- `--timeout`: Set request timeout in seconds (default: 10)

### User Rights Tester

Validates implementation of GDPR user rights (access, rectification, erasure):

```bash
./user_rights_tester.py https://your-wordpress-site.com --admin-username admin --admin-password password [--output report.json]
```

Options:
- `--admin-username`: WordPress admin username
- `--admin-password`: WordPress admin password
- `--admin-url`: WordPress admin URL if different from default
- `--output` / `-o`: Save results to a JSON file
- `--visible` / `-v`: Run in visible mode (not headless)

### Audit Log Tester

Checks for tamper-proof audit logging:

```bash
./audit_log_tester.py https://your-wordpress-site.com --admin-username admin --admin-password password [--output report.json]
```

Options:
- `--admin-username`: WordPress admin username
- `--admin-password`: WordPress admin password
- `--admin-url`: WordPress admin URL if different from default
- `--output` / `-o`: Save results to a JSON file
- `--timeout`: Set request timeout in seconds (default: 10)
- `--no-verify`: Disable SSL verification for testing

### API Authentication Tester

Tests API authentication for GDPR-related endpoints:

```bash
./api_auth_tester.py https://your-wordpress-site.com --admin-username admin --admin-password password [--output report.json]
```

Options:
- `--admin-username`: WordPress admin username
- `--admin-password`: WordPress admin password
- `--admin-url`: WordPress admin URL if different from default
- `--output` / `-o`: Save results to a JSON file
- `--timeout`: Set request timeout in seconds (default: 10)
- `--no-verify`: Disable SSL verification for testing

## Script Details

### Consent Validation Script (`consent_validation.py`)

Tests the implementation of GDPR consent collection, including:
- Cookie banner presence and visibility
- Granular consent options
- Consent storage and persistence
- Consent revocation mechanisms

### GDPR Security Scanner (`gdpr_security_scanner.py`)

Assesses security aspects of GDPR implementation:
- HTTPS/SSL configuration
- Security headers
- WordPress version exposure
- API security
- Sensitive file permissions

### User Rights Tester (`user_rights_tester.py`)

Validates GDPR user rights implementation:
- Data access (Article 15)
- Data rectification (Article 16)
- Data erasure (Article 17)
- Data portability (Article 20)

The script creates a test user, performs various rights requests, and validates responses.

### Audit Log Tester (`audit_log_tester.py`)

Tests GDPR audit logging implementation:
- Audit log presence and structure
- Log entry completeness
- Evidence of tamper-protection
- Log modification security
- Retention periods

### API Authentication Tester (`api_auth_tester.py`)

Tests API authentication for GDPR-related endpoints:
- API endpoint discovery
- Authentication requirements
- Authentication method evaluation
- Token security
- Rate limiting

## Output Formats

All scripts generate:
1. **Console output** with a summary of test results
2. **Optional JSON report** with detailed findings (using the `--output` option)

Example console output:
```
============================================================
GDPR SECURITY SCAN REPORT: https://example.com
============================================================
Timestamp: 2025-03-30T14:30:25.123456
Security Score: 78.5%
Tests: 25 total, 18 passed, 3 warnings, 4 failed, 0 errors
------------------------------------------------------------

Transport Security:
  ✅ PASS: header_strict-transport-security - HTTP Strict Transport Security (HSTS) header is properly set
  ✅ PASS: ssl_certificate - SSL certificate is valid for 234 more days
...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request

## Requirements for GDPR Compliance Framework Testing Scripts

Core HTTP library
requests>=2.28.1

HTML parsing
beautifulsoup4>=4.11.1

Automated browser testing
selenium>=4.5.0

Fake data generation for test users
faker>=15.0.0

Cryptographic validation
pycryptodome>=3.15.0

XML parsing (for data exports)
lxml>=4.9.1

Command line argument parsing
argparse>=1.4.0