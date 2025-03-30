#!/usr/bin/env python3
"""
GDPR Security Scanner for WordPress
-----------------------------------
This script performs security testing on WordPress installations to validate GDPR-related security requirements
including encryption, authentication, and API security. It checks for common security issues that could
lead to unauthorized access to personal data.

Requirements:
- Python 3.6+
- requests
- BeautifulSoup4
- python-owasp-zap-v2.4 (optional, for ZAP integration)

Installation:
pip install requests beautifulsoup4 python-owasp-zap-v2.4

Author: Panagiotis Nikolaidis
"""

import argparse
import json
import re
import sys
import time
import logging
import socket
import ssl
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class GDPRSecurityScanner:
    """Security scanner for GDPR-related vulnerabilities in WordPress."""
    
    def __init__(self, target_url, admin_url=None, api_url=None, timeout=10, verify_ssl=True):
        """Initialize the scanner with target URLs."""
        self.target_url = target_url.rstrip('/')
        
        # Determine admin and API URLs if not provided
        if admin_url:
            self.admin_url = admin_url.rstrip('/')
        else:
            self.admin_url = f"{self.target_url}/wp-admin"
            
        if api_url:
            self.api_url = api_url.rstrip('/')
        else:
            self.api_url = f"{self.target_url}/wp-json"
        
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
        # Set a reasonable user agent
        self.session.headers.update({
            'User-Agent': 'GDPR Security Scanner/1.0 (https://github.com/PanagiotisNikolaidis236322/Wordpress-gdpr-framework-thesis)'
        })
        
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "tests": [],
            "overall_score": 0,
            "max_score": 0
        }
        
    def _add_test_result(self, category, test_name, status, score, max_score, message="", details=None):
        """Add a test result to the results dictionary."""
        self.results["tests"].append({
            "category": category,
            "name": test_name,
            "status": status,
            "score": score,
            "max_score": max_score,
            "message": message,
            "details": details or {}
        })
        self.results["overall_score"] += score
        self.results["max_score"] += max_score
        
        logger.info(f"[{category}] Test '{test_name}': {status} ({score}/{max_score}) - {message}")
    
    def check_ssl_security(self):
        """Check for secure HTTPS implementation and TLS version."""
        category = "Transport Security"
        
        # First check if HTTPS is available
        http_url = self.target_url.replace('https://', 'http://')
        try:
            response = self.session.get(http_url, allow_redirects=False, timeout=self.timeout, verify=False)
            
            if response.status_code in (301, 302, 307, 308) and 'https' in response.headers.get('Location', ''):
                self._add_test_result(
                    category,
                    "http_to_https_redirect",
                    "PASS",
                    1, 1,
                    "Site redirects HTTP to HTTPS"
                )
            else:
                self._add_test_result(
                    category,
                    "http_to_https_redirect",
                    "FAIL",
                    0, 1,
                    "Site does not redirect HTTP to HTTPS"
                )
                
        except requests.exceptions.RequestException as e:
            self._add_test_result(
                category,
                "http_to_https_redirect",
                "ERROR",
                0, 1,
                f"Error checking HTTP to HTTPS redirect: {str(e)}"
            )
        
        # Now check TLS version and cipher
        hostname = urllib.parse.urlparse(self.target_url).hostname
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    
                    # Check TLS version
                    if tls_version in ('TLSv1.3', 'TLSv1.2'):
                        self._add_test_result(
                            category,
                            "tls_version",
                            "PASS",
                            2, 2,
                            f"Strong TLS version in use: {tls_version}",
                            {"tls_version": tls_version, "cipher": cipher[0]}
                        )
                    elif tls_version == 'TLSv1.1':
                        self._add_test_result(
                            category,
                            "tls_version",
                            "WARNING",
                            1, 2,
                            f"Moderate TLS version in use: {tls_version}",
                            {"tls_version": tls_version, "cipher": cipher[0]}
                        )
                    else:
                        self._add_test_result(
                            category,
                            "tls_version",
                            "FAIL",
                            0, 2,
                            f"Weak TLS version in use: {tls_version}",
                            {"tls_version": tls_version, "cipher": cipher[0]}
                        )
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (not_after - datetime.now()).days
                    
                    if days_remaining > 30:
                        self._add_test_result(
                            category,
                            "ssl_certificate",
                            "PASS",
                            1, 1,
                            f"SSL certificate is valid for {days_remaining} more days",
                            {"expires": cert['notAfter'], "days_remaining": days_remaining}
                        )
                    elif days_remaining > 0:
                        self._add_test_result(
                            category,
                            "ssl_certificate",
                            "WARNING",
                            0.5, 1,
                            f"SSL certificate expires soon ({days_remaining} days)",
                            {"expires": cert['notAfter'], "days_remaining": days_remaining}
                        )
                    else:
                        self._add_test_result(
                            category,
                            "ssl_certificate",
                            "FAIL",
                            0, 1,
                            "SSL certificate has expired",
                            {"expires": cert['notAfter'], "days_remaining": days_remaining}
                        )
                    
        except socket.timeout:
            self._add_test_result(
                category,
                "tls_version",
                "ERROR",
                0, 2,
                "Connection timed out while checking TLS"
            )
            self._add_test_result(
                category,
                "ssl_certificate",
                "ERROR",
                0, 1,
                "Connection timed out while checking SSL certificate"
            )
        except socket.error as e:
            self._add_test_result(
                category,
                "tls_version",
                "ERROR",
                0, 2,
                f"Socket error while checking TLS: {str(e)}"
            )
            self._add_test_result(
                category,
                "ssl_certificate",
                "ERROR",
                0, 1,
                f"Socket error while checking SSL certificate: {str(e)}"
            )
        except Exception as e:
            self._add_test_result(
                category,
                "tls_version",
                "ERROR",
                0, 2,
                f"Error checking TLS: {str(e)}"
            )
            self._add_test_result(
                category,
                "ssl_certificate",
                "ERROR",
                0, 1,
                f"Error checking SSL certificate: {str(e)}"
            )
    
    def check_security_headers(self):
        """Check for important security headers."""
        category = "Security Headers"
        
        try:
            response = self.session.get(
                self.target_url, 
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': {
                    'name': 'HTTP Strict Transport Security (HSTS)',
                    'max_score': 2,
                    'regex': r'max-age=(\d+)',
                    'min_value': 15768000  # 6 months
                },
                'X-Content-Type-Options': {
                    'name': 'X-Content-Type-Options',
                    'max_score': 1,
                    'expected': 'nosniff'
                },
                'X-Frame-Options': {
                    'name': 'X-Frame-Options',
                    'max_score': 1,
                    'valid_values': ['DENY', 'SAMEORIGIN']
                },
                'Content-Security-Policy': {
                    'name': 'Content Security Policy (CSP)',
                    'max_score': 2,
                    'check_function': lambda value: 'default-src' in value or 'script-src' in value
                },
                'X-XSS-Protection': {
                    'name': 'X-XSS-Protection',
                    'max_score': 1,
                    'valid_values': ['1', '1; mode=block']
                },
                'Referrer-Policy': {
                    'name': 'Referrer Policy',
                    'max_score': 1,
                    'valid_values': ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
                },
                'Permissions-Policy': {
                    'name': 'Permissions Policy',
                    'max_score': 1,
                    'present_check': True
                },
                'Feature-Policy': {  # Older version of Permissions-Policy
                    'name': 'Feature Policy',
                    'max_score': 1,
                    'present_check': True,
                    'alternative_for': 'Permissions-Policy'
                }
            }
            
            # Track if an alternative header was found
            alternatives_found = set()
            
            for header, config in security_headers.items():
                if header in headers:
                    value = headers[header]
                    max_score = config['max_score']
                    
                    # Check if this is an alternative that was already satisfied
                    if 'alternative_for' in config and config['alternative_for'] in alternatives_found:
                        continue
                    
                    if 'expected' in config:
                        if value.lower() == config['expected'].lower():
                            self._add_test_result(
                                category,
                                f"header_{header.lower()}",
                                "PASS",
                                max_score, max_score,
                                f"{config['name']} header is properly set",
                                {"value": value}
                            )
                        else:
                            self._add_test_result(
                                category,
                                f"header_{header.lower()}",
                                "FAIL",
                                0, max_score,
                                f"{config['name']} header has incorrect value",
                                {"value": value, "expected": config['expected']}
                            )
                    
                    elif 'valid_values' in config:
                        if any(value.upper() == valid.upper() for valid in config['valid_values']):
                            self._add_test_result(
                                category,
                                f"header_{header.lower()}",
                                "PASS",
                                max_score, max_score,
                                f"{config['name']} header is properly set",
                                {"value": value}
                            )
                        else:
                            self._add_test_result(
                                category,
                                f"header_{header.lower()}",
                                "FAIL",
                                0, max_score,
                                f"{config['name']} header has incorrect value",
                                {"value": value, "valid_values": config['valid_values']}
                            )
                    
                    elif 'regex' in config:
                        match = re.search(config['regex'], value)
                        if match:
                            extracted_value = int(match.group(1))
                            if extracted_value >= config['min_value']:
                                self._add_test_result(
                                    category,
                                    f"header_{header.lower()}",
                                    "PASS",
                                    max_score, max_score,
                                    f"{config['name']} header has sufficient value",
                                    {"value": value, "extracted": extracted_value, "min_required": config['min_value']}
                                )
                            else:
                                self._add_test_result(
                                    category,
                                    f"header_{header.lower()}",
                                    "WARNING",
                                    max_score/2, max_score,
                                    f"{config['name']} header value is too low",
                                    {"value": value, "extracted": extracted_value, "min_required": config['min_value']}
                                )
                        else:
                            self._add_test_result(
                                category,
                                f"header_{header.lower()}",
                                "FAIL",
                                0, max_score,
                                f"{config['name']} header has invalid format",
                                {"value": value, "regex": config['regex']}
                            )
                    
                    elif 'check_function' in config:
                        if config['check_function'](value):
                            self._add_test_result(
                                category,
                                f"header_{header.lower()}",
                                "PASS",
                                max_score, max_score,
                                f"{config['name']} header is properly set",
                                {"value": value}
                            )
                        else:
                            self._add_test_result(
                                category,
                                f"header_{header.lower()}",
                                "WARNING",
                                max_score/2, max_score,
                                f"{config['name']} header may be incomplete",
                                {"value": value}
                            )
                    
                    elif 'present_check' in config:
                        self._add_test_result(
                            category,
                            f"header_{header.lower()}",
                            "PASS",
                            max_score, max_score,
                            f"{config['name']} header is present",
                            {"value": value}
                        )
                    
                    # Mark if this is an alternative
                    if 'alternative_for' in config:
                        alternatives_found.add(header)
                else:
                    # If header is not present, check if an alternative exists
                    if 'alternative_for' in config and config['alternative_for'] in alternatives_found:
                        # Skip since alternative is already satisfied
                        continue
                        
                    # Check if this is an alternative itself that was already satisfied
                    if header in alternatives_found:
                        continue
                        
                    self._add_test_result(
                        category,
                        f"header_{header.lower()}",
                        "FAIL",
                        0, config['max_score'],
                        f"{config['name']} header is missing"
                    )
                    
            # Check for cookie security
            cookies = response.cookies
            
            if cookies:
                secure_count = 0
                httponly_count = 0
                samesite_count = 0
                
                for cookie in cookies:
                    if cookie.secure:
                        secure_count += 1
                    if cookie.has_nonstandard_attr('httponly'):
                        httponly_count += 1
                    if cookie.has_nonstandard_attr('samesite'):
                        samesite_count += 1
                
                total_cookies = len(cookies)
                
                # Check Secure flag
                if secure_count == total_cookies:
                    self._add_test_result(
                        category,
                        "cookie_secure_flag",
                        "PASS",
                        1, 1,
                        "All cookies have Secure flag set",
                        {"secure_cookies": secure_count, "total_cookies": total_cookies}
                    )
                elif secure_count > 0:
                    self._add_test_result(
                        category,
                        "cookie_secure_flag",
                        "WARNING",
                        0.5, 1,
                        f"Only {secure_count} out of {total_cookies} cookies have Secure flag set",
                        {"secure_cookies": secure_count, "total_cookies": total_cookies}
                    )
                else:
                    self._add_test_result(
                        category,
                        "cookie_secure_flag",
                        "FAIL",
                        0, 1,
                        "No cookies have Secure flag set",
                        {"secure_cookies": 0, "total_cookies": total_cookies}
                    )
                
                # Check HttpOnly flag
                if httponly_count == total_cookies:
                    self._add_test_result(
                        category,
                        "cookie_httponly_flag",
                        "PASS",
                        1, 1,
                        "All cookies have HttpOnly flag set",
                        {"httponly_cookies": httponly_count, "total_cookies": total_cookies}
                    )
                elif httponly_count > 0:
                    self._add_test_result(
                        category,
                        "cookie_httponly_flag",
                        "WARNING",
                        0.5, 1,
                        f"Only {httponly_count} out of {total_cookies} cookies have HttpOnly flag set",
                        {"httponly_cookies": httponly_count, "total_cookies": total_cookies}
                    )
                else:
                    self._add_test_result(
                        category,
                        "cookie_httponly_flag",
                        "FAIL",
                        0, 1,
                        "No cookies have HttpOnly flag set",
                        {"httponly_cookies": 0, "total_cookies": total_cookies}
                    )
                
                # Check SameSite attribute
                if samesite_count == total_cookies:
                    self._add_test_result(
                        category,
                        "cookie_samesite_attribute",
                        "PASS",
                        1, 1,
                        "All cookies have SameSite attribute set",
                        {"samesite_cookies": samesite_count, "total_cookies": total_cookies}
                    )
                elif samesite_count > 0:
                    self._add_test_result(
                        category,
                        "cookie_samesite_attribute",
                        "WARNING",
                        0.5, 1,
                        f"Only {samesite_count} out of {total_cookies} cookies have SameSite attribute set",
                        {"samesite_cookies": samesite_count, "total_cookies": total_cookies}
                    )
                else:
                    self._add_test_result(
                        category,
                        "cookie_samesite_attribute",
                        "FAIL",
                        0, 1,
                        "No cookies have SameSite attribute set",
                        {"samesite_cookies": 0, "total_cookies": total_cookies}
                    )
            else:
                # No cookies found, so we'll skip these tests
                self._add_test_result(
                    category,
                    "cookie_security",
                    "INFO",
                    0, 0,
                    "No cookies found to test"
                )
                
        except requests.exceptions.SSLError as e:
            self._add_test_result(
                category,
                "security_headers",
                "ERROR",
                0, 10,
                f"SSL error while checking security headers: {str(e)}"
            )
        except requests.exceptions.RequestException as e:
            self._add_test_result(
                category,
                "security_headers",
                "ERROR",
                0, 10,
                f"Error checking security headers: {str(e)}"
            )
    
    def check_wordpress_version(self):
        """Check if WordPress version is up-to-date and not exposed."""
        category = "WordPress Security"
        
        try:
            response = self.session.get(
                self.target_url, 
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            html = response.text
            
            # Check for version in meta generator tag
            soup = BeautifulSoup(html, 'html.parser')
            generator_tag = soup.find('meta', {'name': 'generator'})
            
            version_exposed = False
            version = None
            
            if generator_tag and 'content' in generator_tag.attrs:
                content = generator_tag['content']
                # Try to extract WordPress version
                version_match = re.search(r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', content)
                if version_match:
                    version = version_match.group(1)
                    version_exposed = True
            
            # Also check for version in page source
            if not version_exposed:
                # Try to find it in common places
                version_patterns = [
                    r'wp-includes/js/wp-emoji-release\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)',
                    r'wp-includes/css/dist/block-library/style\.min\.css\?ver=(\d+\.\d+(?:\.\d+)?)',
                    r'wp-content/themes/[^/]+/style\.css\?ver=(\d+\.\d+(?:\.\d+)?)'
                ]
                
                for pattern in version_patterns:
                    version_match = re.search(pattern, html)
                    if version_match:
                        version = version_match.group(1)
                        version_exposed = True
                        break
            
            # Score for version exposure
            if version_exposed:
                self._add_test_result(
                    category,
                    "wordpress_version_exposed",
                    "FAIL",
                    0, 2,
                    "WordPress version is exposed in HTML source",
                    {"version": version}
                )
            else:
                self._add_test_result(
                    category,
                    "wordpress_version_exposed",
                    "PASS",
                    2, 2,
                    "WordPress version is not exposed in HTML source"
                )
            
            # If we found the version, check if it's up-to-date
            if version:
                # This would ideally check against the WordPress API, but for simplicity
                # we'll use a hardcoded recent version. In a real implementation, this would
                # fetch the latest version from WordPress API.
                latest_version = "6.4.3"  # As of February 2024
                
                if version.split('.')[0] < latest_version.split('.')[0]:
                    # Major version behind
                    self._add_test_result(
                        category,
                        "wordpress_version_current",
                        "FAIL",
                        0, 3,
                        f"WordPress major version is outdated ({version} < {latest_version})",
                        {"current_version": version, "latest_version": latest_version}
                    )
                elif version.split('.')[1] < latest_version.split('.')[1]:
                    # Minor version behind
                    self._add_test_result(
                        category,
                        "wordpress_version_current",
                        "WARNING",
                        1, 3,
                        f"WordPress minor version is outdated ({version} < {latest_version})",
                        {"current_version": version, "latest_version": latest_version}
                    )
                elif version.split('.')[2] < latest_version.split('.')[2]:
                    # Patch version behind
                    self._add_test_result(
                        category,
                        "wordpress_version_current",
                        "WARNING",
                        2, 3,
                        f"WordPress patch version is outdated ({version} < {latest_version})",
                        {"current_version": version, "latest_version": latest_version}
                    )
                else:
                    self._add_test_result(
                        category,
                        "wordpress_version_current",
                        "PASS",
                        3, 3,
                        f"WordPress is running the latest version ({version})",
                        {"current_version": version, "latest_version": latest_version}
                    )
            else:
                # If we couldn't determine the version, we'll skip the up-to-date check
                self._add_test_result(
                    category,
                    "wordpress_version_current",
                    "INFO",
                    0, 0,
                    "Could not determine WordPress version"
                )
                
        except requests.exceptions.RequestException as e:
            self._add_test_result(
                category,
                "wordpress_version",
                "ERROR",
                0, 5,
                f"Error checking WordPress version: {str(e)}"
            )
    
    def check_api_security(self):
        """Check the security of the WordPress REST API."""
        category = "API Security"
        
        try:
            # Test API endpoints for GDPR-related data exposure
            endpoints = [
                "/wp/v2/users",
                "/wp/v2/users/me",
                "/wp/v2/comments",
                "/wp-gdpr/v1/consents",  # Hypothetical GDPR plugin endpoint
                "/wp-gdpr/v1/export",    # Hypothetical GDPR plugin endpoint
                "/wp-gdpr/v1/delete"     # Hypothetical GDPR plugin endpoint
            ]
            
            for endpoint in endpoints:
                response = self.session.get(
                    f"{self.api_url}{endpoint}",
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                # Check if authentication is required (good)
                if response.status_code in (401, 403):
                    self._add_test_result(
                        category,
                        f"api_endpoint_{endpoint.replace('/', '_')}",
                        "PASS",
                        1, 1,
                        f"API endpoint {endpoint} requires authentication",
                        {"status_code": response.status_code}
                    )
                else:
                    # Endpoint is accessible without auth, check for sensitive data
                    try:
                        data = response.json()
                        contains_pii = self._check_for_pii(data)
                        
                        if contains_pii:
                            self._add_test_result(
                                category,
                                f"api_endpoint_{endpoint.replace('/', '_')}",
                                "FAIL",
                                0, 1,
                                f"API endpoint {endpoint} exposes personal data without authentication",
                                {"status_code": response.status_code, "pii_detected": True}
                            )
                        else:
                            self._add_test_result(
                                category,
                                f"api_endpoint_{endpoint.replace('/', '_')}",
                                "WARNING",
                                0.5, 1,
                                f"API endpoint {endpoint} is accessible without authentication but doesn't expose personal data",
                                {"status_code": response.status_code}
                            )
                    except ValueError:
                        # Not JSON or empty response
                        self._add_test_result(
                            category,
                            f"api_endpoint_{endpoint.replace('/', '_')}",
                            "WARNING",
                            0.5, 1,
                            f"API endpoint {endpoint} returned non-JSON response",
                            {"status_code": response.status_code}
                        )
                        
            # Check for REST API security headers
            response = self.session.options(
                self.api_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # Check for CORS headers
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            
            if cors_header == '*':
                self._add_test_result(
                    category,
                    "api_cors",
                    "FAIL",
                    0, 2,
                    "API allows requests from any origin (CORS wildcard)",
                    {"cors_header": cors_header}
                )
            elif cors_header:
                if cors_header.startswith('http') and self.target_url.split('//')[1].split('/')[0] in cors_header:
                    self._add_test_result(
                        category,
                        "api_cors",
                        "PASS",
                        2, 2,
                        "API has proper CORS restrictions",
                        {"cors_header": cors_header}
                    )
                else:
                    self._add_test_result(
                        category,
                        "api_cors",
                        "WARNING",
                        1, 2,
                        "API allows requests from external origins",
                        {"cors_header": cors_header}
                    )
            else:
                self._add_test_result(
                    category,
                    "api_cors",
                    "PASS",
                    2, 2,
                    "API doesn't have CORS headers (same-origin only)"
                )
                
        except requests.exceptions.RequestException as e:
            self._add_test_result(
                category,
                "api_security",
                "ERROR",
                0, 7,
                f"Error checking API security: {str(e)}"
            )
    
    def _check_for_pii(self, data):
        """Helper method to check JSON data for personally identifiable information."""
        pii_patterns = [
            r'email',
            r'address',
            r'phone',
            r'name',
            r'user',
            r'birth',
            r'gender'
        ]
        
        # Convert data to string for easier searching
        data_str = json.dumps(data).lower()
        
        for pattern in pii_patterns:
            if re.search(pattern, data_str):
                return True
                
        return False
        
    def check_file_permissions(self):
        """Check for sensitive files that might be accessible."""
        category = "File Security"
        
        sensitive_files = [
            "/wp-config.php",
            "/.env",
            "/.htaccess",
            "/wp-content/debug.log",
            "/wp-content/uploads/wp-config.php",
            "/wp-content/uploads/.env",
            "/wp-includes/version.php",
            "/readme.html",
            "/wp-admin/install.php",
            "/wp-admin/setup-config.php"
        ]
        
        results = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_file = {
                executor.submit(self._check_file_access, file_path): file_path 
                for file_path in sensitive_files
            }
            
            for future in future_to_file:
                file_path = future_to_file[future]
                try:
                    accessible, status_code = future.result()
                    results.append((file_path, accessible, status_code))
                except Exception as e:
                    self._add_test_result(
                        category,
                        f"file_{file_path.replace('/', '_')}",
                        "ERROR",
                        0, 1,
                        f"Error checking file {file_path}: {str(e)}"
                    )
        
        accessible_count = 0
        
        for file_path, accessible, status_code in results:
            if accessible:
                accessible_count += 1
                self._add_test_result(
                    category,
                    f"file_{file_path.replace('/', '_')}",
                    "FAIL",
                    0, 1,
                    f"Sensitive file {file_path} is accessible",
                    {"status_code": status_code}
                )
            else:
                self._add_test_result(
                    category,
                    f"file_{file_path.replace('/', '_')}",
                    "PASS",
                    1, 1,
                    f"Sensitive file {file_path} is not accessible",
                    {"status_code": status_code}
                )
        
        # Summary score
        if accessible_count == 0:
            self._add_test_result(
                category,
                "sensitive_files_summary",
                "PASS",
                3, 3,
                "All sensitive files are properly protected"
            )
        elif accessible_count <= 2:
            self._add_test_result(
                category,
                "sensitive_files_summary",
                "WARNING",
                1, 3,
                f"{accessible_count} sensitive files are accessible"
            )
        else:
            self._add_test_result(
                category,
                "sensitive_files_summary",
                "FAIL",
                0, 3,
                f"{accessible_count} sensitive files are accessible"
            )
    
    def _check_file_access(self, file_path):
        """Helper method to check if a file is accessible."""
        try:
            response = self.session.get(
                f"{self.target_url}{file_path}",
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False  # Don't follow redirects
            )
            
            # Consider it accessible if status code indicates content or found
            return (response.status_code in (200, 302, 304), response.status_code)
            
        except requests.exceptions.RequestException:
            # If there's an error, we'll assume it's not accessible
            return (False, 0)
    
    def run_all_tests(self):
        """Run all security tests."""
        try:
            # Start with SSL/TLS security
            self.check_ssl_security()
            
            # Check security headers
            self.check_security_headers()
            
            # Check WordPress version
            self.check_wordpress_version()
            
            # Check API security
            self.check_api_security()
            
            # Check file permissions
            self.check_file_permissions()
            
            # Calculate security score percentage
            if self.results["max_score"] > 0:
                self.results["security_score_percentage"] = round(
                    (self.results["overall_score"] / self.results["max_score"]) * 100, 1
                )
            else:
                self.results["security_score_percentage"] = 0
                
            return self.results
            
        except Exception as e:
            logger.error(f"Error running tests: {str(e)}")
            self.results["error"] = str(e)
            return self.results
    
    def generate_report(self, output_file=None, output_format="json"):
        """Generate a security report in the specified format."""
        if output_format.lower() == "json" and output_file:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"JSON report saved to {output_file}")
        
        # Print summary to console
        passed = sum(1 for test in self.results["tests"] if test["status"] == "PASS")
        warnings = sum(1 for test in self.results["tests"] if test["status"] == "WARNING")
        failed = sum(1 for test in self.results["tests"] if test["status"] == "FAIL")
        errors = sum(1 for test in self.results["tests"] if test["status"] == "ERROR")
        info = sum(1 for test in self.results["tests"] if test["status"] == "INFO")
        
        print("\n" + "="*60)
        print(f"GDPR SECURITY SCAN REPORT: {self.target_url}")
        print("="*60)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Security Score: {self.results.get('security_score_percentage', 0)}%")
        print(f"Tests: {len(self.results['tests'])} total, {passed} passed, {warnings} warnings, {failed} failed, {errors} errors, {info} info")
        print("-"*60)
        
        # Group tests by category
        tests_by_category = {}
        for test in self.results["tests"]:
            category = test["category"]
            if category not in tests_by_category:
                tests_by_category[category] = []
            tests_by_category[category].append(test)
        
        # Display results by category
        for category, tests in tests_by_category.items():
            print(f"\n{category}:")
            for test in tests:
                status_display = {
                    "PASS": "✅ PASS",
                    "WARNING": "⚠️ WARNING",
                    "FAIL": "❌ FAIL",
                    "ERROR": "⚠️ ERROR",
                    "INFO": "ℹ️ INFO"
                }
                print(f"  {status_display[test['status']]}: {test['name']} - {test['message']}")
            
        print("\n" + "="*60)
        
        return self.results


def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description='GDPR Security Scanner for WordPress')
    parser.add_argument('url', help='Target WordPress URL')
    parser.add_argument('--admin-url', help='WordPress admin URL if different from default')
    parser.add_argument('--api-url', help='WordPress REST API URL if different from default')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', '-f', choices=['json'], default='json', help='Output format')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    
    args = parser.parse_args()
    
    scanner = GDPRSecurityScanner(
        args.url,
        admin_url=args.admin_url,
        api_url=args.api_url,
        timeout=args.timeout,
        verify_ssl=not args.no_verify
    )
    
    scanner.run_all_tests()
    scanner.generate_report(args.output, args.format)


if __name__ == "__main__":
    main()
