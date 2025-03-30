#!/usr/bin/env python3
"""
GDPR Audit Log Integrity Tester
-------------------------------
This script verifies the integrity of WordPress GDPR audit logs to ensure they meet the 
requirements of GDPR Articles 5 and 30 for creating tamper-proof processing records.
It checks for proper cryptographic protection, completeness, and accuracy of audit trails.

Requirements:
- Python 3.6+
- requests
- beautifulsoup4
- pycryptodome (for cryptographic verification)

Installation:
pip install requests beautifulsoup4 pycryptodome

Author: Panagiotis Nikolaidis
"""

import argparse
import json
import re
import sys
import time
import logging
import hashlib
import base64
import random
import string
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from Crypto.Hash import SHA256

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class AuditLogTester:
    """Tester for GDPR audit log integrity in WordPress."""
    
    def __init__(self, target_url, admin_url=None, admin_username=None, admin_password=None, timeout=10, verify_ssl=True):
        """Initialize the tester with target URLs and credentials."""
        self.target_url = target_url.rstrip('/')
        
        # Determine admin URL if not provided
        if admin_url:
            self.admin_url = admin_url.rstrip('/')
        else:
            self.admin_url = f"{self.target_url}/wp-admin"
            
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GDPR Audit Log Tester/1.0 (https://github.com/PanagiotisNikolaidis236322/Wordpress-gdpr-framework-thesis)'
        })
        
        # Results container
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "tests": [],
            "overall_result": "PENDING"
        }
    
    def _add_test_result(self, test_name, status, score=0, max_score=0, message="", details=None):
        """Add a test result to the results dictionary."""
        self.results["tests"].append({
            "name": test_name,
            "status": status,
            "score": score,
            "max_score": max_score,
            "message": message,
            "details": details or {}
        })
        logger.info(f"Test '{test_name}': {status} ({score}/{max_score}) - {message}")
    
    def _random_string(self, length=8):
        """Generate a random string of fixed length."""
        letters = string.ascii_lowercase + string.digits
        return ''.join(random.choice(letters) for _ in range(length))
    
    def _admin_login(self):
        """Login to WordPress admin panel using provided credentials."""
        if not self.admin_username or not self.admin_password:
            self._add_test_result(
                "admin_login",
                "SKIP",
                0, 0,
                "Admin credentials not provided"
            )
            return False
            
        try:
            login_url = f"{self.admin_url}/wp-login.php"
            
            # First get the login page to capture any cookies/nonces
            response = self.session.get(
                login_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # Check for login form
            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form', id='loginform')
            
            if not login_form:
                self._add_test_result(
                    "admin_login",
                    "FAIL",
                    0, 0,
                    "Login form not found"
                )
                return False
            
            # Extract any hidden fields/nonces
            hidden_fields = {}
            for field in login_form.find_all('input', type='hidden'):
                if 'name' in field.attrs and 'value' in field.attrs:
                    hidden_fields[field['name']] = field['value']
            
            # Prepare login data
            login_data = {
                'log': self.admin_username,
                'pwd': self.admin_password,
                'wp-submit': 'Log In',
                'redirect_to': f"{self.admin_url}/",
                'testcookie': '1'
            }
            
            # Add any hidden fields
            login_data.update(hidden_fields)
            
            # Submit login
            response = self.session.post(
                login_url,
                data=login_data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            # Check if login was successful
            if 'wordpress_logged_in' in str(self.session.cookies):
                self._add_test_result(
                    "admin_login",
                    "PASS",
                    0, 0,
                    "Successfully logged in as admin"
                )
                return True
            else:
                self._add_test_result(
                    "admin_login",
                    "FAIL",
                    0, 0,
                    "Failed to login - incorrect credentials or login error"
                )
                return False
                
        except requests.exceptions.RequestException as e:
            self._add_test_result(
                "admin_login",
                "ERROR",
                0, 0,
                f"Error during admin login: {str(e)}"
            )
            return False
    
    def find_gdpr_audit_logs(self):
        """Locate the GDPR audit logs in the WordPress admin panel."""
        if not self._admin_login():
            self._add_test_result(
                "find_audit_logs",
                "SKIP",
                0, 5,
                "Skipping audit log search due to login failure"
            )
            return None
            
        try:
            # Common locations for GDPR audit logs
            audit_log_paths = [
                "/wp-admin/admin.php?page=gdpr-logs",
                "/wp-admin/admin.php?page=gdpr-audit-log",
                "/wp-admin/admin.php?page=gdpr-framework-logs",
                "/wp-admin/admin.php?page=wp_activity_log",
                "/wp-admin/admin.php?page=wp_security_audit_log",
                "/wp-admin/admin.php?page=gdpr-tools",
                "/wp-admin/admin.php?page=wp-gdpr-compliance",
                "/wp-admin/admin.php?page=complianz",
                "/wp-admin/admin.php?page=privacy"
            ]
            
            audit_log_found = False
            audit_log_url = None
            audit_log_content = None
            
            for path in audit_log_paths:
                full_url = self.target_url + path
                
                try:
                    response = self.session.get(
                        full_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    # Check if the page contains audit log indicators
                    audit_terms = [
                        "audit log", "activity log", "gdpr log", "privacy log", 
                        "consent log", "data processing record", "user data", 
                        "compliance log"
                    ]
                    
                    page_content = response.text.lower()
                    
                    for term in audit_terms:
                        if term in page_content:
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            # Look for tables which might contain logs
                            tables = soup.find_all('table')
                            if tables:
                                for table in tables:
                                    # Check if table headers contain relevant terms
                                    headers = table.find_all('th') or table.find_all('td')
                                    header_text = ' '.join(h.get_text().lower() for h in headers)
                                    
                                    log_header_terms = [
                                        "date", "time", "user", "action", "ip", 
                                        "event", "activity", "description", "type"
                                    ]
                                    
                                    if any(h_term in header_text for h_term in log_header_terms):
                                        audit_log_found = True
                                        audit_log_url = full_url
                                        audit_log_content = response.text
                                        break
                            
                            # If we found a table with log-like structure, break the loop
                            if audit_log_found:
                                break
                                
                except requests.exceptions.RequestException:
                    continue
                
                if audit_log_found:
                    break
            
            if audit_log_found:
                self._add_test_result(
                    "find_audit_logs",
                    "PASS",
                    5, 5,
                    f"GDPR audit logs found at {audit_log_url}",
                    {"url": audit_log_url}
                )
                return {
                    "url": audit_log_url,
                    "content": audit_log_content
                }
            else:
                # Try looking for API endpoints that might provide logs
                try:
                    response = self.session.get(
                        f"{self.target_url}/wp-json/wp-gdpr-framework/v1/logs",
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        try:
                            log_data = response.json()
                            if isinstance(log_data, list) and len(log_data) > 0:
                                self._add_test_result(
                                    "find_audit_logs",
                                    "PASS",
                                    5, 5,
                                    "GDPR audit logs found via API endpoint",
                                    {"url": f"{self.target_url}/wp-json/wp-gdpr-framework/v1/logs"}
                                )
                                return {
                                    "url": f"{self.target_url}/wp-json/wp-gdpr-framework/v1/logs",
                                    "content": json.dumps(log_data),
                                    "is_api": True
                                }
                        except json.JSONDecodeError:
                            pass
                except:
                    pass
                
                self._add_test_result(
                    "find_audit_logs",
                    "FAIL",
                    0, 5,
                    "No GDPR audit logs found"
                )
                return None
                
        except Exception as e:
            self._add_test_result(
                "find_audit_logs",
                "ERROR",
                0, 5,
                f"Error searching for audit logs: {str(e)}"
            )
            return None
    
    def analyze_audit_log_structure(self, audit_log_data):
        """Analyze the structure and content of the GDPR audit logs."""
        if not audit_log_data:
            self._add_test_result(
                "audit_log_structure",
                "SKIP",
                0, 10,
                "Skipping audit log analysis due to missing logs"
            )
            return
            
        try:
            # Check if this is an API response or HTML content
            is_api = audit_log_data.get('is_api', False)
            
            if is_api:
                return self._analyze_api_audit_logs(audit_log_data)
            else:
                return self._analyze_html_audit_logs(audit_log_data)
                
        except Exception as e:
            self._add_test_result(
                "audit_log_structure",
                "ERROR",
                0, 10,
                f"Error analyzing audit logs: {str(e)}"
            )
    
    def _analyze_html_audit_logs(self, audit_log_data):
        """Analyze HTML-based audit logs."""
        try:
            soup = BeautifulSoup(audit_log_data['content'], 'html.parser')
            
            # Find tables which might contain logs
            tables = soup.find_all('table')
            if not tables:
                self._add_test_result(
                    "audit_log_structure",
                    "FAIL",
                    0, 10,
                    "No table structure found in audit logs"
                )
                return
            
            # Analyze the most likely log table
            log_table = None
            max_rows = 0
            
            for table in tables:
                rows = table.find_all('tr')
                if len(rows) > max_rows:
                    max_rows = len(rows)
                    log_table = table
            
            if not log_table or max_rows <= 1:  # Just headers is not enough
                self._add_test_result(
                    "audit_log_structure",
                    "FAIL",
                    0, 10,
                    "No log entries found in tables"
                )
                return
            
            # Analyze table headers
            headers = log_table.find_all('th') or log_table.find('tr').find_all('td')
            header_texts = [h.get_text().strip().lower() for h in headers]
            
            # Required columns for GDPR audit logs
            required_fields = {
                'timestamp': ['date', 'time', 'timestamp', 'when'],
                'user': ['user', 'username', 'user id', 'who'],
                'action': ['action', 'event', 'activity', 'what'],
                'data': ['data', 'details', 'info', 'description']
            }
            
            # Check if the required fields are present
            found_fields = defaultdict(bool)
            
            for req_field, synonyms in required_fields.items():
                for header in header_texts:
                    if any(syn in header for syn in synonyms):
                        found_fields[req_field] = True
                        break
            
            # Calculate completeness score
            completeness_score = sum(1 for field in found_fields.values() if field)
            
            if completeness_score == 0:
                self._add_test_result(
                    "audit_log_structure",
                    "FAIL",
                    0, 4,
                    "No required GDPR audit fields found in log headers",
                    {"found_headers": header_texts}
                )
            else:
                self._add_test_result(
                    "audit_log_structure",
                    "PASS" if completeness_score == 4 else "WARNING",
                    completeness_score, 4,
                    f"Found {completeness_score}/4 required GDPR audit log fields",
                    {"found_fields": {k: v for k, v in found_fields.items()}, "headers": header_texts}
                )
            
            # Analyze log entries for GDPR-specific events
            rows = log_table.find_all('tr')
            log_entries = []
            
            # Skip the header row
            for row in rows[1:]:
                cells = row.find_all('td')
                if cells:
                    log_entries.append([cell.get_text().strip() for cell in cells])
            
            # Look for GDPR-specific entries
            gdpr_terms = [
                'consent', 'gdpr', 'privacy', 'data request', 'access request',
                'erasure', 'deletion', 'opt-in', 'opt-out', 'personal data',
                'export', 'data subject', 'processing'
            ]
            
            gdpr_entries = 0
            
            for entry in log_entries:
                entry_text = ' '.join(entry).lower()
                if any(term in entry_text for term in gdpr_terms):
                    gdpr_entries += 1
            
            if gdpr_entries > 0:
                self._add_test_result(
                    "gdpr_specific_logs",
                    "PASS",
                    3, 3,
                    f"Found {gdpr_entries} GDPR-specific log entries",
                    {"total_entries": len(log_entries), "gdpr_entries": gdpr_entries}
                )
            else:
                self._add_test_result(
                    "gdpr_specific_logs",
                    "FAIL",
                    0, 3,
                    "No GDPR-specific log entries found",
                    {"total_entries": len(log_entries), "gdpr_entries": 0}
                )
            
            # Check for evidence of tamper-prevention (hash values, digital signatures)
            tamper_evidence = False
            hash_pattern = re.compile(r'[a-f0-9]{32,}', re.IGNORECASE)  # MD5, SHA-1, SHA-256, etc.
            
            for entry in log_entries:
                entry_text = ' '.join(entry)
                if hash_pattern.search(entry_text):
                    tamper_evidence = True
                    break
            
            # Also look for tamper-proof claims in the page content
            tamper_terms = [
                'tamper-proof', 'immutable', 'cryptographic', 'hash', 'digital signature',
                'blockchain', 'integrity', 'non-repudiation', 'sha256', 'sha512'
            ]
            
            content_text = audit_log_data['content'].lower()
            tamper_claims = any(term in content_text for term in tamper_terms)
            
            if tamper_evidence or tamper_claims:
                self._add_test_result(
                    "tamper_protection",
                    "PASS",
                    3, 3,
                    "Evidence of tamper-protection mechanisms found",
                    {
                        "hash_evidence": tamper_evidence,
                        "tamper_proof_claims": tamper_claims
                    }
                )
            else:
                self._add_test_result(
                    "tamper_protection",
                    "FAIL",
                    0, 3,
                    "No evidence of tamper-protection mechanisms found"
                )
            
            return {
                "completeness_score": completeness_score,
                "gdpr_entries": gdpr_entries,
                "tamper_evidence": tamper_evidence or tamper_claims
            }
            
        except Exception as e:
            self._add_test_result(
                "audit_log_structure",
                "ERROR",
                0, 10,
                f"Error analyzing HTML audit logs: {str(e)}"
            )
            return None
    
    def _analyze_api_audit_logs(self, audit_log_data):
        """Analyze API-based audit logs."""
        try:
            # Parse the JSON content
            log_data = json.loads(audit_log_data['content'])
            
            if not isinstance(log_data, list) or len(log_data) == 0:
                self._add_test_result(
                    "audit_log_structure",
                    "FAIL",
                    0, 10,
                    "No valid log entries found in API response"
                )
                return
            
            # Analyze the first log entry to determine available fields
            sample_entry = log_data[0]
            
            # Required fields for GDPR audit logs
            required_fields = {
                'timestamp': ['date', 'time', 'timestamp', 'created', 'when'],
                'user': ['user', 'username', 'user_id', 'who', 'actor'],
                'action': ['action', 'event', 'activity', 'what', 'type'],
                'data': ['data', 'details', 'info', 'description', 'content']
            }
            
            # Check if the required fields are present
            found_fields = defaultdict(bool)
            
            for field_name, field_value in sample_entry.items():
                field_name_lower = field_name.lower()
                for req_field, synonyms in required_fields.items():
                    if any(syn in field_name_lower for syn in synonyms):
                        found_fields[req_field] = True
                        break
            
            # Calculate completeness score
            completeness_score = sum(1 for field in found_fields.values() if field)
            
            if completeness_score == 0:
                self._add_test_result(
                    "audit_log_structure",
                    "FAIL",
                    0, 4,
                    "No required GDPR audit fields found in API log data",
                    {"available_fields": list(sample_entry.keys())}
                )
            else:
                self._add_test_result(
                    "audit_log_structure",
                    "PASS" if completeness_score == 4 else "WARNING",
                    completeness_score, 4,
                    f"Found {completeness_score}/4 required GDPR audit log fields in API response",
                    {"found_fields": {k: v for k, v in found_fields.items()}, "available_fields": list(sample_entry.keys())}
                )
            
            # Look for GDPR-specific entries
            gdpr_terms = [
                'consent', 'gdpr', 'privacy', 'data request', 'access request',
                'erasure', 'deletion', 'opt-in', 'opt-out', 'personal data',
                'export', 'data subject', 'processing'
            ]
            
            gdpr_entries = 0
            
            for entry in log_data:
                entry_text = json.dumps(entry).lower()
                if any(term in entry_text for term in gdpr_terms):
                    gdpr_entries += 1
            
            if gdpr_entries > 0:
                self._add_test_result(
                    "gdpr_specific_logs",
                    "PASS",
                    3, 3,
                    f"Found {gdpr_entries} GDPR-specific log entries in API response",
                    {"total_entries": len(log_data), "gdpr_entries": gdpr_entries}
                )
            else:
                self._add_test_result(
                    "gdpr_specific_logs",
                    "FAIL",
                    0, 3,
                    "No GDPR-specific log entries found in API response",
                    {"total_entries": len(log_data), "gdpr_entries": 0}
                )
            
            # Check for evidence of tamper-prevention (hash values, signatures)
            tamper_evidence = False
            hash_fields = ['hash', 'signature', 'checksum', 'integrity', 'verification']
            
            for entry in log_data:
                # Check if any field contains a hash-like value
                for field_name, field_value in entry.items():
                    if any(h_field in field_name.lower() for h_field in hash_fields):
                        tamper_evidence = True
                        break
                    
                    # Check if the value looks like a hash
                    if isinstance(field_value, str) and re.match(r'^[a-f0-9]{32,}$', field_value, re.IGNORECASE):
                        tamper_evidence = True
                        break
                        
                if tamper_evidence:
                    break
            
            if tamper_evidence:
                self._add_test_result(
                    "tamper_protection",
                    "PASS",
                    3, 3,
                    "Evidence of tamper-protection mechanisms found in API logs",
                    {"tamper_evidence": True}
                )
            else:
                self._add_test_result(
                    "tamper_protection",
                    "FAIL",
                    0, 3,
                    "No evidence of tamper-protection mechanisms found in API logs"
                )
            
            return {
                "completeness_score": completeness_score,
                "gdpr_entries": gdpr_entries,
                "tamper_evidence": tamper_evidence
            }
            
        except Exception as e:
            self._add_test_result(
                "audit_log_structure",
                "ERROR",
                0, 10,
                f"Error analyzing API audit logs: {str(e)}"
            )
            return None
    
    def perform_audit_log_modification_test(self, audit_log_data):
        """Test if audit logs can be modified (which would indicate lack of tamper protection)."""
        if not audit_log_data:
            self._add_test_result(
                "audit_log_modification",
                "SKIP",
                0, 5,
                "Skipping modification test due to missing logs"
            )
            return
            
        try:
            # This test is more limited as we don't want to actually modify logs,
            # but we can check for edit capabilities in the UI
            
            # Look for edit buttons, links, or other indicators that logs can be modified
            soup = BeautifulSoup(audit_log_data['content'], 'html.parser')
            
            # Look for edit links in the log table
            if 'is_api' not in audit_log_data:  # HTML-based logs
                edit_terms = ['edit', 'modify', 'update', 'change', 'delete', 'remove']
                
                edit_elements = []
                for term in edit_terms:
                    elements = soup.find_all(['a', 'button', 'input'], text=re.compile(term, re.IGNORECASE))
                    edit_elements.extend(elements)
                    
                    # Also check for elements with these terms in their attributes
                    elements = soup.find_all(['a', 'button', 'input'], 
                        lambda tag: any(term in attr.lower() for attr in tag.attrs.values() if isinstance(attr, str)))
                    edit_elements.extend(elements)
                
                if edit_elements:
                    self._add_test_result(
                        "audit_log_modification",
                        "FAIL",
                        0, 5,
                        "Audit logs appear to be modifiable as edit controls were found",
                        {"edit_elements_found": len(edit_elements)}
                    )
                    return False
                else:
                    # Look for forms that might allow editing
                    forms = soup.find_all('form')
                    suspicious_forms = []
                    
                    for form in forms:
                        # Check if form contains log-related fields
                        inputs = form.find_all(['input', 'textarea', 'select'])
                        for input_elem in inputs:
                            input_name = input_elem.get('name', '').lower()
                            if any(term in input_name for term in ['log', 'event', 'audit', 'record']):
                                suspicious_forms.append(form)
                                break
                    
                    if suspicious_forms:
                        self._add_test_result(
                            "audit_log_modification",
                            "WARNING",
                            2, 5,
                            "Forms found that might allow log modification",
                            {"suspicious_forms": len(suspicious_forms)}
                        )
                        return False
                    else:
                        self._add_test_result(
                            "audit_log_modification",
                            "PASS",
                            5, 5,
                            "No evidence found that audit logs can be modified"
                        )
                        return True
            else:  # API-based logs
                # For API logs, we can check if there are PUT/DELETE endpoints
                api_url = audit_log_data['url']
                
                # Make an OPTIONS request to check available methods
                try:
                    response = self.session.options(
                        api_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    allowed_methods = response.headers.get('Allow', '')
                    
                    if any(method in allowed_methods for method in ['PUT', 'DELETE', 'PATCH']):
                        self._add_test_result(
                            "audit_log_modification",
                            "FAIL",
                            0, 5,
                            "API logs appear to be modifiable as PUT/DELETE/PATCH methods are allowed",
                            {"allowed_methods": allowed_methods}
                        )
                        return False
                    else:
                        self._add_test_result(
                            "audit_log_modification",
                            "PASS",
                            5, 5,
                            "API logs appear to be read-only as only safe methods are allowed",
                            {"allowed_methods": allowed_methods}
                        )
                        return True
                except:
                    # If OPTIONS request fails, check documentation for clues
                    page_text = audit_log_data['content'].lower()
                    immutable_terms = ['immutable', 'read-only', 'tamper-proof', 'cannot be modified']
                    
                    if any(term in page_text for term in immutable_terms):
                        self._add_test_result(
                            "audit_log_modification",
                            "PASS",
                            5, 5,
                            "Documentation suggests logs are immutable"
                        )
                        return True
                    else:
                        self._add_test_result(
                            "audit_log_modification",
                            "WARNING",
                            2, 5,
                            "Could not determine if API logs are modifiable"
                        )
                        return False
                
        except Exception as e:
            self._add_test_result(
                "audit_log_modification",
                "ERROR",
                0, 5,
                f"Error testing audit log modification: {str(e)}"
            )
            return False
    
    def test_retention_period(self, audit_log_data):
        """Test if audit logs have appropriate retention periods set."""
        if not audit_log_data:
            self._add_test_result(
                "audit_log_retention",
                "SKIP",
                0, 3,
                "Skipping retention test due to missing logs"
            )
            return
            
        try:
            # Look for retention period information in the page content or settings
            retention_terms = [
                'retention', 'retention period', 'keep logs for', 'store logs for',
                'log storage', 'retention policy', 'purge logs', 'log rotation'
            ]
            
            content_text = audit_log_data['content'].lower()
            
            # Try to find retention period mentions
            retention_found = False
            retention_period = None
            
            for term in retention_terms:
                if term in content_text:
                    # Try to extract retention period using regex
                    pattern = re.compile(r'(\d+)\s+(day|week|month|year)s?', re.IGNORECASE)
                    matches = pattern.findall(content_text[content_text.find(term):content_text.find(term) + 200])
                    
                    if matches:
                        retention_found = True
                        # Extract the first match
                        value, unit = matches[0]
                        retention_period = f"{value} {unit}{'s' if int(value) > 1 and not unit.endswith('s') else ''}"
                        break
            
            if retention_found and retention_period:
                # GDPR requires retention for purpose and no longer
                # A reasonable period for logs is at least 1 year
                value = int(retention_period.split()[0])
                unit = retention_period.split()[1].lower()
                
                days = 0
                if 'day' in unit:
                    days = value
                elif 'week' in unit:
                    days = value * 7
                elif 'month' in unit:
                    days = value * 30
                elif 'year' in unit:
                    days = value * 365
                
                if days >= 365:  # At least 1 year
                    self._add_test_result(
                        "audit_log_retention",
                        "PASS",
                        3, 3,
                        f"Appropriate retention period found: {retention_period}",
                        {"retention_period": retention_period, "days": days}
                    )
                    return True
                elif days > 0:
                    self._add_test_result(
                        "audit_log_retention",
                        "WARNING",
                        1, 3,
                        f"Retention period may be too short: {retention_period}",
                        {"retention_period": retention_period, "days": days}
                    )
                    return False
                else:
                    self._add_test_result(
                        "audit_log_retention",
                        "FAIL",
                        0, 3,
                        f"Could not interpret retention period: {retention_period}"
                    )
                    return False
            else:
                # Check if there are old log entries that suggest long retention
                if 'is_api' not in audit_log_data:  # HTML-based logs
                    soup = BeautifulSoup(audit_log_data['content'], 'html.parser')
                    
                    # Find tables which might contain logs
                    tables = soup.find_all('table')
                    if tables:
                        oldest_date = None
                        
                        for table in tables:
                            rows = table.find_all('tr')
                            
                            # Skip the header row
                            for row in rows[1:]:
                                cells = row.find_all('td')
                                if cells:
                                    row_text = ' '.join(cell.get_text().strip() for cell in cells)
                                    
                                    # Try to extract dates
                                    date_patterns = [
                                        r'(\d{4}-\d{2}-\d{2})',  # YYYY-MM-DD
                                        r'(\d{2}/\d{2}/\d{4})',  # MM/DD/YYYY
                                        r'(\d{2}-\d{2}-\d{4})',  # MM-DD-YYYY
                                        r'(\d{1,2} [A-Za-z]{3,9} \d{4})'  # DD Mon YYYY
                                    ]
                                    
                                    for pattern in date_patterns:
                                        match = re.search(pattern, row_text)
                                        if match:
                                            date_str = match.group(1)
                                            try:
                                                if '-' in date_str and len(date_str.split('-')[0]) == 4:
                                                    # YYYY-MM-DD
                                                    log_date = datetime.strptime(date_str, '%Y-%m-%d')
                                                elif '/' in date_str:
                                                    # MM/DD/YYYY
                                                    log_date = datetime.strptime(date_str, '%m/%d/%Y')
                                                elif '-' in date_str:
                                                    # MM-DD-YYYY
                                                    log_date = datetime.strptime(date_str, '%m-%d-%Y')
                                                else:
                                                    # Try DD Mon YYYY
                                                    log_date = datetime.strptime(date_str, '%d %b %Y')
                                                
                                                if oldest_date is None or log_date < oldest_date:
                                                    oldest_date = log_date
                                                    
                                                break
                                            except ValueError:
                                                continue
                        
                        if oldest_date:
                            days_retained = (datetime.now() - oldest_date).days
                            
                            if days_retained >= 365:  # At least 1 year
                                self._add_test_result(
                                    "audit_log_retention",
                                    "PASS",
                                    3, 3,
                                    f"Logs appear to be retained for a long period (oldest log: {oldest_date.strftime('%Y-%m-%d')}, {days_retained} days)",
                                    {"oldest_log": oldest_date.isoformat(), "days_retained": days_retained}
                                )
                                return True
                            elif days_retained > 90:  # At least 3 months
                                self._add_test_result(
                                    "audit_log_retention",
                                    "WARNING",
                                    1, 3,
                                    f"Logs appear to be retained for at least {days_retained} days, but less than recommended 1 year",
                                    {"oldest_log": oldest_date.isoformat(), "days_retained": days_retained}
                                )
                                return False
                            else:
                                self._add_test_result(
                                    "audit_log_retention",
                                    "FAIL",
                                    0, 3,
                                    f"Logs appear to be retained for only {days_retained} days",
                                    {"oldest_log": oldest_date.isoformat(), "days_retained": days_retained}
                                )
                                return False
                    
                # If no retention period found and couldn't determine from logs
                self._add_test_result(
                    "audit_log_retention",
                    "WARNING",
                    1, 3,
                    "No explicit retention period found for audit logs"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "audit_log_retention",
                "ERROR",
                0, 3,
                f"Error testing audit log retention: {str(e)}"
            )
            return False
    
    def run_all_tests(self):
        """Run all GDPR audit log tests."""
        try:
            # Find GDPR audit logs
            audit_log_data = self.find_gdpr_audit_logs()
            
            if audit_log_data:
                # Analyze audit log structure and content
                self.analyze_audit_log_structure(audit_log_data)
                
                # Test if logs can be modified
                self.perform_audit_log_modification_test(audit_log_data)
                
                # Test retention period
                self.test_retention_period(audit_log_data)
            
            # Calculate overall score and result
            total_score = sum(test.get("score", 0) for test in self.results["tests"])
            max_score = sum(test.get("max_score", 0) for test in self.results["tests"])
            
            if max_score > 0:
                score_percentage = (total_score / max_score) * 100
                self.results["score_percentage"] = round(score_percentage, 1)
                
                if score_percentage >= 80:
                    self.results["overall_result"] = "PASS"
                elif score_percentage >= 50:
                    self.results["overall_result"] = "WARNING"
                else:
                    self.results["overall_result"] = "FAIL"
            else:
                self.results["overall_result"] = "ERROR"
                
            return self.results
            
        except Exception as e:
            logger.error(f"Error running tests: {str(e)}")
            self.results["overall_result"] = "ERROR"
            self.results["error"] = str(e)
            return self.results
    
    def generate_report(self, output_file=None):
        """Generate a JSON report of test results."""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        
        # Calculate statistics for console output
        total_score = sum(test.get("score", 0) for test in self.results["tests"])
        max_score = sum(test.get("max_score", 0) for test in self.results["tests"])
        
        passed = sum(1 for test in self.results["tests"] if test["status"] == "PASS" and test.get("max_score", 0) > 0)
        warnings = sum(1 for test in self.results["tests"] if test["status"] == "WARNING" and test.get("max_score", 0) > 0)
        failed = sum(1 for test in self.results["tests"] if test["status"] == "FAIL" and test.get("max_score", 0) > 0)
        errors = sum(1 for test in self.results["tests"] if test["status"] == "ERROR" and test.get("max_score", 0) > 0)
        skipped = sum(1 for test in self.results["tests"] if test["status"] == "SKIP" and test.get("max_score", 0) > 0)
        
        # Print summary to console
        print("\n" + "="*60)
        print(f"GDPR AUDIT LOG INTEGRITY REPORT: {self.target_url}")
        print("="*60)
        print(f"Timestamp: {self.results['timestamp']}")
        if max_score > 0:
            print(f"Overall Score: {self.results.get('score_percentage', 0)}% ({total_score}/{max_score} points)")
        print(f"Overall Result: {self.results['overall_result']}")
        print(f"Tests: {passed + warnings + failed + errors + skipped} total, {passed} passed, {warnings} warnings, {failed} failed, {errors} errors, {skipped} skipped")
        print("-"*60)
        
        # Display results by test
        for test in self.results["tests"]:
            if test.get("max_score", 0) > 0:  # Only show actual tests, not setup steps
                status_display = {
                    "PASS": "✅ PASS",
                    "WARNING": "⚠️ WARNING",
                    "FAIL": "❌ FAIL",
                    "ERROR": "⚠️ ERROR",
                    "SKIP": "⏭️ SKIP"
                }
                
                score_display = f"({test.get('score', 0)}/{test.get('max_score', 0)})"
                print(f"{status_display[test['status']]} {score_display}: {test['name']} - {test['message']}")
        
        print("="*60)
        
        if self.results['overall_result'] == "PASS":
            print("✅ The audit log implementation appears to meet GDPR requirements.")
        elif self.results['overall_result'] == "WARNING":
            print("⚠️ The audit log implementation partially meets GDPR requirements but could be improved.")
        elif self.results['overall_result'] == "FAIL":
            print("❌ The audit log implementation does not meet GDPR requirements.")
        else:
            print("⚠️ Could not fully assess the audit log implementation due to errors.")
            
        print("\n")
        
        return self.results


def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description='GDPR Audit Log Integrity Tester')
    parser.add_argument('url', help='Target WordPress URL')
    parser.add_argument('--admin-url', help='WordPress admin URL if different from default')
    parser.add_argument('--admin-username', help='WordPress admin username')
    parser.add_argument('--admin-password', help='WordPress admin password')
    parser.add_argument('--output', '-o', help='Output file for JSON report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL verification')
    
    args = parser.parse_args()
    
    tester = AuditLogTester(
        args.url,
        admin_url=args.admin_url,
        admin_username=args.admin_username,
        admin_password=args.admin_password,
        timeout=args.timeout,
        verify_ssl=not args.no_verify
    )
    
    tester.run_all_tests()
    tester.generate_report(args.output)


if __name__ == "__main__":
    main()
