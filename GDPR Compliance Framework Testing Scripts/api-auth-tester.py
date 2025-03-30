#!/usr/bin/env python3
"""
GDPR API Authentication Tester
------------------------------
This script tests the authentication mechanisms of WordPress REST API endpoints that
expose GDPR-related functionality, ensuring they implement OAuth 2.0 or similarly
robust authentication processes to protect personal data.

Requirements:
- Python 3.6+
- requests
- beautifulsoup4

Installation:
pip install requests beautifulsoup4

Author: Panagiotis Nikolaidis
"""

import argparse
import json
import re
import os
import time
import logging
import random
import string
import base64
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class GDPRAPIAuthTester:
    """Tester for API authentication mechanisms in WordPress GDPR implementations."""
    
    def __init__(self, target_url, admin_url=None, admin_username=None, admin_password=None, timeout=10, verify_ssl=True):
        """Initialize the tester with target URLs and credentials."""
        self.target_url = target_url.rstrip('/')
        
        # Determine admin URL if not provided
        if admin_url:
            self.admin_url = admin_url.rstrip('/')
        else:
            self.admin_url = f"{self.target_url}/wp-admin"
            
        # Determine API URL
        self.api_url = f"{self.target_url}/wp-json"
        
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GDPR API Auth Tester/1.0 (https://github.com/PanagiotisNikolaidis236322/Wordpress-gdpr-framework-thesis)'
        })
        
        # Results container
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "api_url": self.api_url,
            "tests": [],
            "overall_result": "PENDING"
        }
        
        # Track API endpoints we discover
        self.gdpr_endpoints = []
    
    def _add_test_result(self, test_name, status, message="", details=None):
        """Add a test result to the results dictionary."""
        self.results["tests"].append({
            "name": test_name,
            "status": status,
            "message": message,
            "details": details or {}
        })
        logger.info(f"Test '{test_name}': {status} - {message}")
    
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
                    "Successfully logged in as admin"
                )
                return True
            else:
                self._add_test_result(
                    "admin_login",
                    "FAIL",
                    "Failed to login - incorrect credentials or login error"
                )
                return False
                
        except requests.exceptions.RequestException as e:
            self._add_test_result(
                "admin_login",
                "ERROR",
                f"Error during admin login: {str(e)}"
            )
            return False
    
    def discover_api_endpoints(self):
        """Discover GDPR-related API endpoints by examining the WordPress REST API."""
        try:
            # Get the main API index
            response = self.session.get(
                self.api_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self._add_test_result(
                    "api_discovery",
                    "FAIL",
                    f"API index not accessible (status code: {response.status_code})"
                )
                return []
            
            try:
                api_index = response.json()
            except json.JSONDecodeError:
                self._add_test_result(
                    "api_discovery",
                    "FAIL",
                    "API index returned invalid JSON"
                )
                return []
            
            # Check for namespaces in the API index
            if 'namespaces' not in api_index:
                self._add_test_result(
                    "api_discovery",
                    "WARNING",
                    "API index does not contain namespaces information"
                )
                # Try an alternative approach
                return self._discover_by_common_paths()
            
            # Look for GDPR-related namespaces
            gdpr_namespaces = []
            
            for namespace in api_index['namespaces']:
                if any(term in namespace.lower() for term in ['gdpr', 'privacy', 'consent', 'data']):
                    gdpr_namespaces.append(namespace)
            
            # If no GDPR namespaces, check for routes in common namespaces
            if not gdpr_namespaces:
                self._add_test_result(
                    "api_discovery",
                    "INFO",
                    "No explicit GDPR namespaces found in API index"
                )
                
                # Check routes for each namespace
                gdpr_routes = []
                
                # Get the routes information if available
                if 'routes' in api_index:
                    for route, info in api_index['routes'].items():
                        if any(term in route.lower() for term in ['gdpr', 'privacy', 'consent', 'data']):
                            gdpr_routes.append(route)
                
                if gdpr_routes:
                    self._add_test_result(
                        "api_discovery",
                        "PASS",
                        f"Found {len(gdpr_routes)} GDPR-related API routes",
                        {"routes": gdpr_routes}
                    )
                    self.gdpr_endpoints = gdpr_routes
                    return gdpr_routes
                else:
                    # If still no routes, try common paths
                    return self._discover_by_common_paths()
            else:
                # We found GDPR namespaces, now get their routes
                gdpr_routes = []
                
                for namespace in gdpr_namespaces:
                    # Get the namespace routes
                    response = self.session.get(
                        f"{self.api_url}/{namespace}",
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        try:
                            namespace_data = response.json()
                            
                            # If this returns a list of routes
                            if isinstance(namespace_data, list):
                                for route in namespace_data:
                                    if isinstance(route, dict) and 'route' in route:
                                        gdpr_routes.append(route['route'])
                            # If it returns an object with routes
                            elif isinstance(namespace_data, dict) and 'routes' in namespace_data:
                                for route in namespace_data['routes']:
                                    gdpr_routes.append(route)
                            
                        except json.JSONDecodeError:
                            pass
                
                if gdpr_routes:
                    self._add_test_result(
                        "api_discovery",
                        "PASS",
                        f"Found {len(gdpr_routes)} GDPR-related API routes in {len(gdpr_namespaces)} namespaces",
                        {"namespaces": gdpr_namespaces, "routes": gdpr_routes}
                    )
                    self.gdpr_endpoints = gdpr_routes
                    return gdpr_routes
                else:
                    # If still no routes found, try with common paths
                    self._add_test_result(
                        "api_discovery",
                        "WARNING",
                        f"Found {len(gdpr_namespaces)} GDPR namespaces but no routes"
                    )
                    return self._discover_by_common_paths()
                
        except requests.exceptions.RequestException as e:
            self._add_test_result(
                "api_discovery",
                "ERROR",
                f"Error during API discovery: {str(e)}"
            )
            return self._discover_by_common_paths()
    
    def _discover_by_common_paths(self):
        """Fallback method to discover API endpoints by checking common paths."""
        common_paths = [
            "/wp/v2/users",
            "/wp/v2/users/me",
            "/wp-gdpr/v1/consent",
            "/wp-gdpr/v1/consents",
            "/wp-gdpr/v1/export",
            "/wp-gdpr/v1/delete",
            "/wp-gdpr/v1/access-request",
            "/gdpr/v1/consents",
            "/gdpr/v1/user-data",
            "/gdpr/v1/delete",
            "/privacy/v1/export",
            "/privacy/v1/erasure",
            "/complianz/v1/consent",
            "/complianz/v1/track",
            "/consent/v1/data",
            "/wp-data-access/v1/users"
        ]
        
        # Also include common paths with the site namespace
        site_name = urlparse(self.target_url).netloc.split('.')[0]
        if site_name != 'www':
            for path in list(common_paths):  # Make a copy to avoid modifying during iteration
                if path.startswith('/wp-gdpr'):
                    common_paths.append(path.replace('/wp-gdpr', f'/{site_name}-gdpr'))
                if path.startswith('/gdpr'):
                    common_paths.append(path.replace('/gdpr', f'/{site_name}'))
        
        found_paths = []
        
        for path in common_paths:
            full_url = f"{self.api_url}{path}"
            
            try:
                response = self.session.get(
                    full_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                # Consider it a valid endpoint if it returns anything other than 404
                if response.status_code != 404:
                    found_paths.append(path)
            except:
                continue
        
        if found_paths:
            self._add_test_result(
                "api_discovery",
                "PASS",
                f"Found {len(found_paths)} GDPR-related API endpoints by checking common paths",
                {"endpoints": found_paths}
            )
        else:
            self._add_test_result(
                "api_discovery",
                "FAIL",
                "No GDPR-related API endpoints found"
            )
        
        self.gdpr_endpoints = found_paths
        return found_paths
    
    def test_authentication_requirements(self, endpoints=None):
        """Test if the GDPR API endpoints require authentication."""
        if not endpoints:
            endpoints = self.gdpr_endpoints
            
        if not endpoints:
            self._add_test_result(
                "api_auth_requirements",
                "SKIP",
                "No endpoints to test for authentication requirements"
            )
            return
            
        try:
            # First test with no authentication
            unauth_session = requests.Session()
            unauth_session.headers.update({
                'User-Agent': 'GDPR API Auth Tester/1.0 (https://github.com/PanagiotisNikolaidis236322/Wordpress-gdpr-framework-thesis)'
            })
            
            endpoints_status = []
            
            for endpoint in endpoints:
                full_url = f"{self.api_url}{endpoint}"
                
                try:
                    response = unauth_session.get(
                        full_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    endpoints_status.append({
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "requires_auth": response.status_code in [401, 403],
                        "response_size": len(response.content)
                    })
                    
                except requests.exceptions.RequestException as e:
                    endpoints_status.append({
                        "endpoint": endpoint,
                        "error": str(e),
                        "requires_auth": False  # Can't determine
                    })
            
            # Count endpoints that require authentication
            auth_required = sum(1 for endpoint in endpoints_status if endpoint.get("requires_auth", False))
            auth_percentage = (auth_required / len(endpoints_status)) * 100 if endpoints_status else 0
            
            if auth_percentage == 100:
                self._add_test_result(
                    "api_auth_requirements",
                    "PASS",
                    "All GDPR-related API endpoints require authentication",
                    {"endpoints": endpoints_status}
                )
            elif auth_percentage >= 80:
                self._add_test_result(
                    "api_auth_requirements",
                    "WARNING",
                    f"{auth_percentage:.1f}% of GDPR-related API endpoints require authentication",
                    {"endpoints": endpoints_status}
                )
            else:
                self._add_test_result(
                    "api_auth_requirements",
                    "FAIL",
                    f"Only {auth_percentage:.1f}% of GDPR-related API endpoints require authentication",
                    {"endpoints": endpoints_status}
                )
            
            return endpoints_status
            
        except Exception as e:
            self._add_test_result(
                "api_auth_requirements",
                "ERROR",
                f"Error testing API authentication requirements: {str(e)}"
            )
            return None
    
    def test_authentication_method(self):
        """Test what authentication method is used by the WordPress API."""
        if not self._admin_login():
            self._add_test_result(
                "api_auth_method",
                "SKIP",
                "Skipping authentication method test due to login failure"
            )
            return
            
        try:
            # Check if there's a REST API settings page we can examine
            rest_settings_paths = [
                "/wp-admin/options-general.php?page=rest-api-settings",
                "/wp-admin/admin.php?page=rest-api",
                "/wp-admin/options-general.php?page=api-settings",
                "/wp-admin/admin.php?page=wp-rest-api"
            ]
            
            auth_method_found = False
            auth_method = None
            
            # First try to find settings pages that might reveal auth method
            for path in rest_settings_paths:
                response = self.session.get(
                    self.target_url + path,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for authentication method settings
                    auth_terms = ['oauth', 'bearer token', 'jwt', 'api key', 'application password', 'basic auth']
                    
                    for term in auth_terms:
                        elements = soup.find_all(text=re.compile(term, re.IGNORECASE))
                        if elements:
                            auth_method_found = True
                            auth_method = term
                            break
                    
                    if auth_method_found:
                        break
            
            # If we couldn't find settings, try to determine from API response headers
            if not auth_method_found:
                # Try to access an endpoint that requires auth with our authenticated session
                auth_probe_endpoints = ["/wp/v2/users/me", "/wp/v2/users"]
                
                for endpoint in auth_probe_endpoints:
                    full_url = f"{self.api_url}{endpoint}"
                    
                    response = self.session.get(
                        full_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        # Check response headers for authentication clues
                        www_auth = response.headers.get('WWW-Authenticate', '')
                        
                        if 'oauth' in www_auth.lower():
                            auth_method_found = True
                            auth_method = 'OAuth'
                            break
                        elif 'bearer' in www_auth.lower():
                            auth_method_found = True
                            auth_method = 'Bearer Token'
                            break
                        elif 'jwt' in www_auth.lower():
                            auth_method_found = True
                            auth_method = 'JWT'
                            break
                        elif 'basic' in www_auth.lower():
                            auth_method_found = True
                            auth_method = 'Basic Auth'
                            break
                
                # If still not found, make a dedicated request to get nonce
                if not auth_method_found:
                    # Try to find nonce in the admin area
                    response = self.session.get(
                        f"{self.admin_url}/index.php",
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for REST API nonce in script tags
                    scripts = soup.find_all('script')
                    nonce_pattern = re.compile(r'wp_(?:api|rest)_nonce["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE)
                    
                    for script in scripts:
                        if script.string:
                            match = nonce_pattern.search(script.string)
                            if match:
                                auth_method_found = True
                                auth_method = 'WP Nonce'
                                break
                    
                    # If still not found, try to detect Application Passwords
                    if not auth_method_found:
                        response = self.session.get(
                            f"{self.admin_url}/profile.php",
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                        
                        if 'application passwords' in response.text.lower():
                            auth_method_found = True
                            auth_method = 'Application Passwords'
            
            # Evaluate the authentication method
            if auth_method_found:
                auth_strength = {
                    'oauth': 'HIGH',
                    'oauth 2.0': 'HIGH',
                    'bearer token': 'MEDIUM',
                    'jwt': 'MEDIUM',
                    'application passwords': 'MEDIUM',
                    'api key': 'LOW',
                    'basic auth': 'LOW',
                    'wp nonce': 'LOW'
                }
                
                method_lower = auth_method.lower()
                strength = next((v for k, v in auth_strength.items() if k in method_lower), 'UNKNOWN')
                
                if strength == 'HIGH':
                    self._add_test_result(
                        "api_auth_method",
                        "PASS",
                        f"Strong authentication method detected: {auth_method}",
                        {"method": auth_method, "strength": strength}
                    )
                elif strength == 'MEDIUM':
                    self._add_test_result(
                        "api_auth_method",
                        "WARNING",
                        f"Moderate authentication method detected: {auth_method}",
                        {"method": auth_method, "strength": strength}
                    )
                elif strength == 'LOW':
                    self._add_test_result(
                        "api_auth_method",
                        "FAIL",
                        f"Weak authentication method detected: {auth_method}",
                        {"method": auth_method, "strength": strength}
                    )
                else:
                    self._add_test_result(
                        "api_auth_method",
                        "WARNING",
                        f"Unknown authentication method strength: {auth_method}",
                        {"method": auth_method, "strength": strength}
                    )
            else:
                self._add_test_result(
                    "api_auth_method",
                    "FAIL",
                    "Could not determine API authentication method"
                )
                
        except Exception as e:
            self._add_test_result(
                "api_auth_method",
                "ERROR",
                f"Error testing API authentication method: {str(e)}"
            )
    
    def test_token_security(self):
        """Test the security of authentication tokens."""
        if not self._admin_login():
            self._add_test_result(
                "token_security",
                "SKIP",
                "Skipping token security test due to login failure"
            )
            return
            
        try:
            # Look for token expiration settings or documentation
            token_settings_paths = [
                "/wp-admin/options-general.php?page=rest-api-settings",
                "/wp-admin/admin.php?page=rest-api",
                "/wp-admin/options-general.php?page=api-settings",
                "/wp-admin/admin.php?page=wp-rest-api",
                "/wp-admin/options-general.php?page=jwt-auth"
            ]
            
            expiration_found = False
            expiration_time = None
            
            for path in token_settings_paths:
                response = self.session.get(
                    self.target_url + path,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Look for expiration settings
                    expiration_terms = ['token expiration', 'token lifetime', 'expires after', 'timeout']
                    
                    for term in expiration_terms:
                        elements = soup.find_all(text=re.compile(term, re.IGNORECASE))
                        if elements:
                            # Try to extract expiration time
                            for element in elements:
                                parent = element.parent
                                if parent:
                                    # Look for input fields near this text
                                    inputs = parent.find_all('input')
                                    selects = parent.find_all('select')
                                    
                                    if inputs:
                                        for input_field in inputs:
                                            if input_field.get('value'):
                                                expiration_found = True
                                                expiration_time = input_field.get('value')
                                                break
                                    
                                    if selects and not expiration_found:
                                        for select in selects:
                                            selected_option = select.find('option', selected=True)
                                            if selected_option and selected_option.get('value'):
                                                expiration_found = True
                                                expiration_time = selected_option.get('value')
                                                break
                            
                            if expiration_found:
                                break
                    
                    if expiration_found:
                        break
            
            # If we found expiration settings, evaluate them
            if expiration_found:
                try:
                    # Try to parse the expiration time
                    expiration_val = int(re.search(r'\d+', expiration_time).group())
                    
                    # Check if it's in minutes, hours, or days
                    if 'minute' in expiration_time.lower():
                        expiration_minutes = expiration_val
                    elif 'hour' in expiration_time.lower():
                        expiration_minutes = expiration_val * 60
                    elif 'day' in expiration_time.lower():
                        expiration_minutes = expiration_val * 1440
                    else:
                        # Assume it's in seconds
                        expiration_minutes = expiration_val / 60
                    
                    # Evaluate the expiration time
                    if expiration_minutes <= 60:  # 1 hour or less
                        self._add_test_result(
                            "token_security",
                            "PASS",
                            f"Short token expiration time: {expiration_time}",
                            {"expiration_time": expiration_time, "minutes": expiration_minutes}
                        )
                    elif expiration_minutes <= 1440:  # 24 hours or less
                        self._add_test_result(
                            "token_security",
                            "WARNING",
                            f"Moderate token expiration time: {expiration_time}",
                            {"expiration_time": expiration_time, "minutes": expiration_minutes}
                        )
                    else:
                        self._add_test_result(
                            "token_security",
                            "FAIL",
                            f"Long token expiration time: {expiration_time}",
                            {"expiration_time": expiration_time, "minutes": expiration_minutes}
                        )
                except:
                    # If we can't parse the value, just report what we found
                    self._add_test_result(
                        "token_security",
                        "INFO",
                        f"Token expiration setting found but could not be parsed: {expiration_time}"
                    )
            else:
                # If we couldn't find expiration settings, check for HTTPS to ensure token transmission security
                site_uses_https = self.target_url.startswith('https://')
                
                if site_uses_https:
                    self._add_test_result(
                        "token_security",
                        "WARNING",
                        "Could not determine token expiration settings, but site uses HTTPS"
                    )
                else:
                    self._add_test_result(
                        "token_security",
                        "FAIL",
                        "Could not determine token expiration settings, and site does not use HTTPS"
                    )
                
        except Exception as e:
            self._add_test_result(
                "token_security",
                "ERROR",
                f"Error testing token security: {str(e)}"
            )
    
    def test_rate_limiting(self):
        """Test if the API implements rate limiting to prevent abuse."""
        try:
            # Pick an endpoint that requires authentication
            test_endpoint = None
            
            for endpoint in self.gdpr_endpoints:
                full_url = f"{self.api_url}{endpoint}"
                
                try:
                    response = requests.get(
                        full_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code in [401, 403]:
                        test_endpoint = endpoint
                        break
                except:
                    continue
            
            if not test_endpoint:
                # If no GDPR endpoint is suitable, use a common WordPress endpoint
                test_endpoint = "/wp/v2/users"
            
            full_url = f"{self.api_url}{test_endpoint}"
            
            # Make several rapid requests to trigger rate limiting
            rate_limit_detected = False
            rate_limit_headers = {}
            
            # Make 10 requests in quick succession
            for i in range(10):
                response = requests.get(
                    full_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                # Check for rate limiting headers
                rate_limit_header_keys = [
                    'X-Rate-Limit',
                    'X-RateLimit-Limit',
                    'X-RateLimit-Remaining',
                    'X-RateLimit-Reset',
                    'Retry-After',
                    'RateLimit-Limit',
                    'RateLimit-Remaining',
                    'RateLimit-Reset'
                ]
                
                for key in rate_limit_header_keys:
                    if key.lower() in [k.lower() for k in response.headers.keys()]:
                        rate_limit_detected = True
                        rate_limit_headers[key] = response.headers[key]
                
                # Also check if we got a 429 Too Many Requests response
                if response.status_code == 429:
                    rate_limit_detected = True
                    break
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.2)
            
            if rate_limit_detected:
                self._add_test_result(
                    "api_rate_limiting",
                    "PASS",
                    "API implements rate limiting",
                    {"rate_limit_headers": rate_limit_headers}
                )
            else:
                self._add_test_result(
                    "api_rate_limiting",
                    "WARNING",
                    "No evidence of API rate limiting detected"
                )
                
        except Exception as e:
            self._add_test_result(
                "api_rate_limiting",
                "ERROR",
                f"Error testing API rate limiting: {str(e)}"
            )
    
    def run_all_tests(self):
        """Run all GDPR API authentication tests."""
        try:
            # First discover API endpoints
            self.discover_api_endpoints()
            
            if self.gdpr_endpoints:
                # Test authentication requirements
                self.test_authentication_requirements()
                
                # Test authentication method
                self.test_authentication_method()
                
                # Test token security
                self.test_token_security()
                
                # Test rate limiting
                self.test_rate_limiting()
            
            # Calculate overall result
            test_results = [test["status"] for test in self.results["tests"] 
                           if test["name"] not in ["admin_login"]]
            
            if "ERROR" in test_results:
                self.results["overall_result"] = "ERROR"
            elif "FAIL" in test_results:
                self.results["overall_result"] = "FAIL"
            elif "WARNING" in test_results:
                self.results["overall_result"] = "WARNING"
            else:
                self.results["overall_result"] = "PASS"
                
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
        
        # Print summary to console
        passed = sum(1 for test in self.results["tests"] 
                    if test["status"] == "PASS" and test["name"] != "admin_login")
        warnings = sum(1 for test in self.results["tests"] 
                      if test["status"] == "WARNING" and test["name"] != "admin_login")
        failed = sum(1 for test in self.results["tests"] 
                    if test["status"] == "FAIL" and test["name"] != "admin_login")
        errors = sum(1 for test in self.results["tests"] 
                    if test["status"] == "ERROR" and test["name"] != "admin_login")
        skipped = sum(1 for test in self.results["tests"] 
                     if test["status"] == "SKIP" and test["name"] != "admin_login")
        
        print("\n" + "="*60)
        print(f"GDPR API AUTHENTICATION REPORT: {self.target_url}")
        print("="*60)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Overall Result: {self.results['overall_result']}")
        print(f"Tests: {passed + warnings + failed + errors + skipped} total, {passed} passed, {warnings} warnings, {failed} failed, {errors} errors, {skipped} skipped")
        print("-"*60)
        
        for test in self.results["tests"]:
            if test["name"] != "admin_login":  # Skip login status
                status_display = {
                    "PASS": "✅ PASS",
                    "WARNING": "⚠️ WARNING",
                    "FAIL": "❌ FAIL",
                    "ERROR": "⚠️ ERROR",
                    "SKIP": "⏭️ SKIP",
                    "INFO": "ℹ️ INFO"
                }
                print(f"{status_display[test['status']]}: {test['name']} - {test['message']}")
            
        print("="*60)
        
        if self.results['overall_result'] == "PASS":
            print("✅ The API authentication implementation meets GDPR security requirements.")
        elif self.results['overall_result'] == "WARNING":
            print("⚠️ The API authentication implementation needs improvements to fully meet GDPR security requirements.")
        elif self.results['overall_result'] == "FAIL":
            print("❌ The API authentication implementation does not meet GDPR security requirements.")
        else:
            print("⚠️ Could not fully assess the API authentication implementation due to errors.")
            
        print("\n")
        
        return self.results


def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description='GDPR API Authentication Tester')
    parser.add_argument('url', help='Target WordPress URL')
    parser.add_argument('--admin-url', help='WordPress admin URL if different from default')
    parser.add_argument('--admin-username', help='WordPress admin username')
    parser.add_argument('--admin-password', help='WordPress admin password')
    parser.add_argument('--output', '-o', help='Output file for JSON report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL verification')
    
    args = parser.parse_args()
    
    tester = GDPRAPIAuthTester(
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
