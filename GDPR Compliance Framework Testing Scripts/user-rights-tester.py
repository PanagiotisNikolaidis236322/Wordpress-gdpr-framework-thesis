#!/usr/bin/env python3
"""
GDPR User Rights Tester
-----------------------
This script tests the implementation of GDPR user rights in a WordPress installation.
It validates if the system correctly implements data access, rectification, deletion,
and portability rights as required by GDPR Articles 15-20.

Requirements:
- Python 3.6+
- requests
- faker
- beautifulsoup4
- selenium

Installation:
pip install requests faker beautifulsoup4 selenium

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
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from faker import Faker
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class GDPRUserRightsTester:
    """Tester for GDPR user rights in WordPress."""
    
    def __init__(self, target_url, admin_url=None, admin_username=None, admin_password=None, headless=True):
        """Initialize the tester with target URLs and credentials."""
        self.target_url = target_url.rstrip('/')
        
        # Determine admin URL if not provided
        if admin_url:
            self.admin_url = admin_url.rstrip('/')
        else:
            self.admin_url = f"{self.target_url}/wp-admin"
            
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.headless = headless
        self.fake = Faker()
        
        # Test user credentials
        self.test_user = {
            'username': f"gdpr_test_{self._random_string(6)}",
            'email': f"gdpr_test_{self._random_string(6)}@example.com",
            'password': self._random_string(12),
            'first_name': self.fake.first_name(),
            'last_name': self.fake.last_name()
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GDPR User Rights Tester/1.0 (https://github.com/PanagiotisNikolaidis236322/Wordpress-gdpr-framework-thesis)'
        })
        
        # Results container
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "tests": [],
            "overall_result": "PENDING"
        }
        
        # Initialize selenium webdriver
        chrome_options = Options()
        if headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        
        self.driver = webdriver.Chrome(options=chrome_options)
        
    def __del__(self):
        """Clean up webdriver on destruction."""
        try:
            self.driver.quit()
        except:
            pass
    
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
            self.driver.get(f"{self.admin_url}/wp-login.php")
            
            # Wait for login form to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "loginform"))
            )
            
            # Fill login form
            username_field = self.driver.find_element(By.ID, "user_login")
            password_field = self.driver.find_element(By.ID, "user_pass")
            submit_button = self.driver.find_element(By.ID, "wp-submit")
            
            username_field.send_keys(self.admin_username)
            password_field.send_keys(self.admin_password)
            submit_button.click()
            
            # Wait for dashboard to load
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.ID, "wpadminbar"))
                )
                self._add_test_result(
                    "admin_login",
                    "PASS",
                    "Successfully logged in as admin"
                )
                return True
            except TimeoutException:
                self._add_test_result(
                    "admin_login",
                    "FAIL",
                    "Failed to login as admin - incorrect credentials or dashboard not loaded"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "admin_login",
                "ERROR",
                f"Error during admin login: {str(e)}"
            )
            return False
    
    def _create_test_user(self):
        """Create a test user for GDPR rights testing."""
        if not self._admin_login():
            return False
            
        try:
            # Navigate to Add New User page
            self.driver.get(f"{self.admin_url}/user-new.php")
            
            # Wait for user form to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "createuser"))
            )
            
            # Fill user form
            self.driver.find_element(By.ID, "user_login").send_keys(self.test_user['username'])
            self.driver.find_element(By.ID, "email").send_keys(self.test_user['email'])
            self.driver.find_element(By.ID, "first_name").send_keys(self.test_user['first_name'])
            self.driver.find_element(By.ID, "last_name").send_keys(self.test_user['last_name'])
            self.driver.find_element(By.ID, "pass1").send_keys(self.test_user['password'])
            
            # Find and click the role dropdown, select subscriber
            role_dropdown = self.driver.find_element(By.ID, "role")
            for option in role_dropdown.find_elements(By.TAG_NAME, "option"):
                if option.text.lower() == "subscriber":
                    option.click()
                    break
            
            # Submit form
            self.driver.find_element(By.ID, "createusersub").click()
            
            # Check for success message
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.CLASS_NAME, "updated"))
                )
                self._add_test_result(
                    "create_test_user",
                    "PASS",
                    f"Successfully created test user: {self.test_user['username']}",
                    {"test_user": {k: v for k, v in self.test_user.items() if k != 'password'}}
                )
                return True
            except TimeoutException:
                # Check for error message
                errors = self.driver.find_elements(By.CLASS_NAME, "error")
                error_messages = [error.text for error in errors if error.is_displayed()]
                
                self._add_test_result(
                    "create_test_user",
                    "FAIL",
                    f"Failed to create test user: {' '.join(error_messages)}",
                    {"errors": error_messages}
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "create_test_user",
                "ERROR",
                f"Error creating test user: {str(e)}"
            )
            return False
    
    def _test_user_login(self):
        """Login using the test user credentials."""
        try:
            # First logout if already logged in
            self.driver.get(f"{self.admin_url}/wp-login.php?action=logout")
            
            try:
                # Click the confirm logout link if present
                logout_links = self.driver.find_elements(By.XPATH, "//a[contains(text(), 'log out')]")
                if logout_links:
                    logout_links[0].click()
            except:
                pass
            
            # Now login with test user
            self.driver.get(f"{self.admin_url}/wp-login.php")
            
            # Wait for login form to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "loginform"))
            )
            
            # Fill login form
            username_field = self.driver.find_element(By.ID, "user_login")
            password_field = self.driver.find_element(By.ID, "user_pass")
            submit_button = self.driver.find_element(By.ID, "wp-submit")
            
            username_field.send_keys(self.test_user['username'])
            password_field.send_keys(self.test_user['password'])
            submit_button.click()
            
            # Wait for dashboard or profile to load
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.ID, "wpadminbar"))
                )
                self._add_test_result(
                    "test_user_login",
                    "PASS",
                    f"Successfully logged in as test user: {self.test_user['username']}"
                )
                return True
            except TimeoutException:
                self._add_test_result(
                    "test_user_login",
                    "FAIL",
                    "Failed to login as test user"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "test_user_login",
                "ERROR",
                f"Error during test user login: {str(e)}"
            )
            return False
    
    def test_data_access_right(self):
        """Test if user can access their personal data (GDPR Article 15)."""
        if not self._test_user_login():
            self._add_test_result(
                "data_access_right",
                "SKIP",
                "Skipping access right test due to login failure"
            )
            return False
            
        try:
            # Different paths to look for GDPR data access functionality
            gdpr_paths = [
                "/wp-admin/profile.php",  # Standard profile may have GDPR options
                "/wp-admin/tools.php",    # Some plugins add to tools menu
                "/wp-admin/admin.php?page=gdpr-tools",
                "/wp-admin/admin.php?page=gdpr-settings",
                "/wp-admin/admin.php?page=gdpr-privacy"
            ]
            
            data_request_found = False
            data_access_link = None
            
            for path in gdpr_paths:
                self.driver.get(f"{self.admin_url}{path}")
                time.sleep(2)  # Allow page to load
                
                # Look for data export/access links or buttons
                access_terms = ["export my data", "personal data", "export data", "download my data", 
                               "access my data", "data access request", "export personal data"]
                               
                for term in access_terms:
                    elements = self.driver.find_elements(By.XPATH, 
                        f"//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{term}')]")
                    
                    if elements:
                        for elem in elements:
                            if elem.is_displayed():
                                data_access_link = elem
                                data_request_found = True
                                break
                
                if data_request_found:
                    break
            
            if not data_request_found:
                # Specifically check the core WordPress privacy tools if nothing found before
                self.driver.get(f"{self.admin_url}/tools.php?page=export_personal_data")
                
                try:
                    # Check if this page loaded correctly
                    privacy_heading = WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((By.XPATH, "//h1[contains(text(), 'Export Personal Data')]"))
                    )
                    
                    if privacy_heading:
                        data_request_found = True
                        
                        # Core WordPress has an email confirmation field
                        email_field = self.driver.find_element(By.ID, "email")
                        email_field.clear()
                        email_field.send_keys(self.test_user['email'])
                        
                        # Look for the request button
                        request_buttons = self.driver.find_elements(By.XPATH, "//button[contains(text(), 'Send Request')]")
                        if request_buttons:
                            data_access_link = request_buttons[0]
                except:
                    pass
            
            if not data_request_found:
                self._add_test_result(
                    "data_access_right",
                    "FAIL",
                    "No data access/export functionality found"
                )
                return False
                
            # We found the link, now click it and verify the outcome
            data_access_link.click()
            time.sleep(3)  # Allow time for request processing
            
            # Check for success confirmation
            confirmation_terms = ["success", "confirm", "email sent", "request received", "request submitted"]
            confirmation_found = False
            
            for term in confirmation_terms:
                elements = self.driver.find_elements(By.XPATH, 
                    f"//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{term}')]")
                
                if elements:
                    for elem in elements:
                        if elem.is_displayed():
                            confirmation_found = True
                            break
                            
                if confirmation_found:
                    break
            
            if confirmation_found:
                self._add_test_result(
                    "data_access_right",
                    "PASS",
                    "Successfully initiated data access request"
                )
                return True
            else:
                # If no confirmation, check if we have immediate data access
                download_links = self.driver.find_elements(By.XPATH, "//a[contains(text(), 'Download')]")
                
                if download_links:
                    for link in download_links:
                        if link.is_displayed():
                            self._add_test_result(
                                "data_access_right",
                                "PASS",
                                "Data access functionality provides immediate download"
                            )
                            return True
                
                self._add_test_result(
                    "data_access_right",
                    "WARNING",
                    "Data access request initiated but no clear confirmation"
                )
                return True
                
        except Exception as e:
            self._add_test_result(
                "data_access_right",
                "ERROR",
                f"Error testing data access right: {str(e)}"
            )
            return False
    
    def test_data_rectification_right(self):
        """Test if user can rectify/correct their personal data (GDPR Article 16)."""
        if not self._test_user_login():
            self._add_test_result(
                "data_rectification_right",
                "SKIP",
                "Skipping rectification right test due to login failure"
            )
            return False
            
        try:
            # Navigate to profile page
            self.driver.get(f"{self.admin_url}/profile.php")
            
            # Wait for profile page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "profile-page"))
            )
            
            # Modify personal information
            new_first_name = self.fake.first_name()
            new_last_name = self.fake.last_name()
            
            first_name_field = self.driver.find_element(By.ID, "first_name")
            last_name_field = self.driver.find_element(By.ID, "last_name")
            
            first_name_field.clear()
            first_name_field.send_keys(new_first_name)
            
            last_name_field.clear()
            last_name_field.send_keys(new_last_name)
            
            # Submit the form
            submit_button = self.driver.find_element(By.ID, "submit")
            submit_button.click()
            
            # Check for success message
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.CLASS_NAME, "updated"))
                )
                
                # Reload the page to verify changes were saved
                self.driver.get(f"{self.admin_url}/profile.php")
                
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.ID, "profile-page"))
                )
                
                # Verify fields contain the new values
                first_name_field = self.driver.find_element(By.ID, "first_name")
                last_name_field = self.driver.find_element(By.ID, "last_name")
                
                if first_name_field.get_attribute("value") == new_first_name and last_name_field.get_attribute("value") == new_last_name:
                    self._add_test_result(
                        "data_rectification_right",
                        "PASS",
                        "Successfully updated personal data",
                        {"updated_fields": {"first_name": new_first_name, "last_name": new_last_name}}
                    )
                    return True
                else:
                    self._add_test_result(
                        "data_rectification_right",
                        "FAIL",
                        "Failed to update personal data - changes not saved"
                    )
                    return False
                    
            except TimeoutException:
                self._add_test_result(
                    "data_rectification_right",
                    "FAIL",
                    "Failed to update personal data - no confirmation received"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "data_rectification_right",
                "ERROR",
                f"Error testing data rectification right: {str(e)}"
            )
            return False
    
    def test_data_erasure_right(self):
        """Test if user can request erasure of their personal data (GDPR Article 17)."""
        if not self._test_user_login():
            self._add_test_result(
                "data_erasure_right",
                "SKIP",
                "Skipping erasure right test due to login failure"
            )
            return False
            
        try:
            # Different paths to look for GDPR data erasure functionality
            gdpr_paths = [
                "/wp-admin/profile.php",  # Standard profile may have GDPR options
                "/wp-admin/tools.php",    # Some plugins add to tools menu
                "/wp-admin/admin.php?page=gdpr-tools",
                "/wp-admin/admin.php?page=gdpr-settings",
                "/wp-admin/admin.php?page=gdpr-privacy"
            ]
            
            erasure_request_found = False
            erasure_link = None
            
            for path in gdpr_paths:
                self.driver.get(f"{self.admin_url}{path}")
                time.sleep(2)  # Allow page to load
                
                # Look for data erasure links or buttons
                erasure_terms = ["delete my data", "erase my data", "remove my data", 
                                "forget me", "right to be forgotten", "data erasure", 
                                "delete account", "erase personal data"]
                               
                for term in erasure_terms:
                    elements = self.driver.find_elements(By.XPATH, 
                        f"//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{term}')]")
                    
                    if elements:
                        for elem in elements:
                            if elem.is_displayed():
                                erasure_link = elem
                                erasure_request_found = True
                                break
                
                if erasure_request_found:
                    break
            
            if not erasure_request_found:
                # Specifically check the core WordPress privacy tools if nothing found before
                self.driver.get(f"{self.admin_url}/tools.php?page=remove_personal_data")
                
                try:
                    # Check if this page loaded correctly
                    privacy_heading = WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((By.XPATH, "//h1[contains(text(), 'Erase Personal Data')]"))
                    )
                    
                    if privacy_heading:
                        erasure_request_found = True
                        
                        # Core WordPress has an email confirmation field
                        email_field = self.driver.find_element(By.ID, "email")
                        email_field.clear()
                        email_field.send_keys(self.test_user['email'])
                        
                        # Look for the request button
                        request_buttons = self.driver.find_elements(By.XPATH, "//button[contains(text(), 'Send Request')]")
                        if request_buttons:
                            erasure_link = request_buttons[0]
                except:
                    pass
            
            if not erasure_request_found:
                self._add_test_result(
                    "data_erasure_right",
                    "FAIL",
                    "No data erasure functionality found"
                )
                return False
                
            # We found the link, now click it and verify the outcome
            erasure_link.click()
            time.sleep(3)  # Allow time for request processing
            
            # Check for success confirmation
            confirmation_terms = ["success", "confirm", "email sent", "request received", "request submitted"]
            confirmation_found = False
            
            for term in confirmation_terms:
                elements = self.driver.find_elements(By.XPATH, 
                    f"//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{term}')]")
                
                if elements:
                    for elem in elements:
                        if elem.is_displayed():
                            confirmation_found = True
                            break
                            
                if confirmation_found:
                    break
            
            if confirmation_found:
                self._add_test_result(
                    "data_erasure_right",
                    "PASS",
                    "Successfully initiated data erasure request"
                )
                return True
            else:
                # If no confirmation, check if we have immediate actions
                action_buttons = self.driver.find_elements(By.XPATH, 
                    "//button[contains(text(), 'Confirm') or contains(text(), 'Delete') or contains(text(), 'Erase')]")
                
                if action_buttons:
                    for button in action_buttons:
                        if button.is_displayed():
                            self._add_test_result(
                                "data_erasure_right",
                                "PASS",
                                "Data erasure functionality provides immediate action"
                            )
                            return True
                
                self._add_test_result(
                    "data_erasure_right",
                    "WARNING",
                    "Data erasure request initiated but no clear confirmation"
                )
                return True
                
        except Exception as e:
            self._add_test_result(
                "data_erasure_right",
                "ERROR",
                f"Error testing data erasure right: {str(e)}"
            )
            return False
    
    def test_data_portability_right(self):
        """Test if user can receive their data in a portable format (GDPR Article 20)."""
        if not self._test_user_login():
            self._add_test_result(
                "data_portability_right",
                "SKIP",
                "Skipping portability right test due to login failure"
            )
            return False
            
        try:
            # For portability, we'll reuse the data access test but look specifically
            # for machine-readable formats like JSON, XML, or CSV
            
            # Navigate to the export personal data page
            self.driver.get(f"{self.admin_url}/tools.php?page=export_personal_data")
            
            try:
                # Check if this page loaded correctly
                privacy_heading = WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.XPATH, "//h1[contains(text(), 'Export Personal Data')]"))
                )
                
                # Look for format information
                page_source = self.driver.page_source.lower()
                
                portable_formats = ["json", "xml", "csv", "machine-readable", "portable format"]
                format_mentioned = False
                
                for format_term in portable_formats:
                    if format_term in page_source:
                        format_mentioned = True
                        break
                
                if format_mentioned:
                    self._add_test_result(
                        "data_portability_right",
                        "PASS",
                        "Data export functionality mentions machine-readable formats"
                    )
                    return True
                else:
                    # If we don't see explicit mention of formats, still pass but with a warning
                    self._add_test_result(
                        "data_portability_right",
                        "WARNING",
                        "Data export functionality exists but doesn't explicitly mention portable formats"
                    )
                    return True
                    
            except TimeoutException:
                # If the export page doesn't exist, check for other portability options
                gdpr_paths = [
                    "/wp-admin/admin.php?page=gdpr-tools",
                    "/wp-admin/admin.php?page=gdpr-settings",
                    "/wp-admin/admin.php?page=gdpr-privacy"
                ]
                
                portability_found = False
                
                for path in gdpr_paths:
                    self.driver.get(f"{self.admin_url}{path}")
                    time.sleep(2)  # Allow page to load
                    
                    # Look for data portability links or buttons
                    portability_terms = ["data portability", "portable format", "download data", "export data", 
                                        "json export", "xml export", "csv export"]
                                       
                    for term in portability_terms:
                        elements = self.driver.find_elements(By.XPATH, 
                            f"//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{term}')]")
                        
                        if elements:
                            for elem in elements:
                                if elem.is_displayed():
                                    portability_found = True
                                    break
                        
                        if portability_found:
                            break
                    
                    if portability_found:
                        break
                
                if portability_found:
                    self._add_test_result(
                        "data_portability_right",
                        "PASS",
                        "Data portability functionality found"
                    )
                    return True
                else:
                    self._add_test_result(
                        "data_portability_right",
                        "FAIL",
                        "No data portability functionality found"
                    )
                    return False
                
        except Exception as e:
            self._add_test_result(
                "data_portability_right",
                "ERROR",
                f"Error testing data portability right: {str(e)}"
            )
            return False
    
    def _cleanup_test_user(self):
        """Delete the test user at the end of testing."""
        if not self._admin_login():
            self._add_test_result(
                "cleanup_test_user",
                "SKIP",
                "Skipping test user cleanup due to login failure"
            )
            return False
            
        try:
            # Navigate to Users page
            self.driver.get(f"{self.admin_url}/users.php")
            
            # Wait for users table to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "wp-list-table"))
            )
            
            # Find the test user row
            user_rows = self.driver.find_elements(By.XPATH, f"//tr[contains(@id, 'user-')]")
            test_user_row = None
            
            for row in user_rows:
                if self.test_user['username'] in row.text or self.test_user['email'] in row.text:
                    test_user_row = row
                    break
            
            if not test_user_row:
                self._add_test_result(
                    "cleanup_test_user",
                    "FAIL",
                    f"Test user not found for cleanup: {self.test_user['username']}"
                )
                return False
                
            # Hover over the row to reveal actions
            actions = test_user_row.find_elements(By.CLASS_NAME, "row-actions")
            
            if actions:
                # Find the delete link
                delete_links = actions[0].find_elements(By.XPATH, ".//a[contains(@href, 'delete') or contains(text(), 'Delete')]")
                
                if delete_links:
                    delete_links[0].click()
                    
                    # Wait for confirmation page
                    WebDriverWait(self.driver, 10).until(
                        EC.presence_of_element_located((By.ID, "submit"))
                    )
                    
                    # Confirm deletion
                    self.driver.find_element(By.ID, "submit").click()
                    
                    # Check for success message
                    try:
                        WebDriverWait(self.driver, 10).until(
                            EC.presence_of_element_located((By.CLASS_NAME, "updated"))
                        )
                        self._add_test_result(
                            "cleanup_test_user",
                            "PASS",
                            f"Successfully deleted test user: {self.test_user['username']}"
                        )
                        return True
                    except TimeoutException:
                        self._add_test_result(
                            "cleanup_test_user",
                            "FAIL",
                            "Failed to delete test user - no confirmation received"
                        )
                        return False
                else:
                    self._add_test_result(
                        "cleanup_test_user",
                        "FAIL",
                        "Delete action not found for test user"
                    )
                    return False
            else:
                self._add_test_result(
                    "cleanup_test_user",
                    "FAIL",
                    "No actions found for test user"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "cleanup_test_user",
                "ERROR",
                f"Error during test user cleanup: {str(e)}"
            )
            return False
    
    def run_all_tests(self):
        """Run all GDPR user rights tests."""
        try:
            # Create a test user for running the tests
            user_created = self._create_test_user()
            
            if not user_created:
                self.results["overall_result"] = "ERROR"
                return self.results
                
            # Run all GDPR rights tests
            self.test_data_access_right()
            self.test_data_rectification_right()
            self.test_data_erasure_right()
            self.test_data_portability_right()
            
            # Clean up the test user
            self._cleanup_test_user()
            
            # Calculate overall result
            test_results = [test["status"] for test in self.results["tests"] 
                           if test["name"] not in ["admin_login", "create_test_user", "test_user_login", "cleanup_test_user"]]
            
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
            return self.results
    
    def generate_report(self, output_file=None):
        """Generate a JSON report of test results."""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        
        # Print summary to console
        passed = sum(1 for test in self.results["tests"] 
                    if test["status"] == "PASS" and test["name"] not in ["admin_login", "create_test_user", "test_user_login", "cleanup_test_user"])
        failed = sum(1 for test in self.results["tests"] 
                    if test["status"] == "FAIL" and test["name"] not in ["admin_login", "create_test_user", "test_user_login", "cleanup_test_user"])
        warnings = sum(1 for test in self.results["tests"] 
                      if test["status"] == "WARNING" and test["name"] not in ["admin_login", "create_test_user", "test_user_login", "cleanup_test_user"])
        errors = sum(1 for test in self.results["tests"] 
                    if test["status"] == "ERROR" and test["name"] not in ["admin_login", "create_test_user", "test_user_login", "cleanup_test_user"])
        skipped = sum(1 for test in self.results["tests"] 
                     if test["status"] == "SKIP" and test["name"] not in ["admin_login", "create_test_user", "test_user_login", "cleanup_test_user"])
        
        print("\n" + "="*60)
        print(f"GDPR USER RIGHTS VALIDATION REPORT: {self.target_url}")
        print("="*60)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Overall Result: {self.results['overall_result']}")
        print(f"Tests: {passed + failed + warnings + errors + skipped} total, {passed} passed, {warnings} warnings, {failed} failed, {errors} errors, {skipped} skipped")
        print("-"*60)
        
        # Group tests
        gdpr_tests = [test for test in self.results["tests"] 
                     if test["name"] not in ["admin_login", "create_test_user", "test_user_login", "cleanup_test_user"]]
        
        for test in gdpr_tests:
            status_display = {
                "PASS": "✅ PASS",
                "WARNING": "⚠️ WARNING",
                "FAIL": "❌ FAIL",
                "ERROR": "⚠️ ERROR",
                "SKIP": "⏭️ SKIP"
            }
            print(f"{status_display[test['status']]}: {test['name']} - {test['message']}")
            
        print("="*60)
        
        return self.results


def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description='GDPR User Rights Tester')
    parser.add_argument('url', help='Target WordPress URL')
    parser.add_argument('--admin-url', help='WordPress admin URL if different from default')
    parser.add_argument('--admin-username', help='WordPress admin username')
    parser.add_argument('--admin-password', help='WordPress admin password')
    parser.add_argument('--output', '-o', help='Output file for JSON report')
    parser.add_argument('--visible', '-v', action='store_true', help='Run in visible mode (not headless)')
    
    args = parser.parse_args()
    
    tester = GDPRUserRightsTester(
        args.url, 
        admin_url=args.admin_url,
        admin_username=args.admin_username,
        admin_password=args.admin_password,
        headless=not args.visible
    )
    
    tester.run_all_tests()
    tester.generate_report(args.output)


if __name__ == "__main__":
    main()
