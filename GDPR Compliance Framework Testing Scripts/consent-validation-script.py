#!/usr/bin/env python3
"""
GDPR Consent Validation Script
------------------------------
This script tests the consent management capabilities of the GDPR Compliance Framework.
It validates the framework's ability to properly store, retrieve, and enforce user consent
in accordance with GDPR Article 7.

Requirements:
- Python 3.6+
- requests
- beautifulsoup4
- selenium

Installation:
pip install requests beautifulsoup4 selenium

Author: Panagiotis Nikolaidis
"""

import argparse
import json
import time
import random
import logging
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class ConsentValidator:
    """Class to validate GDPR consent mechanisms."""
    
    def __init__(self, target_url, headless=True):
        """Initialize the validator with target URL."""
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.headless = headless
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "tests": [],
            "overall_result": "PENDING"
        }
        
        # Initialize webdriver
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
        
    def validate_consent_banner_presence(self):
        """Test if a consent banner is present on first visit."""
        try:
            self.driver.delete_all_cookies()
            self.driver.get(self.target_url)
            
            # Wait for the page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Look for common consent banner indicators
            banner_selectors = [
                ".gdpr-consent-banner", 
                ".cookie-banner", 
                ".cookie-notice", 
                ".consent-banner",
                "#gdpr-cookie-consent",
                "[data-role='gdpr-banner']"
            ]
            
            time.sleep(2)  # Give JavaScript a moment to display the banner
            
            banner_found = False
            banner_element = None
            
            for selector in banner_selectors:
                try:
                    banner_element = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if banner_element.is_displayed():
                        banner_found = True
                        break
                except NoSuchElementException:
                    continue
            
            if banner_found:
                self._add_test_result(
                    "consent_banner_presence", 
                    "PASS",
                    "Consent banner found on first visit",
                    {"element": selector}
                )
                return banner_element
            else:
                self._add_test_result(
                    "consent_banner_presence", 
                    "FAIL",
                    "No consent banner found on first visit"
                )
                return None
                
        except Exception as e:
            self._add_test_result(
                "consent_banner_presence", 
                "ERROR",
                f"Error checking for consent banner: {str(e)}"
            )
            return None
    
    def validate_granular_consent_options(self, banner_element):
        """Test if the consent banner provides granular options."""
        if not banner_element:
            self._add_test_result(
                "granular_consent_options", 
                "SKIP",
                "Cannot validate granular options without a banner"
            )
            return False
            
        try:
            # Look for multiple checkboxes or toggle elements within the banner
            checkboxes = banner_element.find_elements(By.CSS_SELECTOR, "input[type='checkbox']")
            toggles = banner_element.find_elements(By.CSS_SELECTOR, ".toggle, .switch, [role='switch']")
            option_elements = checkboxes + toggles
            
            # Also look for radio buttons in case of category selection
            radio_buttons = banner_element.find_elements(By.CSS_SELECTOR, "input[type='radio']")
            
            if len(option_elements) > 1 or len(radio_buttons) > 2:  # More than accept/reject
                categories = []
                
                for elem in option_elements:
                    # Try to get the label for this option
                    try:
                        # Check for a label associated with this input
                        if elem.get_attribute("id"):
                            label = self.driver.find_element(By.CSS_SELECTOR, f"label[for='{elem.get_attribute('id')}']")
                            categories.append(label.text.strip())
                        else:
                            # If no label, try to get the parent element's text
                            parent = elem.find_element(By.XPATH, "./..")
                            categories.append(parent.text.strip())
                    except:
                        categories.append("Unlabeled option")
                
                self._add_test_result(
                    "granular_consent_options", 
                    "PASS",
                    f"Found {len(option_elements)} granular consent options",
                    {"categories": categories}
                )
                return True
            else:
                # Check for another common UI pattern - buttons for different categories
                category_buttons = banner_element.find_elements(By.CSS_SELECTOR, 
                    ".cookie-category, .consent-category, .gdpr-category, [data-category]")
                
                if len(category_buttons) > 1:
                    categories = [btn.text.strip() for btn in category_buttons]
                    self._add_test_result(
                        "granular_consent_options", 
                        "PASS",
                        f"Found {len(category_buttons)} granular consent options",
                        {"categories": categories}
                    )
                    return True
                
                self._add_test_result(
                    "granular_consent_options", 
                    "FAIL",
                    "No granular consent options found"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "granular_consent_options", 
                "ERROR",
                f"Error checking for granular options: {str(e)}"
            )
            return False
    
    def validate_consent_acceptance(self, banner_element):
        """Test if consenting actually sets cookies and localStorage items."""
        if not banner_element:
            self._add_test_result(
                "consent_acceptance", 
                "SKIP",
                "Cannot validate consent acceptance without a banner"
            )
            return False
            
        try:
            # Get initial cookies and localStorage
            initial_cookies = self.driver.get_cookies()
            initial_local_storage = self._get_local_storage()
            
            # Look for accept buttons
            accept_button_selectors = [
                ".accept-cookies", 
                ".accept-all", 
                ".accept-consent",
                ".gdpr-accept",
                "[data-action='accept']",
                "button:contains('Accept')",
                "button:contains('Accept All')",
                "a:contains('Accept')"
            ]
            
            for selector in accept_button_selectors:
                try:
                    accept_button = banner_element.find_element(By.CSS_SELECTOR, selector)
                    if accept_button.is_displayed():
                        accept_button.click()
                        time.sleep(2)  # Wait for cookies to be set
                        break
                except NoSuchElementException:
                    continue
            
            # Check for new cookies or localStorage items
            new_cookies = self.driver.get_cookies()
            new_local_storage = self._get_local_storage()
            
            cookies_diff = [c for c in new_cookies if c not in initial_cookies]
            ls_keys_diff = set(new_local_storage.keys()) - set(initial_local_storage.keys())
            
            combined_diff = len(cookies_diff) + len(ls_keys_diff)
            
            if combined_diff > 0:
                self._add_test_result(
                    "consent_acceptance", 
                    "PASS",
                    f"Consent acceptance stored ({len(cookies_diff)} new cookies, {len(ls_keys_diff)} new localStorage items)",
                    {
                        "new_cookies": [c['name'] for c in cookies_diff],
                        "new_localStorage_keys": list(ls_keys_diff)
                    }
                )
                return True
            else:
                # No new cookies but check if consent banner disappeared
                try:
                    if not banner_element.is_displayed():
                        self._add_test_result(
                            "consent_acceptance", 
                            "PASS",
                            "Consent banner disappeared after acceptance"
                        )
                        return True
                except:
                    pass
                    
                self._add_test_result(
                    "consent_acceptance", 
                    "FAIL",
                    "No evidence of consent being stored after acceptance"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "consent_acceptance", 
                "ERROR",
                f"Error validating consent acceptance: {str(e)}"
            )
            return False
    
    def validate_consent_persistence(self):
        """Test if consent settings persist across page reloads."""
        try:
            # Reload the page
            self.driver.get(self.target_url)
            
            # Wait for the page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            time.sleep(2)  # Give JavaScript a moment to potentially show a banner
            
            # Check for banner again using the same selectors
            banner_selectors = [
                ".gdpr-consent-banner", 
                ".cookie-banner", 
                ".cookie-notice", 
                ".consent-banner",
                "#gdpr-cookie-consent",
                "[data-role='gdpr-banner']"
            ]
            
            banner_visible = False
            
            for selector in banner_selectors:
                try:
                    element = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if element.is_displayed():
                        banner_visible = True
                        break
                except:
                    continue
            
            if not banner_visible:
                self._add_test_result(
                    "consent_persistence", 
                    "PASS",
                    "Consent settings persisted after page reload"
                )
                return True
            else:
                self._add_test_result(
                    "consent_persistence", 
                    "FAIL",
                    "Consent banner reappeared after page reload"
                )
                return False
                
        except Exception as e:
            self._add_test_result(
                "consent_persistence", 
                "ERROR",
                f"Error checking consent persistence: {str(e)}"
            )
            return False
    
    def validate_consent_revocation(self):
        """Test if consent can be revoked."""
        try:
            # Look for privacy policy or cookie settings link
            privacy_links = self.driver.find_elements(By.XPATH, 
                "//a[contains(text(), 'Privacy') or contains(text(), 'Cookie') or contains(@href, 'privacy') or contains(@href, 'cookie')]")
            
            if not privacy_links:
                self._add_test_result(
                    "consent_revocation", 
                    "SKIP",
                    "Could not find privacy policy or cookie settings link"
                )
                return False
            
            # Click the first relevant link
            for link in privacy_links:
                if link.is_displayed():
                    link.click()
                    time.sleep(2)
                    break
            
            # Look for revocation UI elements
            revoke_elements = self.driver.find_elements(By.XPATH, 
                "//*[contains(text(), 'Revoke') or contains(text(), 'Withdraw') or contains(text(), 'Delete cookies') or contains(text(), 'Reset')]")
            
            if not revoke_elements:
                # Try looking for a "Cookie Settings" button
                settings_buttons = self.driver.find_elements(By.XPATH, 
                    "//*[contains(text(), 'Cookie Settings') or contains(text(), 'Privacy Settings')]")
                
                if settings_buttons:
                    for button in settings_buttons:
                        if button.is_displayed():
                            button.click()
                            time.sleep(2)
                            
                            # Look again for revocation elements
                            revoke_elements = self.driver.find_elements(By.XPATH, 
                                "//*[contains(text(), 'Revoke') or contains(text(), 'Withdraw') or contains(text(), 'Delete cookies') or contains(text(), 'Reset')]")
                            break
            
            if revoke_elements:
                for elem in revoke_elements:
                    if elem.is_displayed() and elem.is_enabled():
                        initial_cookies = self.driver.get_cookies()
                        initial_local_storage = self._get_local_storage()
                        
                        elem.click()
                        time.sleep(2)
                        
                        # Check if cookies were deleted
                        new_cookies = self.driver.get_cookies()
                        new_local_storage = self._get_local_storage()
                        
                        if len(new_cookies) < len(initial_cookies) or len(new_local_storage) < len(initial_local_storage):
                            self._add_test_result(
                                "consent_revocation", 
                                "PASS",
                                "Successfully revoked consent (cookies/localStorage were removed)"
                            )
                            return True
                        else:
                            # Check if banner reappears after revocation
                            banner_reappeared = False
                            banner_selectors = [
                                ".gdpr-consent-banner", 
                                ".cookie-banner", 
                                ".cookie-notice", 
                                ".consent-banner",
                                "#gdpr-cookie-consent",
                                "[data-role='gdpr-banner']"
                            ]
                            
                            for selector in banner_selectors:
                                try:
                                    element = self.driver.find_element(By.CSS_SELECTOR, selector)
                                    if element.is_displayed():
                                        banner_reappeared = True
                                        break
                                except:
                                    continue
                            
                            if banner_reappeared:
                                self._add_test_result(
                                    "consent_revocation", 
                                    "PASS",
                                    "Successfully revoked consent (banner reappeared)"
                                )
                                return True
                            
                        self._add_test_result(
                            "consent_revocation", 
                            "FAIL",
                            "Clicked revocation element but no evidence of actual revocation"
                        )
                        return False
            
            self._add_test_result(
                "consent_revocation", 
                "FAIL",
                "Could not find consent revocation mechanism"
            )
            return False
                
        except Exception as e:
            self._add_test_result(
                "consent_revocation", 
                "ERROR",
                f"Error testing consent revocation: {str(e)}"
            )
            return False
    
    def _get_local_storage(self):
        """Helper to get all localStorage items."""
        try:
            return self.driver.execute_script("""
                var items = {};
                for (var i = 0, len = localStorage.length; i < len; ++i) {
                    var key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            """)
        except:
            return {}
    
    def run_all_tests(self):
        """Run all consent validation tests."""
        try:
            banner = self.validate_consent_banner_presence()
            self.validate_granular_consent_options(banner)
            self.validate_consent_acceptance(banner)
            self.validate_consent_persistence()
            self.validate_consent_revocation()
            
            # Calculate overall result
            test_results = [test["status"] for test in self.results["tests"]]
            
            if "ERROR" in test_results:
                self.results["overall_result"] = "ERROR"
            elif "FAIL" in test_results:
                self.results["overall_result"] = "FAIL"
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
        passed = sum(1 for test in self.results["tests"] if test["status"] == "PASS")
        failed = sum(1 for test in self.results["tests"] if test["status"] == "FAIL")
        errors = sum(1 for test in self.results["tests"] if test["status"] == "ERROR")
        skipped = sum(1 for test in self.results["tests"] if test["status"] == "SKIP")
        
        print("\n" + "="*60)
        print(f"GDPR CONSENT VALIDATION REPORT: {self.target_url}")
        print("="*60)
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Overall Result: {self.results['overall_result']}")
        print(f"Tests: {len(self.results['tests'])} total, {passed} passed, {failed} failed, {errors} errors, {skipped} skipped")
        print("-"*60)
        
        for test in self.results["tests"]:
            status_display = {
                "PASS": "✅ PASS",
                "FAIL": "❌ FAIL",
                "ERROR": "⚠️ ERROR",
                "SKIP": "⏭️ SKIP"
            }
            print(f"{status_display[test['status']]}: {test['name']} - {test['message']}")
            
        print("="*60)
        
        return self.results


def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description='GDPR Consent Validation Script')
    parser.add_argument('url', help='Target URL to validate')
    parser.add_argument('--output', '-o', help='Output file for JSON report')
    parser.add_argument('--visible', '-v', action='store_true', help='Run in visible mode (not headless)')
    
    args = parser.parse_args()
    
    validator = ConsentValidator(args.url, headless=not args.visible)
    validator.run_all_tests()
    validator.generate_report(args.output)


if __name__ == "__main__":
    main()
