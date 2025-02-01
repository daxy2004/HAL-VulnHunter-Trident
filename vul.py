import requests
from bs4 import BeautifulSoup
import urllib.parse
import logging
import argparse
from typing import List, Dict, Set, Optional
import re
import time
from dataclasses import dataclass
from datetime import datetime
import json
import hashlib
import ssl
import socket
import os
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException
import yaml

@dataclass
class VulnerabilityReport:
    vulnerability_type: str
    url: str
    parameter: str
    severity: str
    description: str
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    proof_of_concept: Optional[str] = None

class SecurityHeaders:
    REQUIRED_HEADERS = {
        'Strict-Transport-Security': 'Ensures secure HTTPS connections',
        'X-Frame-Options': 'Prevents clickjacking attacks',
        'X-Content-Type-Options': 'Prevents MIME-type sniffing',
        'Content-Security-Policy': 'Controls resource loading',
        'X-XSS-Protection': 'Provides XSS filtering',
        'Referrer-Policy': 'Controls referrer information',
        'Permissions-Policy': 'Controls browser features'
    }

    @staticmethod
    def analyze_headers(headers: Dict) -> List[Dict]:
        missing_headers = []
        for header, description in SecurityHeaders.REQUIRED_HEADERS.items():
            if header not in headers:
                missing_headers.append({
                    'header': header,
                    'description': description,
                    'recommendation': f'Add the {header} header with appropriate values'
                })
        return missing_headers

class WebScanner:
    def __init__(self, base_url: str, max_pages: int = 10, threads: int = 5):
        self.base_url = base_url
        self.max_pages = max_pages
        self.threads = threads
        self.visited_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.vulnerabilities: List[VulnerabilityReport] = []
        self.session = requests.Session()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=f'scanner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        )
        self.logger = logging.getLogger(__name__)
        
        # Load vulnerability patterns
        self.load_vulnerability_patterns()
        
        # Safety checks
        if not self._is_authorized_domain():
            raise ValueError("Unauthorized domain. Please ensure you have permission to test this site.")

    def _is_authorized_domain(self) -> bool:
        """Check if the domain is authorized for testing."""
        restricted_domains = {
            'gov', 'mil', 'edu', 'bank', 'healthcare',
            'medical', 'emergency', 'police', 'hospital'
        }
        
        parsed_url = urllib.parse.urlparse(self.base_url)
        domain_parts = parsed_url.netloc.lower().split('.')
        
        return not any(part in restricted_domains for part in domain_parts)

    def _is_valid_url(self, url: str, base_url: str) -> bool:
        """
        Check if a URL is valid and within scope for crawling.
        """
        try:
            # Handle relative URLs
            absolute_url = urllib.parse.urljoin(base_url, url)
            parsed_url = urllib.parse.urlparse(absolute_url)
            base_parsed = urllib.parse.urlparse(self.base_url)
            
            # Check if URL is valid and in scope
            return all([
                # Has a valid scheme
                parsed_url.scheme in ['http', 'https'],
                # Is part of the same domain
                parsed_url.netloc == base_parsed.netloc,
                # Not a fragment or javascript link
                not url.startswith(('#', 'javascript:', 'mailto:', 'tel:')),
                # Not a file download
                not any(parsed_url.path.lower().endswith(ext) 
                       for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar'])
            ])
            
        except Exception as e:
            self.logger.debug(f"URL validation error for {url}: {str(e)}")
            return False

    def load_vulnerability_patterns(self):
        """Load vulnerability patterns from YAML configuration."""
        try:
            with open('vulnerability_patterns.yaml', 'r') as f:
                self.patterns = yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.warning("vulnerability_patterns.yaml not found, creating default patterns")
            create_config_file()
            with open('vulnerability_patterns.yaml', 'r') as f:
                self.patterns = yaml.safe_load(f)

    def crawl(self):
        """Crawl the website to discover pages and forms."""
        self.logger.info(f"Starting crawl of {self.base_url}")
        
        try:
            response = self.session.get(self.base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            self._process_page(soup, self.base_url)
            self.logger.info(f"Completed crawling. Found {len(self.visited_urls)} pages and {len(self.forms)} forms")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error crawling {self.base_url}: {str(e)}")

    def _process_page(self, soup: BeautifulSoup, current_url: str):
        """Process a single page for links and forms."""
        # Extract and store forms
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': [(input_field.get('name', ''), input_field.get('type', ''))
                          for input_field in form.find_all('input')]
            }
            self.forms.append(form_data)

        # Extract and follow links
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and self._is_valid_url(href, current_url):
                absolute_url = urllib.parse.urljoin(current_url, href)
                if absolute_url not in self.visited_urls and len(self.visited_urls) < self.max_pages:
                    self.visited_urls.add(absolute_url)
                    try:
                        response = self.session.get(absolute_url, timeout=10)
                        new_soup = BeautifulSoup(response.text, 'html.parser')
                        self._process_page(new_soup, absolute_url)
                    except requests.exceptions.RequestException:
                        continue

    def test_xss(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        self.logger.info("Starting XSS vulnerability tests")
        xss_payloads = self.patterns.get('xss_payloads', [
            '<script>alert("xss_test")</script>',
            '"><img src=x onerror=alert("xss_test")>',
            "'-alert(1)-'",
            '<svg/onload=alert("xss_test")>'
        ])
        
        for form in self.forms:
            for input_name, input_type in form['inputs']:
                if input_type not in ['hidden', 'submit', 'button']:
                    for payload in xss_payloads:
                        try:
                            data = {input_name: payload}
                            url = urllib.parse.urljoin(self.base_url, form['action'])
                            
                            if form['method'] == 'post':
                                response = self.session.post(url, data=data, timeout=10)
                            else:
                                response = self.session.get(url, params=data, timeout=10)
                                
                            if payload in response.text:
                                self.vulnerabilities.append(
                                    VulnerabilityReport(
                                        vulnerability_type="XSS",
                                        url=url,
                                        parameter=input_name,
                                        severity="High",
                                        description=f"Reflected XSS found in {input_name} parameter",
                                        recommendation="Implement proper input validation and output encoding",
                                        cwe_id="CWE-79",
                                        cvss_score=6.5,
                                        proof_of_concept=payload
                                    )
                                )
                        except RequestException as e:
                            self.logger.error(f"Error testing XSS on {url}: {str(e)}")
                            continue

    def test_sql_injection(self):
        """Test for SQL Injection vulnerabilities."""
        self.logger.info("Starting SQL Injection tests")
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "admin' --"
        ]
        
        sql_errors = [
            'SQL syntax.*MySQL',
            'Warning.*mysql_.*',
            'PostgreSQL.*ERROR',
            'SQLite/JDBCDriver',
            'Oracle.*ORA-[0-9][0-9][0-9][0-9]'
        ]
        
        for form in self.forms:
            for input_name, input_type in form['inputs']:
                if input_type not in ['hidden', 'submit', 'button']:
                    for payload in sql_payloads:
                        try:
                            data = {input_name: payload}
                            url = urllib.parse.urljoin(self.base_url, form['action'])
                            
                            if form['method'] == 'post':
                                response = self.session.post(url, data=data, timeout=10)
                            else:
                                response = self.session.get(url, params=data, timeout=10)
                            
                            if any(re.search(error, response.text, re.IGNORECASE) for error in sql_errors):
                                self.vulnerabilities.append(
                                    VulnerabilityReport(
                                        vulnerability_type="SQL Injection",
                                        url=url,
                                        parameter=input_name,
                                        severity="Critical",
                                        description=f"Potential SQL injection found in {input_name} parameter",
                                        recommendation="Use prepared statements and input validation",
                                        cwe_id="CWE-89",
                                        cvss_score=9.0,
                                        proof_of_concept=payload
                                    )
                                )
                        except RequestException as e:
                            self.logger.error(f"Error testing SQL injection on {url}: {str(e)}")
                            continue

    def check_security_headers(self):
        """Check for missing or misconfigured security headers."""
        self.logger.info("Checking security headers")
        try:
            response = self.session.get(self.base_url)
            missing_headers = SecurityHeaders.analyze_headers(response.headers)
            
            for missing in missing_headers:
                self.vulnerabilities.append(
                    VulnerabilityReport(
                        vulnerability_type="Missing Security Header",
                        url=self.base_url,
                        parameter=missing['header'],
                        severity="Medium",
                        description=f"Missing {missing['header']} header: {missing['description']}",
                        recommendation=missing['recommendation'],
                        cwe_id="CWE-693",
                        cvss_score=5.0
                    )
                )
        except RequestException as e:
            self.logger.error(f"Error checking security headers: {str(e)}")

    def scan(self):
        """Perform a complete security scan."""
        self.logger.info(f"Starting security scan of {self.base_url}")
        
        try:
            # Crawl the website
            self.crawl()
            
            # Run security tests
            tests = [
                self.test_xss,
                self.test_sql_injection,
                self.check_security_headers
            ]
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                list(executor.map(lambda test: test(), tests))
            
            # Generate report
            self.generate_report()
            
            self.logger.info("Scan completed successfully")
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}", exc_info=True)
            raise

    def generate_report(self):
        """Generate a detailed security report."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f'security_report_{timestamp}.txt'
        
        report = f"""
Web Vulnerability Scan Report
============================
Target: {self.base_url}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Pages Scanned: {len(self.visited_urls)}
Forms Analyzed: {len(self.forms)}

Summary
-------
Total Vulnerabilities Found: {len(self.vulnerabilities)}

Vulnerability Breakdown:
- Critical: {sum(1 for v in self.vulnerabilities if v.severity == 'Critical')}
- High: {sum(1 for v in self.vulnerabilities if v.severity == 'High')}
- Medium: {sum(1 for v in self.vulnerabilities if v.severity == 'Medium')}
- Low: {sum(1 for v in self.vulnerabilities if v.severity == 'Low')}

Detailed Findings
----------------
"""
        
        # Sort vulnerabilities by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x.severity, 4))
        
        for vuln in sorted_vulns:
            report += f"""
[{vuln.severity.upper()}] {vuln.vulnerability_type}
URL: {vuln.url}
Parameter: {vuln.parameter}
CWE ID: {vuln.cwe_id or 'N/A'}
CVSS Score: {vuln.cvss_score or 'N/A'}
Description: {vuln.description}
Recommendation: {vuln.recommendation}
Proof of Concept: {vuln.proof_of_concept or 'N/A'}
----------------------------------------
"""
        
        with open(report_filename, 'w') as f:
            f.write(report)
            
        self.logger.info(f"Report saved as {report_filename}")
        print(f"\nScan completed. Report saved as {report_filename}")

def create_config_file():
    """Create a default vulnerability patterns configuration file."""
    default_patterns = {
        'xss_payloads': [
            '<script>alert("xss")</script>',
            '"><img src=x onerror=alert("xss")>',
            "'-alert(1)-'",
            '<svg/onload=alert("xss")>'
        ],
        'sql_injection_payloads': [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "admin' --"
        ]
    }
    
    with open('vulnerability_patterns.yaml', 'w') as f:
        yaml.dump(default_patterns, f)

def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--max-pages', type=int, default=10, help='Maximum number of pages to scan')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
    args = parser.parse_args()
    
    try:
        scanner = WebScanner(args.url, args.max_pages, args.threads)
        scanner.scan()
        print(f"\nScan completed successfully. Check the generated report file.")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        logging.error(f"Scan failed: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()