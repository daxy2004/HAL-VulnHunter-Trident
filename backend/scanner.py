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
import dns.resolver
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

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

@dataclass
class SubdomainInfo:
    subdomain: str
    ip_address: Optional[str]
    status: str
    server: Optional[str]

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

# ... [previous imports remain the same]

class WebScanner:
    def __init__(self, base_url: str, max_pages: int = 10, threads: int = 5):  # FIXED CONSTRUCTOR
        self.base_url = base_url
        self.max_pages = max_pages
        self.threads = threads
        self.visited_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.vulnerabilities: List[VulnerabilityReport] = []
        self.subdomains: List[SubdomainInfo] = []
        self.session = requests.Session()
        
        # Configure logging (console only)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)  # FIXED LOGGER NAME
        
        # Load vulnerability patterns
        self.load_vulnerability_patterns()
        
        # Safety checks
        if not self._is_authorized_domain():
            raise ValueError("Unauthorized domain. Please ensure you have permission to test this site.")

    # ... [rest of the code remains unchanged]

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
        """Check if a URL is valid and within scope for crawling."""
        try:
            absolute_url = urllib.parse.urljoin(base_url, url)
            parsed_url = urllib.parse.urlparse(absolute_url)
            base_parsed = urllib.parse.urlparse(self.base_url)
            
            return all([
                parsed_url.scheme in ['http', 'https'],
                parsed_url.netloc == base_parsed.netloc,
                not url.startswith(('#', 'javascript:', 'mailto:', 'tel:')),
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
            self.create_config_file()
            with open('vulnerability_patterns.yaml', 'r') as f:
                self.patterns = yaml.safe_load(f)

    def create_config_file(self):
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
            ],
            'subdomain_wordlist': [
                'www', 'mail', 'remote', 'blog', 'webmail', 'server',
                'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
                'staging', 'test', 'admin', 'portal', 'cdn'
            ]
        }
        
        with open('vulnerability_patterns.yaml', 'w') as f:
            yaml.dump(default_patterns, f)

    def discover_subdomains(self):
        """Discover subdomains of the target domain using a wordlist."""
        self.logger.info("Starting subdomain discovery")
        subdomain_wordlist = self.patterns.get('subdomain_wordlist', [])
        parsed_url = urllib.parse.urlparse(self.base_url)
        domain = parsed_url.netloc

        if domain.startswith('www.'):
            domain = domain[4:]

        for subdomain in subdomain_wordlist:
            full_subdomain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_subdomain, 'A')
                ip_address = answers[0].address if answers else None

                try:
                    response = self.session.get(f"http://{full_subdomain}", timeout=5)
                    status = "Live"
                    server = response.headers.get('Server', 'Unknown')
                except RequestException:
                    status = "Unreachable"
                    server = None

                self.subdomains.append(
                    SubdomainInfo(
                        subdomain=full_subdomain,
                        ip_address=ip_address,
                        status=status,
                        server=server
                    )
                )
                self.logger.info(f"Discovered subdomain: {full_subdomain} ({status})")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                self.logger.debug(f"Subdomain not found: {full_subdomain}")
                continue

    def generate_pdf_report(self):
        """Generate a PDF report of vulnerabilities and subdomains with detailed recommendations."""
        self.logger.info("Generating PDF report")
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        title_style = ParagraphStyle(
            name='Title',
            parent=styles['Heading1'],
            alignment=1,
            fontSize=18,
            spaceAfter=12
        )
        title = Paragraph("Web Security Scan Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.25 * inch))

        # Summary Section
        summary_style = ParagraphStyle(
            name='Summary',
            parent=styles['BodyText'],
            fontSize=12,
            spaceAfter=12
        )
        summary_text = f"""
        This report summarizes the findings of the security scan conducted on {self.base_url}.
        The scan included vulnerability testing, subdomain discovery, and security header analysis.
        Below are the detailed results and recommendations.
        """
        elements.append(Paragraph(summary_text, summary_style))
        elements.append(Spacer(1, 0.5 * inch))

        # Vulnerabilities Section
        if self.vulnerabilities:
            vuln_style = ParagraphStyle(
                name='VulnHeader',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=6
            )
            elements.append(Paragraph("Vulnerabilities Found", vuln_style))
            
            vuln_data = [["Type", "URL", "Parameter", "Severity", "CVSS", "CWE"]]
            for vuln in self.vulnerabilities:
                vuln_data.append([
                    vuln.vulnerability_type,
                    vuln.url,
                    vuln.parameter,
                    vuln.severity,
                    str(vuln.cvss_score) if vuln.cvss_score else "N/A",
                    vuln.cwe_id if vuln.cwe_id else "N/A"
                ])
            
            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 10),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('BACKGROUND', (0,1), (-1,-1), colors.beige),
                ('GRID', (0,0), (-1,-1), 1, colors.black)
            ]))
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.5 * inch))

            # Recommendations for Vulnerabilities
            recommendations_style = ParagraphStyle(
                name='Recommendations',
                parent=styles['BodyText'],
                fontSize=12,
                spaceAfter=6
            )
            elements.append(Paragraph("Recommendations for Vulnerabilities", vuln_style))
            
            for vuln in self.vulnerabilities:
                recommendation_text = f"""
                <b>Vulnerability:</b> {vuln.vulnerability_type}<br/>
                <b>Description:</b> {vuln.description}<br/>
                <b>Recommendation:</b> {vuln.recommendation}<br/>
                <b>Proof of Concept:</b> {vuln.proof_of_concept if vuln.proof_of_concept else "N/A"}<br/>
                """
                elements.append(Paragraph(recommendation_text, recommendations_style))
                elements.append(Spacer(1, 0.25 * inch))

        # General Recommendations
        general_recommendations_style = ParagraphStyle(
            name='GeneralRecommendations',
            parent=styles['BodyText'],
            fontSize=12,
            spaceAfter=6
        )
        elements.append(Paragraph("General Security Recommendations", vuln_style))
        
        general_recommendation_text = """
        <b>General Recommendations:</b><br/>
        1. Implement all missing security headers.<br/>
        2. Conduct regular security header audits.<br/>
        3. Use HTTPS across all pages and subdomains.<br/>
        4. Maintain a minimal attack surface by disabling unused features.<br/>
        5. Monitor security headers using tools like SecurityHeaders.com.<br/>
        """
        elements.append(Paragraph(general_recommendation_text, general_recommendations_style))
        elements.append(Spacer(1, 0.25 * inch))

        # Build the PDF
        doc.build(elements)
        self.logger.info(f"PDF report saved as {filename}")

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
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': [(input_field.get('name', ''), input_field.get('type', ''))
                          for input_field in form.find_all('input')]
            }
            self.forms.append(form_data)

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
        xss_payloads = self.patterns.get('xss_payloads', [])
        
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

    def test_sql_injection(self):
        """Test for SQL Injection vulnerabilities."""
        self.logger.info("Starting SQL Injection tests")
        sql_payloads = self.patterns.get('sql_injection_payloads', [])
        sql_errors = [
            'SQL syntax.*MySQL',
            'Warning.mysql_.',
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
            self.discover_subdomains()
            self.crawl()
            
            tests = [
                self.test_xss,
                self.test_sql_injection,
                self.check_security_headers
            ]
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                list(executor.map(lambda test: test(), tests))
            
            self.generate_pdf_report()
            self.logger.info("Scan completed successfully")
            print("\nScan completed successfully! Check the generated PDF report.")
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}", exc_info=True)
            raise

def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--max-pages', type=int, default=10, help='Maximum number of pages to scan')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads')
    args = parser.parse_args()
    
    try:
        scanner = WebScanner(args.url, args.max_pages, args.threads)
        scanner.scan()
    except Exception as e:
        print(f"Error: {str(e)}")
        logging.error(f"Scan failed: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()