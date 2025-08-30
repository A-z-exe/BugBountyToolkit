import os
import subprocess
import sys
import time
import argparse
import json
import datetime
import requests
import shlex
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

class BugBountyTool:
    def __init__(self):
        self.target = None
        self.output_dir = None
        self.scan_results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBountyTool/1.0 (Security Research)'
        })
        
    def banner(self):
         print("""
    
            ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
            ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
            ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
            ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
            ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
            ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   
                                                                                        
      
                         ████████╗ ██████╗  ██████╗ ██╗     
                         ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
                            ██║   ██║   ██║██║   ██║██║     
                            ██║   ██║   ██║██║   ██║██║     
                            ██║   ╚██████╔╝╚██████╔╝███████╗
                            ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                                                            
                    ╔═══════════════╗   ╔══════════════════════════════╗
                    ║ A-z-exe       ║   ║     Advanced Bug Scanner     ║
                    ╚═══════════════╝   ╚══════════════════════════════╝
                                
                🌐 Github:  github.com/a-z-exe
                📱 Telegram: t.me/A_Z_exe
                📷 Instagram: instagram.com/A_Z_exe
            """)

    def validate_target(self, target):
        """Validate and sanitize target input"""
        if not target:
            return None
            
        # Remove dangerous characters
        sanitized = re.sub(r'[;&|`$()]', '', target)
        
        # Validate domain format
        if not sanitized.startswith(('http://', 'https://')):
            sanitized = f"https://{sanitized}"
            
        try:
            parsed = urlparse(sanitized)
            if not parsed.netloc:
                return None
            return sanitized
        except:
            return None

    def setup(self):
        """Setup output directory and initial configuration"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.target:
            target_name = self.target.replace("https://", "").replace("http://", "").replace("/", "_").split(":")[0]
            # Sanitize filename
            target_name = re.sub(r'[^\w\-_\.]', '_', target_name)
            self.output_dir = Path(f"results_{target_name}_{timestamp}")
        else:
            self.output_dir = Path(f"results_{timestamp}")
            
        self.output_dir.mkdir(parents=True, exist_ok=True)
        print(f"[+] Output directory created: {self.output_dir}")

    def execute_command_safe(self, command_list, output_file=None, timeout=30):
        """Execute command safely without shell injection"""
        try:
            if isinstance(command_list, str):
                # Split string command safely
                command_list = shlex.split(command_list)
                
            print(f"[*] Executing: {' '.join(command_list)}")
            
            if output_file:
                output_path = self.output_dir / output_file
                with open(output_path, 'w') as f:
                    process = subprocess.run(
                        command_list, 
                        stdout=f,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=timeout
                    )
                if process.returncode != 0:
                    print(f"[!] Error executing command: {process.stderr}")
                else:
                    print(f"[+] Output saved to {output_path}")
                return str(output_path)
            else:
                process = subprocess.run(
                    command_list, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout
                )
                if process.returncode != 0:
                    print(f"[!] Error executing command: {process.stderr}")
                    return None
                return process.stdout
                
        except subprocess.TimeoutExpired:
            print(f"[!] Command timed out after {timeout} seconds")
            return None
        except Exception as e:
            print(f"[!] Exception executing command: {str(e)}")
            return None

    def check_tool_installed(self, tool):
        """Check if a tool is installed"""
        try:
            subprocess.run(["which", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def check_requirements(self):
        """Check if required tools are installed"""
        tools = {
            "whois": "Domain information lookup",
            "dig": "DNS lookup utility", 
            "subfinder": "Subdomain discovery tool",
            "nmap": "Network mapper",
            "nikto": "Web vulnerability scanner",
            "sqlmap": "SQL injection tool",
            "wfuzz": "Web fuzzer",
            "curl": "HTTP client",
            "openssl": "SSL/TLS toolkit"
        }
        
        missing_tools = []
        installed_tools = []
        
        for tool, description in tools.items():
            if self.check_tool_installed(tool):
                installed_tools.append(tool)
                print(f"[+] {tool} is installed - {description}")
            else:
                missing_tools.append(tool)
                print(f"[!] {tool} is missing - {description}")
        
        if missing_tools:
            print(f"\n[!] Missing tools: {', '.join(missing_tools)}")
            print("[*] Installation suggestions:")
            print("  Ubuntu/Debian: sudo apt-get install whois dnsutils nmap nikto curl openssl")
            print("  For subfinder: https://github.com/projectdiscovery/subfinder")
            print("  For sqlmap: https://github.com/sqlmapproject/sqlmap")
            print("  For wfuzz: pip install wfuzz")
            return False
        
        print(f"\n[+] All required tools are installed!")
        return True

    def safe_request(self, url, method="GET", timeout=10, **kwargs):
        """Make HTTP request safely with error handling"""
        try:
            response = self.session.request(method, url, timeout=timeout, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"[!] Request error for {url}: {str(e)}")
            return None

    def info_gathering(self):
        """Gather target information"""
        print("\n[+] Gathering information...")
        
        if not self.target:
            target_input = input("Enter the target domain: ")
            self.target = self.validate_target(target_input)
            if not self.target:
                print("[!] Invalid target format")
                return
        
        domain = urlparse(self.target).netloc or self.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        self.scan_results["info_gathering"] = {}
        
        print("[*] Getting domain information...")
        whois_output = self.execute_command_safe(["whois", domain], "whois_output.txt")
        self.scan_results["info_gathering"]["whois"] = whois_output
        
        print("[*] Getting DNS information...")
        dig_output = self.execute_command_safe(["dig", "+short", domain], "dig_output.txt")
        self.scan_results["info_gathering"]["dig"] = dig_output
        
        if self.check_tool_installed("subfinder"):
            print("[*] Discovering subdomains...")
            subfinder_output = self.execute_command_safe(["subfinder", "-d", domain, "-silent"], "subfinder_output.txt")
            self.scan_results["info_gathering"]["subdomains"] = subfinder_output
        else:
            print("[!] Subfinder not installed, skipping subdomain discovery")
        
        # Get SSL information
        print("[*] Checking SSL certificate...")
        ssl_cmd = f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -text"
        ssl_info = self.execute_command_safe(shlex.split(ssl_cmd), "ssl_info.txt")
        self.scan_results["info_gathering"]["ssl_info"] = ssl_info
        
        # Get robots.txt safely
        print("[*] Retrieving robots.txt...")
        robots_url = urljoin(self.target, "/robots.txt")
        response = self.safe_request(robots_url)
        
        if response and response.status_code == 200:
            robots_path = self.output_dir / "robots.txt"
            with open(robots_path, 'w') as f:
                f.write(response.text)
            self.scan_results["info_gathering"]["robots_txt"] = str(robots_path)
            print(f"[+] Retrieved robots.txt and saved to {robots_path}")
        else:
            print("[!] Could not retrieve robots.txt")
        
        print("[+] Information gathering completed")

    def vulnerability_scan(self):
        """Scan for vulnerabilities"""
        print("\n[+] Scanning for vulnerabilities...")
        
        if not self.target:
            target_input = input("Enter the target URL: ")
            self.target = self.validate_target(target_input)
            if not self.target:
                print("[!] Invalid target format")
                return
            
        self.scan_results["vulnerability_scan"] = {}
        
        domain = urlparse(self.target).netloc
        
        # Run port scan with limited scope
        if self.check_tool_installed("nmap"):
            print("[*] Running limited port scan...")
            nmap_output = self.execute_command_safe([
                "nmap", "-sV", "-T4", "--top-ports", "100", domain
            ], "nmap_output.txt", timeout=300)
            self.scan_results["vulnerability_scan"]["nmap"] = nmap_output
        else:
            print("[!] Nmap not installed, skipping port scan")
        
        # Run web vulnerability scan
        if self.check_tool_installed("nikto"):
            print("[*] Running web vulnerability scan...")
            nikto_output = self.execute_command_safe([
                "nikto", "-h", self.target, "-nointeractive"
            ], "nikto_output.txt", timeout=600)
            self.scan_results["vulnerability_scan"]["nikto"] = nikto_output
        else:
            print("[!] Nikto not installed, skipping web vulnerability scan")
        
        # Check for common misconfigurations
        print("[*] Checking for common web misconfigurations...")
        self.check_misconfigurations()
        
        print("[+] Vulnerability scanning completed")

    def check_misconfigurations(self):
        """Check for common misconfigurations safely"""
        common_paths = [
            "admin", "backup", "config", "db", "debug", "old", "test", 
            ".git", ".env", ".htaccess", "wp-admin", "phpmyadmin"
        ]
        misconfig_results = {}
        
        base_url = self.target.rstrip('/')
        
        for path in common_paths:
            try:
                url = f"{base_url}/{path}"
                response = self.safe_request(url, timeout=5)
                
                if response and response.status_code not in [404, 403]:
                    misconfig_results[path] = {
                        "url": url,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "headers": dict(response.headers)
                    }
                    print(f"[!] Found potentially interesting path: {url} (Status: {response.status_code})")
                    
            except Exception as e:
                print(f"[!] Error checking {path}: {str(e)}")
                
        misconfig_path = self.output_dir / "misconfiguration_checks.json"
        with open(misconfig_path, 'w') as f:
            json.dump(misconfig_results, f, indent=2)
            
        self.scan_results["vulnerability_scan"]["misconfigurations"] = str(misconfig_path)

    def attack_tests(self):
        """Test for common attacks with safety measures"""
        print("\n[+] Testing for common attacks...")
        
        if not self.target:
            target_input = input("Enter the target URL: ")
            self.target = self.validate_target(target_input)
            if not self.target:
                print("[!] Invalid target format")
                return
            
        self.scan_results["attack_tests"] = {}
        
        # SQL injection test with proper parameters
        if self.check_tool_installed("sqlmap"):
            print("[*] Testing for SQL injection (safe mode)...")
            print("[!] Note: Only performing safe, non-invasive tests")
            sqlmap_output = self.execute_command_safe([
                "sqlmap", "-u", self.target, "--batch", "--level=2", "--risk=1", 
                "--no-cast", "--threads=1", "--timeout=10"
            ], "sqlmap_output.txt", timeout=300)
            self.scan_results["attack_tests"]["sqlmap"] = sqlmap_output
        else:
            print("[!] SQLMap not installed, skipping SQL injection tests")
        
        # Directory and file bruteforce with wfuzz
        if self.check_tool_installed("wfuzz"):
            print("[*] Fuzzing for hidden directories and files...")
            # Use a smaller, safer wordlist
            wfuzz_output = self.execute_command_safe([
                "wfuzz", "-c", "-z", "file,/usr/share/wfuzz/wordlist/general/common.txt",
                "--hc", "404", "-t", "10", f"{self.target}/FUZZ"
            ], "wfuzz_output.txt", timeout=300)
            self.scan_results["attack_tests"]["wfuzz"] = wfuzz_output
        else:
            print("[!] Wfuzz not installed, skipping directory fuzzing")
        
        # XSS test payloads (for manual testing only)
        print("[*] Preparing XSS test payloads...")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        xss_path = self.output_dir / "xss_payloads.txt"
        with open(xss_path, 'w') as f:
            f.write("XSS Test Payloads (For Manual Testing Only)\n")
            f.write("=" * 50 + "\n\n")
            f.write("IMPORTANT: Only test these on applications you own or have explicit permission to test!\n\n")
            for i, payload in enumerate(xss_payloads, 1):
                f.write(f"{i}. {payload}\n")
        
        self.scan_results["attack_tests"]["xss_payloads"] = str(xss_path)
        print(f"[+] XSS payloads saved to {xss_path} for manual testing")
        
        print("[+] Attack testing completed")

    def api_mobile_security(self):
        """Review API and mobile security"""
        print("\n[+] Reviewing API and mobile security...")
        
        if not self.target:
            target_input = input("Enter the API URL: ")
            self.target = self.validate_target(target_input)
            if not self.target:
                print("[!] Invalid target format")
                return
            
        self.scan_results["api_security"] = {}
        
        # Check HTTP headers
        print("[*] Analyzing HTTP headers...")
        response = self.safe_request(self.target)
        
        if response:
            headers_analysis = self.analyze_security_headers(response.headers)
            headers_path = self.output_dir / "headers_analysis.json"
            with open(headers_path, 'w') as f:
                json.dump(headers_analysis, f, indent=2)
            self.scan_results["api_security"]["headers"] = str(headers_path)
            print(f"[+] Headers analysis saved to {headers_path}")
        
        # Check for CORS misconfiguration
        print("[*] Testing CORS configuration...")
        cors_results = self.test_cors()
        cors_path = self.output_dir / "cors_analysis.json"
        with open(cors_path, 'w') as f:
            json.dump(cors_results, f, indent=2)
        self.scan_results["api_security"]["cors"] = str(cors_path)
        
        # JWT token analysis instructions
        print("[*] Setting up JWT analysis instructions...")
        jwt_path = self.output_dir / "jwt_analysis.md"
        with open(jwt_path, 'w') as f:
            f.write("# JWT Analysis Instructions\n\n")
            f.write("## Manual Steps Required:\n\n")
            f.write("1. **Capture JWT Token**: Use browser dev tools or Burp Suite\n")
            f.write("2. **Decode Token**: Visit jwt.io or use jwt_tool\n")
            f.write("3. **Check for Vulnerabilities**:\n")
            f.write("   - Weak signature algorithms (none, HS256 with public key)\n")
            f.write("   - Exposed secrets in payload\n")
            f.write("   - Long expiration times\n")
            f.write("   - Missing claims validation\n\n")
            f.write("## Commands to Run:\n")
            f.write("```bash\n")
            f.write("# Install jwt_tool if not available\n")
            f.write("pip install pyjwt\n\n")
            f.write("# Analyze token\n")
            f.write("jwt_tool <YOUR_TOKEN_HERE>\n")
            f.write("```\n")
        
        self.scan_results["api_security"]["jwt_analysis"] = str(jwt_path)
        
        # API documentation discovery
        print("[*] Searching for API documentation...")
        self.discover_api_docs()
        
        print("[+] API security review completed")

    def analyze_security_headers(self, headers):
        """Analyze security headers"""
        security_headers = {
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'XSS protection (legacy)',
            'Strict-Transport-Security': 'Forces HTTPS',
            'Content-Security-Policy': 'Prevents various attacks',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features'
        }
        
        analysis = {
            "present_headers": {},
            "missing_headers": [],
            "recommendations": []
        }
        
        for header, description in security_headers.items():
            if header in headers:
                analysis["present_headers"][header] = {
                    "value": headers[header],
                    "description": description
                }
            else:
                analysis["missing_headers"].append({
                    "header": header,
                    "description": description
                })
        
        # Add recommendations
        if analysis["missing_headers"]:
            analysis["recommendations"].append("Implement missing security headers")
        
        return analysis

    def test_cors(self):
        """Test CORS configuration"""
        test_origins = [
            "https://evil.com",
            "null",
            "https://attacker.com"
        ]
        
        cors_results = {}
        
        for origin in test_origins:
            response = self.safe_request(
                self.target,
                headers={"Origin": origin}
            )
            
            if response:
                cors_results[origin] = {
                    "access_control_allow_origin": response.headers.get("Access-Control-Allow-Origin"),
                    "access_control_allow_credentials": response.headers.get("Access-Control-Allow-Credentials"),
                    "status_code": response.status_code
                }
        
        return cors_results

    def discover_api_docs(self):
        """Discover API documentation endpoints"""
        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/docs",
            "/swagger", "/swagger/index.html", "/swagger-ui.html", "/swagger.json",
            "/api-docs", "/docs", "/documentation",
            "/graphql", "/graphiql",
            "/openapi.json", "/openapi.yaml"
        ]
        
        api_docs_results = {}
        base_url = self.target.rstrip('/')
        
        print("[*] Checking for API documentation...")
        
        for path in common_api_paths:
            url = f"{base_url}{path}"
            response = self.safe_request(url)
            
            if response and response.status_code not in [404, 403]:
                api_docs_results[path] = {
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_type": response.headers.get("Content-Type", "")
                }
                print(f"[!] Found potential API docs: {url} (Status: {response.status_code})")
        
        api_docs_path = self.output_dir / "api_docs_discovery.json"
        with open(api_docs_path, 'w') as f:
            json.dump(api_docs_results, f, indent=2)
            
        self.scan_results["api_security"]["api_docs_discovery"] = str(api_docs_path)

    def reporting(self):
        """Generate comprehensive reports from collected data"""
        print("\n[+] Generating reports...")
        
        if not self.output_dir:
            print("[!] No scan data available. Please run scans first.")
            return
            
        # Create detailed summary report
        summary_path = self.output_dir / "SECURITY_REPORT.md"
        print(f"[*] Creating comprehensive security report at {summary_path}")
        
        with open(summary_path, 'w') as f:
            f.write(f"# Security Assessment Report\n\n")
            f.write(f"**Target:** {self.target}\n")
            f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Scan Type:** Automated Security Assessment\n\n")
            
            f.write("## Executive Summary\n\n")
            f.write("This report contains the results of an automated security assessment. ")
            f.write("Manual verification of findings is strongly recommended.\n\n")
            
            f.write("## Methodology\n\n")
            f.write("The assessment included:\n")
            f.write("- Information gathering and reconnaissance\n")
            f.write("- Vulnerability scanning\n")
            f.write("- Configuration analysis\n")
            f.write("- API security review\n\n")
            
            f.write("## Detailed Findings\n\n")
            
            if "info_gathering" in self.scan_results:
                f.write("### Information Gathering Results\n\n")
                for key, file_path in self.scan_results["info_gathering"].items():
                    if file_path:
                        f.write(f"- **{key.replace('_', ' ').title()}**: [View Details]({Path(file_path).name})\n")
                f.write("\n")
            
            if "vulnerability_scan" in self.scan_results:
                f.write("### Vulnerability Scan Results\n\n")
                for key, file_path in self.scan_results["vulnerability_scan"].items():
                    if file_path:
                        f.write(f"- **{key.replace('_', ' ').title()}**: [View Details]({Path(file_path).name})\n")
                f.write("\n")
            
            if "attack_tests" in self.scan_results:
                f.write("### Attack Test Results\n\n")
                for key, file_path in self.scan_results["attack_tests"].items():
                    if file_path:
                        f.write(f"- **{key.replace('_', ' ').title()}**: [View Details]({Path(file_path).name})\n")
                f.write("\n")
            
            if "api_security" in self.scan_results:
                f.write("### API Security Review\n\n")
                for key, file_path in self.scan_results["api_security"].items():
                    if file_path:
                        f.write(f"- **{key.replace('_', ' ').title()}**: [View Details]({Path(file_path).name})\n")
                f.write("\n")
            
            f.write("## Manual Review Required\n\n")
            f.write("| Category | Item | Priority | Notes |\n")
            f.write("|----------|------|----------|-------|\n")
            f.write("| Web Security | Review Nikto findings | High | Check for actual vulnerabilities |\n")
            f.write("| SQL Injection | Verify SQLMap results | Critical | Manual testing recommended |\n")
            f.write("| XSS | Test XSS payloads | High | Manual verification required |\n")
            f.write("| Configuration | Review exposed paths | Medium | Determine if intentional |\n")
            f.write("| Headers | Implement missing headers | Medium | Improve security posture |\n\n")
            
            f.write("## Recommendations\n\n")
            f.write("### Immediate Actions\n")
            f.write("1. **Review Critical Findings**: Prioritize any confirmed vulnerabilities\n")
            f.write("2. **Security Headers**: Implement missing security headers\n")
            f.write("3. **Access Controls**: Verify all exposed endpoints are intentional\n\n")
            
            f.write("### Long-term Improvements\n")
            f.write("1. **Regular Assessments**: Implement periodic security testing\n")
            f.write("2. **Security Training**: Ensure development team is security-aware\n")
            f.write("3. **Monitoring**: Implement security monitoring and logging\n")
            f.write("4. **Incident Response**: Develop security incident response procedures\n\n")
            
            f.write("## Disclaimer\n\n")
            f.write("This automated assessment provides initial security insights. ")
            f.write("Manual verification by security professionals is essential. ")
            f.write("Only test systems you own or have explicit permission to test.\n")
        
        # Generate JSON summary for programmatic use
        json_summary = {
            "target": self.target,
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_results": self.scan_results,
            "tools_used": [tool for tool in ["nmap", "nikto", "sqlmap", "wfuzz", "subfinder"] if self.check_tool_installed(tool)]
        }
        
        json_path = self.output_dir / "scan_summary.json"
        with open(json_path, 'w') as f:
            json.dump(json_summary, f, indent=2)
        
        print(f"[+] Comprehensive security report created: {summary_path}")
        print(f"[+] JSON summary available: {json_path}")
        print("[+] Reporting completed")

    def run_full_scan(self):
        """Run all scan modules sequentially with progress tracking"""
        print("\n[+] Starting comprehensive security scan...")
        
        if not self.target:
            target_input = input("Enter the target URL/domain: ")
            self.target = self.validate_target(target_input)
            if not self.target:
                print("[!] Invalid target format")
                return
        
        print(f"[*] Target: {self.target}")
        
        if not self.check_requirements():
            print("[!] Please install missing requirements before running full scan")
            return
        
        try:
            self.setup()
            
            # Progress tracking
            total_steps = 5
            current_step = 1
            
            print(f"\n[{current_step}/{total_steps}] Information Gathering...")
            self.info_gathering()
            current_step += 1
            
            print(f"\n[{current_step}/{total_steps}] Vulnerability Scanning...")
            self.vulnerability_scan()
            current_step += 1
            
            print(f"\n[{current_step}/{total_steps}] Attack Testing...")
            self.attack_tests()
            current_step += 1
            
            print(f"\n[{current_step}/{total_steps}] API Security Review...")
            self.api_mobile_security()
            current_step += 1
            
            print(f"\n[{current_step}/{total_steps}] Generating Reports...")
            self.reporting()
            
            print("\n" + "="*60)
            print("[+] FULL SECURITY SCAN COMPLETED!")
            print("="*60)
            print(f"📁 Results directory: {self.output_dir}")
            print(f"📋 Main report: {self.output_dir}/SECURITY_REPORT.md")
            print(f"📊 JSON summary: {self.output_dir}/scan_summary.json")
            print("="*60)
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"\n[!] Error during full scan: {str(e)}")

    def interactive_mode(self):
        """Enhanced interactive mode with better UX"""
        while True:
            try:
                self.banner()
                self.menu()
                choice = input("\n🔍 Choose an option: ").strip()
                
                if choice == "1":
                    if not self.output_dir:
                        self.setup()
                    self.info_gathering()
                elif choice == "2":
                    if not self.output_dir:
                        self.setup()
                    self.vulnerability_scan()
                elif choice == "3":
                    if not self.output_dir:
                        self.setup()
                    self.attack_tests()
                elif choice == "4":
                    if not self.output_dir:
                        self.setup()
                    self.api_mobile_security()
                elif choice == "5":
                    self.reporting()
                elif choice == "6":
                    self.run_full_scan()
                elif choice == "7":
                    self.check_requirements()
                elif choice == "8":
                    print("\n[+] Thank you for using Bug Bounty Tool!")
                    print("🔒 Remember: Only test systems you own or have permission to test!")
                    break
                else:
                    print("[!] Invalid option. Please choose 1-8.")
                    continue
                
                input("\n📝 Press Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\n[!] Program interrupted by user. Exiting...")
                break
            except Exception as e:
                print(f"\n[!] An error occurred: {str(e)}")
                input("Press Enter to continue...")

    def menu(self):
        """Display enhanced main menu"""
        print("\n" + "="*60)
        print("🛡️  SECURITY ASSESSMENT MENU")
        print("="*60)
        print("1. 🔍 Information Gathering")
        print("2. 🛡️  Vulnerability Scanning") 
        print("3. ⚔️  Common Attack Testing")
        print("4. 🔌 API & Mobile Security Review")
        print("5. 📊 Generate Reports")
        print("6. 🚀 Run Full Comprehensive Scan")
        print("7. ⚙️  Check Tool Requirements")
        print("8. 🚪 Exit")
        print("="*60)
        print("⚠️  LEGAL WARNING: Only test systems you own or have explicit permission to test!")

def validate_legal_usage():
    """Ensure user understands legal implications"""
    print("\n" + "⚠️ "*20)
    print("LEGAL DISCLAIMER AND USAGE AGREEMENT")
    print("⚠️ "*20)
    print("\nThis tool is designed for:")
    print("✅ Testing your own systems")
    print("✅ Authorized penetration testing") 
    print("✅ Bug bounty programs with proper scope")
    print("✅ Educational purposes in controlled environments")
    print("\n❌ DO NOT USE for:")
    print("❌ Unauthorized testing of third-party systems")
    print("❌ Any illegal activities")
    print("❌ Testing without explicit written permission")
    print("\n🚨 Unauthorized access to computer systems is illegal in most jurisdictions.")
    print("🚨 Users are solely responsible for compliance with applicable laws.")
    
    while True:
        consent = input("\nDo you agree to use this tool only for legal, authorized testing? (yes/no): ").lower().strip()
        if consent in ['yes', 'y']:
            break
        elif consent in ['no', 'n']:
            print("\n[!] Tool usage not authorized. Exiting...")
            sys.exit(1)
        else:
            print("[!] Please answer 'yes' or 'no'")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Bug Bounty Security Assessment Tool",
        epilog="Example: python bugbounty_tool.py -t https://example.com -m full"
    )
    parser.add_argument("-t", "--target", help="Target URL or domain")
    parser.add_argument("-m", "--mode", 
                        choices=["info", "vuln", "attack", "api", "full"], 
                        help="Scan mode: info, vuln, attack, api, or full")
    parser.add_argument("--skip-legal", action="store_true", 
                        help="Skip legal disclaimer (use only if you understand the legal implications)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Command timeout in seconds (default: 30)")
    return parser.parse_args()

def main():
    # Parse arguments
    args = parse_arguments()
    
    # Legal disclaimer
    if not args.skip_legal:
        validate_legal_usage()
    
    # Initialize tool
    tool = BugBountyTool()
    
    if args.target:
        tool.target = tool.validate_target(args.target)
        if not tool.target:
            print("[!] Invalid target format provided")
            sys.exit(1)
        
    # Command line mode
    if args.mode:
        print(f"\n[+] Running in {args.mode} mode...")
        
        if not tool.check_requirements():
            print("[!] Missing required tools. Please install them first.")
            sys.exit(1)
            
        tool.setup()
        
        if args.mode == "info":
            tool.info_gathering()
        elif args.mode == "vuln":
            tool.vulnerability_scan()
        elif args.mode == "attack":
            tool.attack_tests()
        elif args.mode == "api":
            tool.api_mobile_security()
        elif args.mode == "full":
            tool.run_full_scan()
            
        print(f"\n[+] {args.mode.upper()} scan completed!")
        print(f"📁 Check results in: {tool.output_dir}")
        sys.exit(0)
    
    # Interactive mode
    tool.interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user. Exiting safely...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {str(e)}")
        print("[!] Please report this issue if it persists.")
        sys.exit(1)