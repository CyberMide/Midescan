#!/usr/bin/env python3
# ================================================
#   MideScan v1.0 - by Cybermide
#   OWASP Top 10 2021 Web Vulnerability Scanner
#   github.com/cybermide/MideScan
# ================================================

import requests
import urllib3
import sys
import os
import datetime
import shutil
from urllib.parse import urlparse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import (
    crawler,
    a01_access,
    a02_crypto,
    a03_injection,
    a04_design,
    a05_misconfig,
    a06_components,
    a07_auth,
    a08_integrity,
    a09_logging,
    a10_ssrf
)

# ================================================
# COLORS FOR TERMINAL OUTPUT
# ================================================
class Color:
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    GREEN   = '\033[92m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

def colorize(text, color):
    return f"{color}{text}{Color.RESET}"

# ================================================
# BANNER
# ================================================
def print_banner():
    banner = f"""
{Color.CYAN}{Color.BOLD}
  ███╗   ███╗██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗ ████║██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔████╔██║██║██║  ██║█████╗  ███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╔╝██║██║██║  ██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚═╝ ██║██║██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝     ╚═╝╚═╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Color.RESET}
{Color.BLUE}          MideScan v1.0 - OWASP Top 10 2021 Web Vulnerability Scanner{Color.RESET}
{Color.WHITE}                        Created by Cybermide{Color.RESET}
{Color.WHITE}              github.com/cybermide | For ethical use only{Color.RESET}
    """
    print(banner)

# ================================================
# ETHICAL DISCLAIMER
# ================================================
def print_disclaimer():
    disclaimer = f"""
{Color.YELLOW}{'='*65}
  LEGAL DISCLAIMER AND ETHICAL USE AGREEMENT
{'='*65}{Color.RESET}
{Color.WHITE}
  MideScan is designed for ETHICAL security testing only.

  By using this tool you confirm that:
  - You own the target system OR
  - You have WRITTEN PERMISSION from the owner to test it
  - You will not use results for malicious purposes
  - You understand unauthorized scanning may be ILLEGAL

  Unauthorized use may violate:
  - Nigeria Cybercrimes Act 2015
  - Computer Fraud and Abuse Act (USA)
  - Computer Misuse Act (UK)
  - And other applicable laws in your jurisdiction
{Color.RESET}
{Color.YELLOW}{'='*65}{Color.RESET}
    """
    print(disclaimer)
    agreement = input(f"{Color.BOLD}  Type 'I AGREE' to continue: {Color.RESET}").strip()
    if agreement.upper() != 'I AGREE':
        print(colorize("\n  Exiting - Agreement not confirmed.\n", Color.RED))
        sys.exit(0)
    print(colorize("\n  Agreement confirmed - Proceeding with scan.\n", Color.GREEN))

# ================================================
# TARGET INPUT AND VALIDATION
# ================================================
def get_target():
    print(f"{Color.CYAN}{'='*65}")
    print("  TARGET CONFIGURATION")
    print(f"{'='*65}{Color.RESET}\n")

    target = input(f"{Color.WHITE}  Enter target URL or domain (e.g. example.com): {Color.RESET}").strip()

    # Add https:// if no scheme provided
    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'https://' + target
        print(colorize(f"  [*] Scheme not specified - defaulting to: {target}", Color.BLUE))

    # Validate URL format
    parsed = urlparse(target)
    if not parsed.netloc:
        print(colorize("  [!] Invalid URL format. Please try again.", Color.RED))
        return get_target()

    return target

def get_scan_options():
    print(f"\n{Color.CYAN}  SCAN OPTIONS{Color.RESET}")
    print(f"  {'1.'} Quick Scan (headers and basic checks only)")
    print(f"  {'2.'} Full Scan (all OWASP Top 10 checks - recommended)\n")
    depth = input(f"{Color.WHITE}  Choose scan type (1 or 2) [default: 2]: {Color.RESET}").strip()
    depth = depth if depth in ['1', '2'] else '2'

    print(f"\n{Color.CYAN}  SUBDOMAIN DISCOVERY METHOD{Color.RESET}")
    print(f"  {'1.'} Wordlist (Fast - checks ~80 common subdomains) [DEFAULT]")
    print(f"  {'2.'} DNS Brute Force (Thorough - checks all subdomains, slower)\n")
    sub_method = input(f"{Color.WHITE}  Choose method (1 or 2) [default: 1]: {Color.RESET}").strip()
    sub_method = 'dns' if sub_method == '2' else 'wordlist'

    return depth, sub_method

def verify_target(target, session):
    print(f"\n{Color.BLUE}  [*] Verifying target reachability...{Color.RESET}")
    try:
        resp = session.get(target, timeout=10, verify=False)
        print(colorize(f"  [+] Target reachable - HTTP {resp.status_code}", Color.GREEN))
        return True
    except requests.exceptions.ConnectionError:
        print(colorize(f"  [!] Cannot connect to {target} - check URL and try again", Color.RED))
        return False
    except requests.exceptions.Timeout:
        print(colorize(f"  [!] Connection timed out - target may be slow or unreachable", Color.RED))
        return False
    except Exception as e:
        print(colorize(f"  [!] Error: {str(e)}", Color.RED))
        return False

# ================================================
# SEVERITY COLORS
# ================================================
def severity_color(severity):
    colors = {
        'CRITICAL': Color.RED,
        'HIGH':     Color.YELLOW,
        'MEDIUM':   '\033[38;5;208m',
        'LOW':      Color.GREEN,
        'INFO':     Color.CYAN,
    }
    return colors.get(severity, Color.WHITE)

# ================================================
# PRINT SCAN PROGRESS
# ================================================
def print_section_header(title, owasp_id):
    print(f"\n{Color.CYAN}{'='*65}")
    print(f"  [{owasp_id}] {title}")
    print(f"{'='*65}{Color.RESET}")

# ================================================
# GENERATE REPORT
# ================================================
def generate_report(target, all_results, scan_duration, platform):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    date_str  = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # Count by severity
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    vulnerable = [r for r in all_results if r['status'] in ['VULNERABLE', 'POTENTIAL']]
    safe       = [r for r in all_results if r['status'] == 'SAFE']

    for r in all_results:
        if r['severity'] in counts:
            counts[r['severity']] += 1

    # ================================================
    # PRINT REPORT TO TERMINAL
    # ================================================
    print(f"\n{Color.BOLD}{Color.CYAN}")
    print("=" * 65)
    print("           MIDESCAN v1.0 - SCAN REPORT")
    print("=" * 65)
    print(f"{Color.RESET}")
    print(f"  Target:    {target}")
    print(f"  Platform:  {platform}")
    print(f"  Date:      {timestamp}")
    print(f"  Duration:  {scan_duration:.2f} seconds")
    print(f"  Total findings: {len(all_results)}")
    print()

    # Summary table
    print(f"  {colorize('CRITICAL', Color.RED)}: {counts['CRITICAL']}  "
          f"{colorize('HIGH', Color.YELLOW)}: {counts['HIGH']}  "
          f"MEDIUM: {counts['MEDIUM']}  "
          f"{colorize('LOW', Color.GREEN)}: {counts['LOW']}  "
          f"{colorize('INFO', Color.CYAN)}: {counts['INFO']}")

    print(f"\n{Color.CYAN}{'='*65}{Color.RESET}")
    print(f"  DETAILED FINDINGS")
    print(f"{Color.CYAN}{'='*65}{Color.RESET}\n")

    # Group by severity
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        severity_results = [r for r in all_results if r['severity'] == severity]
        if severity_results:
            color = severity_color(severity)
            print(f"{color}{Color.BOLD}  [{severity}]{Color.RESET}")
            for r in severity_results:
                status_icon = '[!]' if r['status'] == 'VULNERABLE' else '[~]' if r['status'] == 'POTENTIAL' else '[+]'
                print(f"\n  {color}{status_icon}{Color.RESET} {Color.BOLD}{r['title']}{Color.RESET}")
                print(f"      OWASP: {r['owasp']}")
                print(f"      Status: {r['status']}")
                print(f"      Evidence:")
                for line in r['evidence'].split('\n'):
                    print(f"        {line}")
                print(f"      Details: {r['details']}")
                print(f"      Fix: {r['recommendation']}")
            print()

    # ================================================
    # SAVE REPORT TO FILE
    # ================================================
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    os.makedirs(reports_dir, exist_ok=True)

    domain = urlparse(target).netloc.replace('.', '_').replace(':', '_')
    filename = f"midescan_{domain}_{date_str}.txt"
    filepath = os.path.join(reports_dir, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("=" * 65 + "\n")
        f.write("  MIDESCAN v1.0 - SCAN REPORT\n")
        f.write("  Created by Cybermide\n")
        f.write("=" * 65 + "\n\n")
        f.write(f"Target:    {target}\n")
        f.write(f"Platform:  {platform}\n")
        f.write(f"Date:      {timestamp}\n")
        f.write(f"Duration:  {scan_duration:.2f} seconds\n")
        f.write(f"Total findings: {len(all_results)}\n\n")
        f.write(f"SUMMARY\n")
        f.write(f"CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  "
                f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}  INFO: {counts['INFO']}\n\n")
        f.write("=" * 65 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("=" * 65 + "\n\n")

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_results = [r for r in all_results if r['severity'] == severity]
            if severity_results:
                f.write(f"[{severity}]\n\n")
                for r in severity_results:
                    f.write(f"Title:          {r['title']}\n")
                    f.write(f"OWASP:          {r['owasp']}\n")
                    f.write(f"Status:         {r['status']}\n")
                    f.write(f"Evidence:\n")
                    for line in r['evidence'].split('\n'):
                        f.write(f"  {line}\n")
                    f.write(f"Details:        {r['details']}\n")
                    f.write(f"Recommendation: {r['recommendation']}\n")
                    f.write("-" * 40 + "\n\n")

    print(colorize(f"  [+] Report saved to: {filepath}", Color.GREEN))

    # Ask if user wants to download to Downloads folder
    download = input(f"\n{Color.WHITE}  Download report to Downloads folder? (yes/no): {Color.RESET}").strip().lower()
    if download == 'yes':
        downloads_dir = os.path.join(os.path.expanduser('~'), 'Downloads')
        dest = os.path.join(downloads_dir, filename)
        shutil.copy2(filepath, dest)
        print(colorize(f"  [+] Report downloaded to: {dest}", Color.GREEN))

    return filepath

# ================================================
# MAIN SCANNER ENGINE
# ================================================
def run_scan(target, depth, sub_method, session):
    all_results = []
    start_time  = datetime.datetime.now()

    print(f"\n{Color.CYAN}{'='*65}")
    print("  STARTING SCAN")
    print(f"{'='*65}{Color.RESET}\n")
    print(f"  Target:  {target}")
    print(f"  Depth:   {'Full Scan' if depth == '2' else 'Quick Scan'}")
    print(f"  Method:  {sub_method.upper()} subdomain discovery")
    print(f"  Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Detect platform
    print(colorize("  [*] Detecting platform...", Color.BLUE))
    platform = crawler.detect_platform(target, session)
    print(colorize(f"  [+] Platform detected: {platform}", Color.GREEN))

    # Crawl pages
    print_section_header("Crawling & Discovery", "RECON")
    found_pages  = crawler.crawl_pages(target, session)
    admin_pages  = crawler.enumerate_admin_pages(target, session)
    subdomains   = crawler.enumerate_subdomains(target, method=sub_method)
    admin_urls   = [p['url'] for p in admin_pages if p['status'] == 200]
    all_pages    = found_pages + admin_urls

    # Run all OWASP checks
    modules = [
        ("Broken Access Control",                    "A01", lambda: a01_access.scan(target, session, all_pages)),
        ("Cryptographic Failures",                   "A02", lambda: a02_crypto.scan(target, session)),
        ("Injection",                                "A03", lambda: a03_injection.scan(target, session, all_pages)),
        ("Insecure Design",                          "A04", lambda: a04_design.scan(target, session, all_pages)),
        ("Security Misconfiguration",                "A05", lambda: a05_misconfig.scan(target, session)),
        ("Vulnerable and Outdated Components",       "A06", lambda: a06_components.scan(target, session)),
        ("Identification and Authentication Failures","A07", lambda: a07_auth.scan(target, session)),
        ("Software and Data Integrity Failures",     "A08", lambda: a08_integrity.scan(target, session)),
        ("Security Logging and Monitoring Failures", "A09", lambda: a09_logging.scan(target, session)),
        ("Server Side Request Forgery",              "A10", lambda: a10_ssrf.scan(target, session, all_pages)),
    ]

    for title, owasp_id, scan_func in modules:
        print_section_header(title, owasp_id)
        try:
            results = scan_func()
            all_results.extend(results)
        except Exception as e:
            print(colorize(f"  [!] Error in {owasp_id}: {str(e)}", Color.RED))

    scan_duration = (datetime.datetime.now() - start_time).total_seconds()
    return all_results, scan_duration, platform

# ================================================
# ENTRY POINT
# ================================================
def main():
    print_banner()
    print_disclaimer()

    target = get_target()
    depth, sub_method = get_scan_options()

    # Set up session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'MideScan/1.0 (Security Scanner - Ethical Use Only)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    })

    if not verify_target(target, session):
        print(colorize("\n  [!] Cannot reach target - exiting.\n", Color.RED))
        sys.exit(1)

    all_results, scan_duration, platform = run_scan(
        target, depth, sub_method, session
    )

    generate_report(target, all_results, scan_duration, platform)

    print(f"\n{Color.GREEN}{Color.BOLD}  Scan complete! Stay ethical. - Cybermide{Color.RESET}\n")

if __name__ == '__main__':
    main()