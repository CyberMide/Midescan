# MideScan v1.0 - by Cybermide
# Module: A06 - Vulnerable and Outdated Components

import requests
import re

def scan(target, session, verbose=True):
    results = []

    if verbose:
        print("\n  [*] A06 - Checking Vulnerable and Outdated Components...")

    # ================================================
    # CHECK 1 - Server Header Version Detection
    # ================================================
    if verbose:
        print("  [*] Checking server and technology versions...")

    # Known vulnerable versions database
    vulnerable_versions = {
        'apache': [
            ('2.4.49', 'CRITICAL', 'CVE-2021-41773 - Path Traversal and RCE'),
            ('2.4.50', 'CRITICAL', 'CVE-2021-42013 - Path Traversal and RCE'),
            ('2.2', 'HIGH', 'Apache 2.2.x is end of life - no longer receiving security updates'),
            ('2.0', 'CRITICAL', 'Apache 2.0.x is end of life - multiple known critical vulnerabilities'),
        ],
        'nginx': [
            ('1.14', 'HIGH', 'Nginx 1.14.x - multiple known vulnerabilities'),
            ('1.12', 'HIGH', 'Nginx 1.12.x is end of life'),
            ('1.10', 'CRITICAL', 'Nginx 1.10.x is end of life - multiple critical vulnerabilities'),
        ],
        'php': [
            ('5.', 'CRITICAL', 'PHP 5.x is end of life - no security updates since 2018'),
            ('7.0', 'CRITICAL', 'PHP 7.0.x is end of life'),
            ('7.1', 'CRITICAL', 'PHP 7.1.x is end of life'),
            ('7.2', 'HIGH', 'PHP 7.2.x is end of life'),
            ('7.3', 'HIGH', 'PHP 7.3.x is end of life'),
            ('7.4', 'MEDIUM', 'PHP 7.4.x reached end of life November 2022'),
        ],
        'iis': [
            ('6.0', 'CRITICAL', 'IIS 6.0 is end of life - CVE-2017-7269 WebDAV RCE'),
            ('7.0', 'HIGH', 'IIS 7.0 is end of life'),
            ('7.5', 'HIGH', 'IIS 7.5 is end of life'),
        ],
        'openssl': [
            ('1.0.1', 'CRITICAL', 'CVE-2014-0160 - Heartbleed vulnerability'),
            ('1.0.2', 'HIGH', 'OpenSSL 1.0.2 is end of life'),
            ('1.1.0', 'HIGH', 'OpenSSL 1.1.0 is end of life'),
        ]
    }

    try:
        resp = session.get(target, timeout=5, verify=False)
        headers = resp.headers

        # Check Server header
        server = headers.get('Server', '')
        if server:
            if verbose:
                print(f"  [*] Server header: {server}")
            server_lower = server.lower()
            for software, versions in vulnerable_versions.items():
                if software in server_lower:
                    for version, severity, description in versions:
                        if version in server_lower:
                            results.append({
                                'owasp': 'A06 - Vulnerable and Outdated Components',
                                'severity': severity,
                                'status': 'VULNERABLE',
                                'title': f'Outdated/vulnerable {software.upper()} version detected',
                                'evidence': (
                                    f"Response header: Server: {server}\n"
                                    f"  Detected version: {version}\n"
                                    f"  Known issue: {description}"
                                ),
                                'details': f"Server is running {software.upper()} version {version} which has known vulnerabilities: {description}",
                                'recommendation': f"Immediately update {software.upper()} to the latest stable version and apply all security patches"
                            })
                            if verbose:
                                print(f"  [!] {severity}: Vulnerable {software.upper()} version - {description}")

            # Flag any server version disclosure even if not in vulnerable list
            version_pattern = re.search(r'[\d]+\.[\d]+\.?[\d]*', server)
            if version_pattern and not any(
                software in server_lower for software in vulnerable_versions.keys()
            ):
                results.append({
                    'owasp': 'A06 - Vulnerable and Outdated Components',
                    'severity': 'LOW',
                    'status': 'POTENTIAL',
                    'title': 'Server version information disclosed',
                    'evidence': f"Server header reveals version: {server}",
                    'details': 'Server version is publicly visible - should be verified against CVE databases manually',
                    'recommendation': 'Cross-reference this version against https://cve.mitre.org and update if vulnerabilities exist'
                })
                if verbose:
                    print(f"  [~] POTENTIAL: Server version disclosed: {server}")

        # Check X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            if verbose:
                print(f"  [*] X-Powered-By: {powered_by}")
            powered_lower = powered_by.lower()
            for software, versions in vulnerable_versions.items():
                if software in powered_lower:
                    for version, severity, description in versions:
                        if version in powered_lower:
                            results.append({
                                'owasp': 'A06 - Vulnerable and Outdated Components',
                                'severity': severity,
                                'status': 'VULNERABLE',
                                'title': f'Outdated {software.upper()} version in X-Powered-By header',
                                'evidence': (
                                    f"Response header: X-Powered-By: {powered_by}\n"
                                    f"  Detected version: {version}\n"
                                    f"  Known issue: {description}"
                                ),
                                'details': f"Application is running {software.upper()} {version} which has known security vulnerabilities",
                                'recommendation': f"Update {software.upper()} immediately and remove X-Powered-By header from responses"
                            })
                            if verbose:
                                print(f"  [!] {severity}: Vulnerable {software.upper()} in X-Powered-By")

    except Exception as e:
        pass

    # ================================================
    # CHECK 2 - JavaScript Library Versions
    # ================================================
    if verbose:
        print("  [*] Checking JavaScript library versions...")

    vulnerable_js = {
        'jquery': [
            ('1.', 'HIGH', 'jQuery 1.x - multiple XSS vulnerabilities including CVE-2019-11358'),
            ('2.', 'HIGH', 'jQuery 2.x - multiple XSS vulnerabilities'),
            ('3.0', 'MEDIUM', 'jQuery 3.0.x - CVE-2019-11358 prototype pollution'),
            ('3.1', 'MEDIUM', 'jQuery 3.1.x - CVE-2019-11358 prototype pollution'),
            ('3.2', 'MEDIUM', 'jQuery 3.2.x - CVE-2019-11358 prototype pollution'),
            ('3.3', 'MEDIUM', 'jQuery 3.3.x - CVE-2019-11358 prototype pollution'),
        ],
        'angular': [
            ('1.', 'HIGH', 'AngularJS 1.x is end of life - multiple known vulnerabilities'),
        ],
        'bootstrap': [
            ('3.', 'MEDIUM', 'Bootstrap 3.x - XSS vulnerabilities in tooltip and popover'),
            ('4.0', 'LOW', 'Bootstrap 4.0.x - known XSS vulnerabilities'),
        ]
    }

    try:
        resp = session.get(target, timeout=5, verify=False)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, 'html.parser')
        scripts = soup.find_all('script', src=True)

        for script in scripts:
            src = script.get('src', '').lower()
            for library, versions in vulnerable_js.items():
                if library in src:
                    version_match = re.search(r'[\d]+\.[\d]+\.?[\d]*', src)
                    if version_match:
                        detected = version_match.group()
                        for version, severity, description in versions:
                            if detected.startswith(version):
                                results.append({
                                    'owasp': 'A06 - Vulnerable and Outdated Components',
                                    'severity': severity,
                                    'status': 'VULNERABLE',
                                    'title': f'Vulnerable {library.upper()} version detected',
                                    'evidence': (
                                        f"Script source: {script.get('src')}\n"
                                        f"  Detected version: {detected}\n"
                                        f"  Known issue: {description}"
                                    ),
                                    'details': f"Page loads {library.upper()} version {detected} which has known vulnerabilities: {description}",
                                    'recommendation': f"Update {library.upper()} to the latest stable version immediately"
                                })
                                if verbose:
                                    print(f"  [!] {severity}: Vulnerable {library.upper()} {detected} detected")
                    else:
                        if verbose:
                            print(f"  [*] {library.upper()} detected but version not identifiable from URL")
    except:
        pass

    # ================================================
    # CHECK 3 - WordPress Plugin/Theme Versions
    # ================================================
    if verbose:
        print("  [*] Checking CMS component versions...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        body = resp.text

        # WordPress version detections
        # (placeholder - detection logic can be implemented here)
        pass
    except Exception:
        pass

    # Return aggregated results
    return results