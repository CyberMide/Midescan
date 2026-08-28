# MideScan v1.0 - by Cybermide
# Module: A08 - Software and Data Integrity Failures

import requests
from bs4 import BeautifulSoup
import re

def scan(target, session, verbose=True):
    results = []

    if verbose:
        print("\n  [*] A08 - Checking Software and Data Integrity Failures...")

    # ================================================
    # CHECK 1 - Missing Subresource Integrity (SRI)
    # ================================================
    if verbose:
        print("  [*] Checking Subresource Integrity (SRI) on external resources...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')

        # Check external scripts
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            integrity = script.get('integrity', '')
            crossorigin = script.get('crossorigin', '')

            # Only check external scripts (CDN or third party)
            if src.startswith('http') or src.startswith('//'):
                if not integrity:
                    results.append({
                        'owasp': 'A08 - Software and Data Integrity Failures',
                        'severity': 'MEDIUM',
                        'status': 'VULNERABLE',
                        'title': 'External script missing Subresource Integrity (SRI)',
                        'evidence': (
                            f"Script tag: <script src=\"{src}\">\n"
                            f"  External source: {src}\n"
                            f"  integrity attribute: NOT PRESENT\n"
                            f"  crossorigin attribute: {'present' if crossorigin else 'NOT PRESENT'}\n"
                            f"  Found on page: {target}"
                        ),
                        'details': f"External script '{src}' loaded without SRI hash - if the CDN is compromised attacker can serve malicious JavaScript to all visitors",
                        'recommendation': f"Add integrity and crossorigin attributes to the script tag - generate SRI hash at https://www.srihash.org"
                    })
                    if verbose:
                        print(f"  [!] MEDIUM: External script missing SRI - {src[:60]}...")
                else:
                    if verbose:
                        print(f"  [+] SRI present for script: {src[:60]}...")

        # Check external stylesheets
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '')
            integrity = link.get('integrity', '')

            if href.startswith('http') or href.startswith('//'):
                if not integrity:
                    results.append({
                        'owasp': 'A08 - Software and Data Integrity Failures',
                        'severity': 'LOW',
                        'status': 'VULNERABLE',
                        'title': 'External stylesheet missing Subresource Integrity (SRI)',
                        'evidence': (
                            f"Link tag: <link rel=\"stylesheet\" href=\"{href}\">\n"
                            f"  External source: {href}\n"
                            f"  integrity attribute: NOT PRESENT\n"
                            f"  Found on page: {target}"
                        ),
                        'details': f"External stylesheet '{href}' loaded without SRI - compromised CDN could inject malicious CSS",
                        'recommendation': "Add integrity attribute to link tag - generate hash at https://www.srihash.org"
                    })
                    if verbose:
                        print(f"  [!] LOW: External stylesheet missing SRI - {href[:60]}...")
                else:
                    if verbose:
                        print(f"  [+] SRI present for stylesheet: {href[:60]}...")

    except Exception as e:
        pass

    # ================================================
    # CHECK 2 - Insecure Deserialization Indicators
    # ================================================
    if verbose:
        print("  [*] Checking for insecure deserialization indicators...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        headers = resp.headers
        cookies = resp.cookies

        # Check cookies for serialized objects
        for cookie in cookies:
            value = cookie.value

            # Check for base64 encoded serialized PHP objects
            import base64
            try:
                decoded = base64.b64decode(value + '==').decode('utf-8', errors='ignore')
                if any(sign in decoded for sign in ['O:', 'a:', 's:', 'i:', 'serialize']):
                    results.append({
                        'owasp': 'A08 - Software and Data Integrity Failures',
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': 'Serialized object detected in cookie',
                        'evidence': (
                            f"Cookie name: {cookie.name}\n"
                            f"  Raw value (preview): {value[:50]}...\n"
                            f"  Decoded value (preview): {decoded[:100]}...\n"
                            f"  Serialization indicators found: PHP object notation detected"
                        ),
                        'details': f"Cookie '{cookie.name}' appears to contain a serialized PHP object - if not properly validated this can lead to Remote Code Execution",
                        'recommendation': 'Never trust serialized objects from user input - use signed tokens (JWT) instead - implement integrity checks on all deserialized data'
                    })
                    if verbose:
                        print(f"  [!] HIGH: Serialized object in cookie '{cookie.name}'")
            except:
                pass

            # Check for Java serialized objects (starts with 0xACED)
            if value.startswith('rO0') or value.startswith('ACED'):
                results.append({
                    'owasp': 'A08 - Software and Data Integrity Failures',
                    'severity': 'CRITICAL',
                    'status': 'VULNERABLE',
                    'title': 'Java serialized object detected in cookie',
                    'evidence': (
                        f"Cookie name: {cookie.name}\n"
                        f"  Value prefix: {value[:20]}\n"
                        f"  Java serialization magic bytes detected (rO0/ACED)"
                    ),
                    'details': "Java serialized object detected in cookie - this is a common vector for critical Remote Code Execution vulnerabilities (e.g. Apache Commons Collections)",
                    'recommendation': 'Replace Java serialization with JSON - implement deserialization filters - use Java 9+ serialization filtering'
                })
                if verbose:
                    print(f"  [!] CRITICAL: Java serialized object in cookie '{cookie.name}'")

    except:
        pass

    # ================================================
    # CHECK 3 - Unsigned/Unverified Updates
    # ================================================
    if verbose:
        print("  [*] Checking for unsafe auto-update mechanisms...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        body = resp.text.lower()

        # Check for update scripts loading from external sources without verification
        update_signs = [
            'auto-update', 'autoupdate', 'auto_update',
            'check-for-updates', 'software-update',
            'download-update', 'install-update'
        ]

        for sign in update_signs:
            if sign in body:
                results.append({
                    'owasp': 'A08 - Software and Data Integrity Failures',
                    'severity': 'MEDIUM',
                    'status': 'POTENTIAL',
                    'title': 'Auto-update mechanism detected - manual review needed',
                    'evidence': (
                        f"Keyword '{sign}' found in page source of {target}\n"
                        f"  This may indicate an auto-update mechanism"
                    ),
                    'details': 'Auto-update mechanisms must verify integrity of updates using cryptographic signatures - unverified updates can be tampered with',
                    'recommendation': 'Ensure all software updates are cryptographically signed and verified before installation'
                })
                if verbose:
                    print(f"  [~] MEDIUM: Auto-update indicator found: {sign}")
                break

    except:
        pass

    # ================================================
    # CHECK 4 - JWT Token Security
    # ================================================
    if verbose:
        print("  [*] Checking for JWT token weaknesses...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        cookies = resp.cookies
        headers_dict = dict(resp.headers)

        # Look for JWT in cookies or Authorization header
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

        # Check cookies
        for cookie in cookies:
            match = jwt_pattern.search(cookie.value)
            if match:
                token = match.group()
                parts = token.split('.')

                # Decode header
                import base64
                try:
                    header_pad = parts[0] + '=='
                    header = base64.b64decode(header_pad).decode('utf-8', errors='ignore')

                    if '"alg":"none"' in header or "'alg':'none'" in header:
                        results.append({
                            'owasp': 'A08 - Software and Data Integrity Failures',
                            'severity': 'CRITICAL',
                            'status': 'VULNERABLE',
                            'title': 'JWT using "none" algorithm - signature bypass possible',
                            'evidence': (
                                f"Cookie: {cookie.name}\n"
                                f"  JWT header decoded: {header}\n"
                                f"  Algorithm: none - NO signature verification!"
                            ),
                            'details': 'JWT token uses "none" algorithm - attacker can forge tokens without knowing the secret key',
                            'recommendation': 'Always require a strong algorithm (RS256 or HS256) - reject tokens with "none" algorithm'
                        })
                        if verbose:
                            print(f"  [!] CRITICAL: JWT with 'none' algorithm in cookie '{cookie.name}'")

                    elif '"alg":"HS256"' in header:
                        results.append({
                            'owasp': 'A08 - Software and Data Integrity Failures',
                            'severity': 'INFO',
                            'status': 'POTENTIAL',
                            'title': 'JWT token detected - verify secret key strength',
                            'evidence': (
                                f"Cookie: {cookie.name}\n"
                                f"  JWT header: {header}\n"
                                f"  Algorithm: HS256"
                            ),
                            'details': 'JWT using HS256 - ensure the secret key is strong and not a default/weak value',
                            'recommendation': 'Use a cryptographically random secret of at least 256 bits - consider RS256 for better security'
                        })
                        if verbose:
                            print(f"  [~] INFO: JWT (HS256) found in cookie '{cookie.name}' - verify key strength")
                except:
                    pass

    except:
        pass

    if not results:
        results.append({
            'owasp': 'A08 - Software and Data Integrity Failures',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No software integrity failures detected',
            'evidence': 'SRI checks passed, no serialized objects or weak JWT tokens found',
            'details': 'Basic integrity checks passed',
            'recommendation': 'Add SRI hashes to all external scripts and stylesheets - use signed tokens for session management'
        })
        if verbose:
            print("  [+] No software integrity failures detected")

    return results
