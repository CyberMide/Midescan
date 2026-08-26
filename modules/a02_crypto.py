# MideScan v1.0 by Cybermide
# Module: A02 Cryptographic Failures

import requests
import socket
import ssl

def scan(target, session, verbose=True):
    results = []
    parsed_target = target.rstrip('/')

    if verbose:
        print("\n  [*] A02 — Checking Cryptographic Failures...")

    # Check 1 HTTP vs HTTPS
    if target.startswith('http://'):
        results.append({
            'owasp': 'A02 — Cryptographic Failures',
            'severity': 'CRITICAL',
            'status': 'VULNERABLE',
            'title': 'Site running on HTTP — No encryption',
            'evidence': f"Target URL uses HTTP: {target}",
            'details': 'All data transmitted between client and server is unencrypted and can be intercepted by attackers (Man-in-the-Middle attack)',
            'recommendation': 'Migrate to HTTPS immediately — obtain an SSL/TLS certificate (free via Let\'s Encrypt)'
        })
        if verbose:
            print("  [!] CRITICAL: Site is using HTTP — no encryption!")

        # Check if HTTPS version exists
        https_target = target.replace('http://', 'https://')
        try:
            resp = session.get(https_target, timeout=5, verify=False)
            if resp.status_code == 200:
                results.append({
                    'owasp': 'A02 — Cryptographic Failures',
                    'severity': 'HIGH',
                    'status': 'VULNERABLE',
                    'title': 'HTTPS available but HTTP not redirecting to HTTPS',
                    'evidence': f"HTTPS version exists at {https_target} but HTTP does not redirect",
                    'details': 'Users who visit the HTTP version will not be automatically redirected to the secure HTTPS version',
                    'recommendation': 'Configure server to redirect all HTTP traffic to HTTPS using 301 permanent redirect'
                })
                if verbose:
                    print("  [!] HIGH: HTTPS exists but HTTP is not redirecting to it")
        except:
            pass

    else:
        if verbose:
            print("  [+] Site is using HTTPS")

        # Check 2 HTTPS redirect from HTTP
        http_target = target.replace('https://', 'http://')
        try:
            resp = requests.get(http_target, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code not in [301, 302, 307, 308]:
                results.append({
                    'owasp': 'A02 — Cryptographic Failures',
                    'severity': 'MEDIUM',
                    'status': 'VULNERABLE',
                    'title': 'HTTP does not redirect to HTTPS',
                    'evidence': f"GET {http_target} returned HTTP {resp.status_code} — no redirect to HTTPS",
                    'details': 'Users who visit the HTTP version are not redirected to HTTPS — data may be sent unencrypted',
                    'recommendation': 'Configure 301 permanent redirect from HTTP to HTTPS on the server'
                })
                if verbose:
                    print("  [!] MEDIUM: HTTP version does not redirect to HTTPS")
            else:
                if verbose:
                    print("  [+] HTTP correctly redirects to HTTPS")
        except:
            pass

    # Check 3 SSL/TLS certificate validity
    if verbose:
        print("  [*] Checking SSL/TLS certificate...")

    try:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.netloc or parsed.path
        hostname = hostname.split(':')[0]

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

            # Check expiry
            import datetime
            expire_date = datetime.datetime.strptime(
                cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
            )
            days_left = (expire_date - datetime.datetime.utcnow()).days

            if days_left < 0:
                results.append({
                    'owasp': 'A02 — Cryptographic Failures',
                    'severity': 'CRITICAL',
                    'status': 'VULNERABLE',
                    'title': 'SSL Certificate has EXPIRED',
                    'evidence': f"Certificate expired on {cert['notAfter']}",
                    'details': 'An expired SSL certificate means browsers will warn users the site is insecure',
                    'recommendation': 'Renew the SSL certificate immediately'
                })
                if verbose:
                    print(f"  [!] CRITICAL: SSL certificate expired on {cert['notAfter']}")
            elif days_left < 30:
                results.append({
                    'owasp': 'A02 — Cryptographic Failures',
                    'severity': 'HIGH',
                    'status': 'VULNERABLE',
                    'title': f'SSL Certificate expiring soon — {days_left} days left',
                    'evidence': f"Certificate expires on {cert['notAfter']}",
                    'details': f'SSL certificate will expire in {days_left} days — users will see security warnings soon',
                    'recommendation': 'Renew SSL certificate before it expires'
                })
                if verbose:
                    print(f"  [!] HIGH: SSL certificate expires in {days_left} days!")
            else:
                if verbose:
                    print(f"  [+] SSL certificate valid — {days_left} days remaining")

    except ssl.SSLCertVerificationError:
        results.append({
            'owasp': 'A02 — Cryptographic Failures',
            'severity': 'HIGH',
            'status': 'VULNERABLE',
            'title': 'SSL Certificate verification failed',
            'evidence': 'SSL certificate could not be verified — possibly self-signed or misconfigured',
            'details': 'An invalid SSL certificate allows attackers to perform Man-in-the-Middle attacks',
            'recommendation': 'Install a valid SSL certificate from a trusted Certificate Authority'
        })
        if verbose:
            print("  [!] HIGH: SSL certificate verification failed")
    except:
        pass

    # Check 4 — Sensitive data in cookies
    if verbose:
        print("  [*] Checking cookie security flags...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        cookies = resp.cookies

        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append("missing SameSite flag")

            if issues:
                results.append({
                    'owasp': 'A02 — Cryptographic Failures',
                    'severity': 'MEDIUM',
                    'status': 'VULNERABLE',
                    'title': f'Cookie "{cookie.name}" has weak security flags',
                    'evidence': f"Cookie: {cookie.name}={cookie.value[:20]}... | Issues: {', '.join(issues)}",
                    'details': f"Cookie '{cookie.name}' is missing security flags: {', '.join(issues)} — can be stolen via XSS or sent over HTTP",
                    'recommendation': 'Set Secure, HttpOnly and SameSite=Strict flags on all cookies'
                })
                if verbose:
                    print(f"  [!] MEDIUM: Cookie '{cookie.name}' — {', '.join(issues)}")
            else:
                if verbose:
                    print(f"  [+] Cookie '{cookie.name}' has proper security flags")

    except:
        pass

    # Check 5 — Sensitive data in URL
    if verbose:
        print("  [*] Checking for sensitive data in URLs...")

    sensitive_params = ['password', 'passwd', 'pass', 'pwd', 'token',
                        'secret', 'key', 'api_key', 'apikey', 'auth',
                        'credit_card', 'card', 'ssn', 'session']
    try:
        resp = session.get(target, timeout=5, verify=False)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup.find_all(['a', 'form']):
            href = tag.get('href') or tag.get('action') or ''
            for param in sensitive_params:
                if param in href.lower():
                    results.append({
                        'owasp': 'A02 — Cryptographic Failures',
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': 'Sensitive data found in URL',
                        'evidence': f"URL contains sensitive parameter: {href[:100]}",
                        'details': f"Parameter '{param}' found in URL — sensitive data in URLs is logged by servers, browsers and proxies",
                        'recommendation': 'Never pass sensitive data in URLs — use POST requests with encrypted body instead'
                    })
                    if verbose:
                        print(f"  [!] HIGH: Sensitive parameter '{param}' found in URL")
    except:
        pass

    if not results:
        results.append({
            'owasp': 'A02 — Cryptographic Failures',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No cryptographic failures detected',
            'evidence': 'HTTPS enabled, certificate valid, cookies properly configured',
            'details': 'Basic cryptographic checks passed',
            'recommendation': 'Continue monitoring SSL certificate expiry and cookie configurations'
        })
        if verbose:
            print("  [+] No cryptographic failures detected")

    return results