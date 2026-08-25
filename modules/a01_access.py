# MideScan v1.0 by Cybermide
# Module: A01 Broken Access Control

import requests

def scan(target, session, found_pages=[], verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] A01 — Checking Broken Access Control...")

    # Check discovered pages for access control issues
    sensitive_keywords = [
        'dashboard', 'admin', 'panel', 'control',
        'manage', 'config', 'setting', 'user', 'account',
        'backup', 'database', 'secret', 'private'
    ]

    for page in found_pages:
        for keyword in sensitive_keywords:
            if keyword in page.lower():
                try:
                    resp = session.get(page, timeout=5, verify=False, allow_redirects=False)
                    if resp.status_code == 200:
                        results.append({
                            'owasp': 'A01 — Broken Access Control',
                            'severity': 'HIGH',
                            'status': 'VULNERABLE',
                            'title': 'Sensitive page accessible without authentication',
                            'evidence': f"GET {page} returned HTTP 200 OK without login",
                            'details': f"Page '{page}' containing keyword '{keyword}' is publicly accessible",
                            'recommendation': 'Implement authentication and authorisation checks on all sensitive pages'
                        })
                        if verbose:
                            print(f"  [!] VULNERABLE: {page} accessible without auth (HTTP 200)")
                    elif resp.status_code == 403:
                        results.append({
                            'owasp': 'A01 — Broken Access Control',
                            'severity': 'MEDIUM',
                            'status': 'POTENTIAL',
                            'title': 'Sensitive page exists but access forbidden',
                            'evidence': f"GET {page} returned HTTP 403 Forbidden",
                            'details': f"Page exists at '{page}' — forbidden but may be bypassable",
                            'recommendation': 'Verify 403 cannot be bypassed with header manipulation'
                        })
                        if verbose:
                            print(f"  [~] POTENTIAL: {page} exists but returns 403")
                except:
                    pass
                break

    # Check for IDOR Insecure Direct Object Reference
    idor_paths = [
        '/user/1', '/user/2', '/account/1', '/account/2',
        '/profile/1', '/profile/2', '/api/user/1', '/api/user/2',
        '/order/1', '/order/2', '/document/1', '/document/2'
    ]

    if verbose:
        print("  [*] Checking for IDOR vulnerabilities...")

    for path in idor_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 100:
                results.append({
                    'owasp': 'A01 — Broken Access Control',
                    'severity': 'HIGH',
                    'status': 'VULNERABLE',
                    'title': 'Potential IDOR — Insecure Direct Object Reference',
                    'evidence': f"GET {url} returned HTTP 200 with {len(resp.content)} bytes of data",
                    'details': f"Resource at '{path}' is accessible without authentication — changing ID may expose other users data",
                    'recommendation': 'Implement object-level authorisation checks — verify the requesting user owns the resource'
                })
                if verbose:
                    print(f"  [!] POTENTIAL IDOR: {url} returned 200 with data")
        except:
            pass

    # Check for HTTP method tampering
    if verbose:
        print("  [*] Checking HTTP method tampering...")

    try:
        resp = session.options(target, timeout=5, verify=False)
        allowed = resp.headers.get('Allow', '')
        dangerous = [m for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] if m in allowed]
        if dangerous:
            results.append({
                'owasp': 'A01 — Broken Access Control',
                'severity': 'MEDIUM',
                'status': 'VULNERABLE',
                'title': 'Dangerous HTTP methods allowed',
                'evidence': f"OPTIONS request returned Allow: {allowed}",
                'details': f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                'recommendation': 'Disable unused HTTP methods — only allow GET and POST where appropriate'
            })
            if verbose:
                print(f"  [!] Dangerous HTTP methods allowed: {', '.join(dangerous)}")
    except:
        pass

    if not results:
        results.append({
            'owasp': 'A01 — Broken Access Control',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No obvious broken access control issues found',
            'evidence': 'All checked pages returned appropriate responses',
            'details': 'Basic access control checks passed',
            'recommendation': 'Continue manual testing — automated scanners cannot catch all access control flaws'
        })
        if verbose:
            print("  [+] No obvious access control issues found")

    return results