# MideScan v1.0 by Cybermide
# Module: A04 — Insecure Design

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time

def scan(target, session, found_pages=[], verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] A04 — Checking Insecure Design...")

    # ================================================
    # CHECK 1 Rate Limiting on Login
    # ================================================
    if verbose:
        print("  [*] Testing rate limiting on login pages...")

    login_paths = [
        '/login', '/signin', '/auth', '/user/login',
        '/admin/login', '/wp-login.php', '/account/login'
    ]

    login_found = None
    for path in login_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                login_found = url
                break
        except:
            pass

    if login_found:
        if verbose:
            print(f"  [*] Login page found at {login_found} — testing rate limiting...")

        blocked = False
        for i in range(10):
            try:
                resp = session.post(login_found, data={
                    'username': 'testuser',
                    'password': f'wrongpassword{i}',
                    'email': 'test@test.com'
                }, timeout=5, verify=False)

                if resp.status_code in [429, 403] or 'too many' in resp.text.lower() or 'locked' in resp.text.lower() or 'blocked' in resp.text.lower():
                    blocked = True
                    if verbose:
                        print(f"  [+] Rate limiting detected after {i+1} attempts")
                    break
            except:
                pass
            time.sleep(0.2)

        if not blocked:
            results.append({
                'owasp': 'A04 — Insecure Design',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
                'title': 'No rate limiting detected on login page',
                'evidence': (
                    f"Login URL: {login_found}\n"
                    f"  Method: POST with 10 rapid requests\n"
                    f"  Result: No blocking, rate limiting or lockout detected after 10 failed attempts\n"
                    f"  HTTP status remained: {resp.status_code}"
                ),
                'details': 'Login page does not implement rate limiting — attacker can perform brute force or credential stuffing attacks without restriction',
                'recommendation': 'Implement rate limiting (max 5 attempts), account lockout, CAPTCHA and exponential backoff on login endpoints'
            })
            if verbose:
                print("  [!] HIGH: No rate limiting on login — brute force possible")
        else:
            results.append({
                'owasp': 'A04 — Insecure Design',
                'severity': 'INFO',
                'status': 'SAFE',
                'title': 'Rate limiting detected on login page',
                'evidence': f"Login at {login_found} blocked requests after repeated attempts",
                'details': 'Rate limiting is active on the login endpoint',
                'recommendation': 'Ensure lockout duration is sufficient and CAPTCHA is also implemented'
            })
    else:
        if verbose:
            print("  [~] No login page found to test rate limiting")

    # ================================================
    # CHECK 2 — CAPTCHA Detection
    # ================================================
    if verbose:
        print("  [*] Checking for CAPTCHA on forms...")

    pages_to_check = [target] + found_pages[:5]
    for page in pages_to_check:
        try:
            resp = session.get(page, timeout=5, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                form_html = str(form).lower()
                has_captcha = any(word in form_html for word in [
                    'captcha', 'recaptcha', 'g-recaptcha',
                    'hcaptcha', 'turnstile', 'cf-turnstile'
                ])
                has_sensitive = any(word in form_html for word in [
                    'password', 'login', 'signin', 'register',
                    'signup', 'contact', 'email'
                ])
                if has_sensitive and not has_captcha:
                    results.append({
                        'owasp': 'A04 — Insecure Design',
                        'severity': 'MEDIUM',
                        'status': 'VULNERABLE',
                        'title': 'Sensitive form missing CAPTCHA protection',
                        'evidence': (
                            f"Page: {page}\n"
                            f"  Form action: {form.get('action', 'unknown')}\n"
                            f"  Contains sensitive fields but no CAPTCHA detected"
                        ),
                        'details': 'Sensitive form has no CAPTCHA — vulnerable to automated bot attacks, spam and credential stuffing',
                        'recommendation': 'Implement CAPTCHA (Google reCAPTCHA v3 or Cloudflare Turnstile) on all sensitive forms'
                    })
                    if verbose:
                        print(f"  [!] MEDIUM: Form at {page} missing CAPTCHA")
        except:
            pass

    # ================================================
    # CHECK 3  IDOR via Predictable URLs
    # ================================================
    if verbose:
        print("  [*] Checking for predictable resource IDs (IDOR)...")

    idor_patterns = [
        '/user/1', '/user/2', '/user/3',
        '/account/1', '/account/2',
        '/profile/1', '/profile/2',
        '/order/1', '/order/2',
        '/invoice/1', '/invoice/2',
        '/document/1', '/document/2',
        '/api/v1/user/1', '/api/v1/user/2',
        '/api/users/1', '/api/users/2',
    ]

    from modules.crawler import is_false_positive
    found_idor = []
    for path in idor_patterns:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 50:
                if is_false_positive(resp, baselines):
                    continue
                found_idor.append({'url': url, 'size': len(resp.content)})
        except:
            pass

    if len(found_idor) >= 2:
        results.append({
            'owasp': 'A04 — Insecure Design',
            'severity': 'HIGH',
            'status': 'VULNERABLE',
            'title': 'Predictable resource IDs detected — potential IDOR',
            'evidence': (
                f"Multiple sequential IDs returned data:\n"
                + '\n'.join([f"  GET {r['url']} → 200 OK ({r['size']} bytes)" for r in found_idor])
            ),
            'details': 'Sequential numeric IDs in URLs suggest IDOR vulnerability — attacker can enumerate IDs to access other users data',
            'recommendation': 'Use UUIDs instead of sequential IDs — implement object-level authorisation checks on every request'
        })
        if verbose:
            print(f"  [!] HIGH: Predictable IDs found — possible IDOR at {found_idor[0]['url']}")

    # ================================================
    # CHECK 4  Password Reset Design Flaws
    # ================================================
    if verbose:
        print("  [*] Checking password reset design...")

    reset_paths = ['/forgot-password', '/reset-password', '/password-reset',
                   '/account/forgot', '/user/forgot', '/auth/reset']

    for path in reset_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                if 'security question' in body:
                    results.append({
                        'owasp': 'A04 — Insecure Design',
                        'severity': 'MEDIUM',
                        'status': 'VULNERABLE',
                        'title': 'Password reset uses security questions',
                        'evidence': f"Password reset at {url} uses security questions — easily guessable or researched",
                        'details': 'Security questions are a weak form of authentication — answers can often be found on social media',
                        'recommendation': 'Replace security questions with email/SMS OTP or authenticator app for password reset'
                    })
                    if verbose:
                        print(f"  [!] MEDIUM: Security questions used for password reset at {url}")

                if 'token' not in body and 'link' not in body and 'email' not in body:
                    results.append({
                        'owasp': 'A04 — Insecure Design',
                        'severity': 'MEDIUM',
                        'status': 'POTENTIAL',
                        'title': 'Password reset page found — manual review recommended',
                        'evidence': f"Password reset page found at {url}",
                        'details': 'Password reset mechanism requires manual testing to verify token expiry, single-use enforcement and enumeration protection',
                        'recommendation': 'Ensure reset tokens are random, expire quickly, are single-use and do not reveal if email exists'
                    })
                    if verbose:
                        print(f"  [~] Password reset found at {url} — manual review needed")
        except:
            pass

    if not results:
        results.append({
            'owasp': 'A04 — Insecure Design',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No obvious insecure design issues found',
            'evidence': 'Rate limiting, CAPTCHA and IDOR checks passed',
            'details': 'Basic insecure design checks passed — manual review still recommended',
            'recommendation': 'Conduct threat modelling and manual penetration testing for complete coverage'
        })
        if verbose:
            print("  [+] No obvious insecure design issues found")

    return results