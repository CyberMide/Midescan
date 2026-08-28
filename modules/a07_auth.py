# MideScan v1.0 - by Cybermide
# Module: A07 - Identification and Authentication Failures

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
import re
import time

def get_wordlist(filename):
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, 'wordlists', filename)
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def find_login_page(target, session):
    """Find login page on the target"""
    base = target.rstrip('/')
    login_paths = [
        '/login', '/signin', '/auth', '/user/login',
        '/admin/login', '/wp-login.php', '/account/login',
        '/auth/login', '/users/sign_in', '/session/new'
    ]
    for path in login_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(word in body for word in ['password', 'username', 'email', 'signin', 'login']):
                    return url
        except:
            pass
    return None

def get_login_form(url, session):
    """Extract login form details"""
    try:
        resp = session.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            form_str = str(form).lower()
            if 'password' in form_str:
                inputs = {}
                for inp in form.find_all('input'):
                    name = inp.get('name', '')
                    type_ = inp.get('type', 'text')
                    value = inp.get('value', '')
                    if name:
                        inputs[name] = value
                action = form.get('action', url)
                method = form.get('method', 'post').lower()
                if not action.startswith('http'):
                    action = urljoin(url, action)
                return {'action': action, 'method': method, 'inputs': inputs}
    except:
        pass
    return None

def scan(target, session, verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] A07 - Checking Authentication Failures...")

    # Find login page
    login_url = find_login_page(target, session)
    if login_url:
        if verbose:
            print(f"  [+] Login page found: {login_url}")
        login_form = get_login_form(login_url, session)
    else:
        if verbose:
            print("  [~] No login page found - skipping authentication checks")
        login_url = None
        login_form = None

    # ================================================
    # CHECK 1 - Default Credentials Testing
    # ================================================
    if login_url and login_form:
        if verbose:
            print("  [*] Testing default and common credentials...")

        passwords = get_wordlist('passwords.txt')
        usernames = ['admin', 'administrator', 'root', 'user', 'test', 'guest']

        # Also add username as password (e.g. admin:admin)
        credential_pairs = []
        for username in usernames:
            credential_pairs.append((username, username))
            for password in passwords:
                credential_pairs.append((username, password))

        # Remove duplicates
        credential_pairs = list(dict.fromkeys(credential_pairs))

        successful_logins = []

        for username, password in credential_pairs[:50]:
            try:
                data = login_form['inputs'].copy()

                # Find username and password field names
                for field_name in data.keys():
                    field_lower = field_name.lower()
                    if any(word in field_lower for word in ['user', 'email', 'login', 'name']):
                        data[field_name] = username
                    elif any(word in field_lower for word in ['pass', 'pwd', 'secret']):
                        data[field_name] = password

                resp = session.post(
                    login_form['action'],
                    data=data,
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )

                # Check if login was successful
                body = resp.text.lower()
                success_signs = [
                    'dashboard', 'welcome', 'logout',
                    'sign out', 'my account', 'profile',
                    'successfully logged', 'logged in'
                ]
                failure_signs = [
                    'invalid', 'incorrect', 'wrong',
                    'failed', 'error', 'try again',
                    'invalid credentials', 'bad credentials'
                ]

                has_success = any(sign in body for sign in success_signs)
                has_failure = any(sign in body for sign in failure_signs)

                if has_success and not has_failure:
                    successful_logins.append((username, password))
                    if verbose:
                        print(f"  [!] CRITICAL: Login succeeded with {username}:{password}")

                time.sleep(0.3)

            except:
                pass

        if successful_logins:
            for username, password in successful_logins:
                results.append({
                    'owasp': 'A07 - Identification and Authentication Failures',
                    'severity': 'CRITICAL',
                    'status': 'VULNERABLE',
                    'title': 'Default credentials accepted',
                    'evidence': (
                        f"Login URL: {login_url}\n"
                        f"  Method: POST to {login_form['action']}\n"
                        f"  Credentials tried: username={username}, password={password}\n"
                        f"  Result: Server returned success response - login accepted\n"
                        f"  Success indicators found in response: dashboard/welcome/logout"
                    ),
                    'details': f"Application accepts default credentials ({username}:{password}) - attacker can gain immediate unauthorised access",
                    'recommendation': 'Change all default credentials immediately - enforce strong password policy - implement MFA'
                })
        else:
            if verbose:
                print("  [+] No default credentials accepted")
            results.append({
                'owasp': 'A07 - Identification and Authentication Failures',
                'severity': 'INFO',
                'status': 'SAFE',
                'title': 'Default credentials not accepted',
                'evidence': f"Tested {len(credential_pairs[:50])} username/password combinations against {login_url}",
                'details': 'Common default credentials were rejected by the login page',
                'recommendation': 'Continue enforcing strong password policies and consider implementing MFA'
            })

    # ================================================
    # CHECK 2 - Account Lockout
    # ================================================
    if login_url and login_form:
        if verbose:
            print("  [*] Testing account lockout...")

        blocked = False
        last_status = None

        for i in range(10):
            try:
                data = login_form['inputs'].copy()
                for field_name in data.keys():
                    field_lower = field_name.lower()
                    if any(word in field_lower for word in ['user', 'email', 'login']):
                        data[field_name] = 'admin'
                    elif any(word in field_lower for word in ['pass', 'pwd']):
                        data[field_name] = f'wrongpassword{i}'

                resp = session.post(
                    login_form['action'],
                    data=data,
                    timeout=5,
                    verify=False
                )
                last_status = resp.status_code
                body = resp.text.lower()

                if resp.status_code == 429 or any(
                    word in body for word in ['locked', 'too many', 'blocked', 'try again later', 'temporarily']
                ):
                    blocked = True
                    if verbose:
                        print(f"  [+] Account lockout triggered after {i+1} attempts")
                    break

                time.sleep(0.2)
            except:
                pass

        if not blocked:
            results.append({
                'owasp': 'A07 - Identification and Authentication Failures',
                'severity': 'HIGH',
                'status': 'VULNERABLE',
                'title': 'No account lockout detected',
                'evidence': (
                    f"Login URL: {login_url}\n"
                    f"  Method: POST with 10 consecutive wrong passwords\n"
                    f"  Last HTTP status: {last_status}\n"
                    f"  Result: No lockout, rate limiting or blocking detected after 10 failed attempts"
                ),
                'details': 'No account lockout mechanism detected - attacker can perform unlimited brute force attacks against user accounts',
                'recommendation': 'Implement account lockout after 5 failed attempts - add exponential backoff - alert users of suspicious login activity'
            })
            if verbose:
                print("  [!] HIGH: No account lockout after 10 failed attempts")

    # ================================================
    # CHECK 3 - Session Token Strength
    # ================================================
    if verbose:
        print("  [*] Checking session token strength...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        cookies = resp.cookies

        for cookie in cookies:
            issues = []
            value = cookie.value

            # Check token length
            if len(value) < 16:
                issues.append(f"token too short ({len(value)} chars - minimum 32 recommended)")

            # Check if token looks predictable
            if value.isdigit():
                issues.append("token is purely numeric - easily guessable")
            if re.match(r'^[0-9a-f]+$', value) and len(value) < 32:
                issues.append("token appears to be a short hex value - may be predictable")

            # Check sequential patterns
            if any(str(i) + str(i+1) + str(i+2) in value for i in range(8)):
                issues.append("token contains sequential numbers - may be predictable")

            # Check security flags
            if not cookie.secure:
                issues.append("missing Secure flag - cookie sent over HTTP")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("missing HttpOnly flag - accessible via JavaScript (XSS risk)")
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append("missing SameSite flag - CSRF risk")

            if issues:
                results.append({
                    'owasp': 'A07 - Identification and Authentication Failures',
                    'severity': 'HIGH' if any('short' in i or 'numeric' in i for i in issues) else 'MEDIUM',
                    'status': 'VULNERABLE',
                    'title': f'Weak session token detected: {cookie.name}',
                    'evidence': (
                        f"Cookie name: {cookie.name}\n"
                        f"  Cookie value (preview): {value[:20]}...\n"
                        f"  Token length: {len(value)} characters\n"
                        f"  Issues found:\n"
                        + '\n'.join([f"    - {issue}" for issue in issues])
                    ),
                    'details': f"Session cookie '{cookie.name}' has weak security properties - issues: {', '.join(issues)}",
                    'recommendation': 'Use cryptographically random session tokens of at least 32 chars - set Secure, HttpOnly and SameSite=Strict flags'
                })
                if verbose:
                    print(f"  [!] Weak session token '{cookie.name}': {', '.join(issues)}")
            else:
                if verbose:
                    print(f"  [+] Session token '{cookie.name}' appears strong")

    except:
        pass

    # ================================================
    # CHECK 4 - Password in URL
    # ================================================
    if verbose:
        print("  [*] Checking for credentials in URLs...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup.find_all(['a', 'form']):
            href = tag.get('href') or tag.get('action') or ''
            sensitive_params = ['password', 'passwd', 'pass', 'pwd',
                                 'token', 'secret', 'key', 'auth']
            for param in sensitive_params:
                if f'{param}=' in href.lower():
                    results.append({
                        'owasp': 'A07 - Identification and Authentication Failures',
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': 'Credentials or tokens found in URL',
                        'evidence': (
                            f"URL containing sensitive parameter: {href[:150]}\n"
                            f"  Sensitive parameter detected: {param}"
                        ),
                        'details': f"Sensitive parameter '{param}' found in URL - credentials in URLs are logged by servers, proxies and browser history",
                        'recommendation': 'Never pass passwords or tokens in URLs - use POST requests with HTTPS encrypted body'
                    })
                    if verbose:
                        print(f"  [!] HIGH: Sensitive parameter '{param}' found in URL")
    except:
        pass

    # ================================================
    # CHECK 5 - Multi-Factor Authentication
    # ================================================
    if login_url:
        if verbose:
            print("  [*] Checking for MFA indicators...")

        try:
            resp = session.get(login_url, timeout=5, verify=False)
            body = resp.text.lower()
            mfa_signs = ['two-factor', '2fa', 'multi-factor', 'mfa',
                         'authenticator', 'otp', 'one-time', 'verification code']
            has_mfa = any(sign in body for sign in mfa_signs)

            if not has_mfa:
                results.append({
                    'owasp': 'A07 - Identification and Authentication Failures',
                    'severity': 'MEDIUM',
                    'status': 'POTENTIAL',
                    'title': 'No Multi-Factor Authentication (MFA) detected',
                    'evidence': (
                        f"Login page: {login_url}\n"
                        f"  Checked for MFA indicators: {', '.join(mfa_signs)}\n"
                        f"  Result: No MFA indicators found in login page"
                    ),
                    'details': 'No MFA detected on login page - if credentials are compromised attacker gains immediate access',
                    'recommendation': 'Implement MFA using TOTP authenticator app, SMS OTP or hardware security keys'
                })
                if verbose:
                    print("  [~] MEDIUM: No MFA indicators found on login page")
            else:
                if verbose:
                    print("  [+] MFA indicators detected on login page")
        except:
            pass

    if not results:
        results.append({
            'owasp': 'A07 - Identification and Authentication Failures',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No authentication failures detected',
            'evidence': 'Default credentials rejected, session tokens appear strong',
            'details': 'Basic authentication checks passed',
            'recommendation': 'Implement MFA, enforce strong password policy and monitor for suspicious login patterns'
        })
        if verbose:
            print("  [+] No authentication failures detected")

    return results