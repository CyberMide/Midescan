# MideScan v1.0 - by Cybermide
# Module: A05 - Security Misconfiguration

import requests
from bs4 import BeautifulSoup
from modules.crawler import is_false_positive
import os

def get_wordlist(filename):
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, 'wordlists', filename)
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def scan(target, session, baselines=[], verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] A05 - Checking Security Misconfiguration...")

    # ================================================
    # CHECK 1 - Missing Security Headers
    # ================================================
    if verbose:
        print("  [*] Checking security headers...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        headers = resp.headers

        security_headers = {
            'Content-Security-Policy': {
                'severity': 'HIGH',
                'detail': 'CSP header missing - attacker can inject and execute malicious scripts (XSS)',
                'recommendation': 'Add Content-Security-Policy header to restrict sources of scripts, styles and other resources'
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'detail': 'X-Frame-Options missing - site vulnerable to Clickjacking attacks',
                'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent the page being embedded in iframes'
            },
            'X-Content-Type-Options': {
                'severity': 'MEDIUM',
                'detail': 'X-Content-Type-Options missing - browser may interpret files as different MIME types',
                'recommendation': 'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing'
            },
            'Strict-Transport-Security': {
                'severity': 'HIGH',
                'detail': 'HSTS missing - browser may allow HTTP connections leaving users vulnerable to downgrade attacks',
                'recommendation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
            },
            'Referrer-Policy': {
                'severity': 'LOW',
                'detail': 'Referrer-Policy missing - full URL may be sent to third parties in the Referer header',
                'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'severity': 'LOW',
                'detail': 'Permissions-Policy missing - browser features like camera and microphone not restricted',
                'recommendation': 'Add Permissions-Policy header to restrict access to sensitive browser features'
            },
        }

        for header, info in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                results.append({
                    'owasp': 'A05 - Security Misconfiguration',
                    'severity': info['severity'],
                    'status': 'VULNERABLE',
                    'title': f'Missing security header: {header}',
                    'evidence': (
                        f"GET {target}\n"
                        f"  Expected header: {header}\n"
                        f"  Result: Header not present in server response"
                    ),
                    'details': info['detail'],
                    'recommendation': info['recommendation']
                })
                if verbose:
                    print(f"  [!] {info['severity']}: Missing header - {header}")
            else:
                if verbose:
                    print(f"  [+] Header present: {header}")

    except Exception as e:
        pass

    # ================================================
    # CHECK 2 - Sensitive Files Exposed
    # ================================================
    if verbose:
        print("  [*] Checking for exposed sensitive files...")

    sensitive_files = [
        '/.env', '/.env.local', '/.env.production', '/.env.backup',
        '/.git/config', '/.git/HEAD', '/.gitignore',
        '/config.php', '/config.yml', '/config.json', '/config.xml',
        '/configuration.php', '/wp-config.php', '/wp-config.php.bak',
        '/database.yml', '/database.php', '/db.php',
        '/settings.py', '/settings.php', '/local_settings.py',
        '/web.config', '/appsettings.json',
        '/backup.sql', '/backup.zip', '/backup.tar.gz', '/dump.sql',
        '/phpinfo.php', '/info.php', '/test.php',
        '/composer.json', '/composer.lock', '/package.json',
        '/Dockerfile', '/docker-compose.yml',
        '/.htaccess', '/.htpasswd',
        '/robots.txt', '/sitemap.xml',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/server-status', '/server-info',
        '/elmah.axd', '/trace.axd',
    ]

    for path in sensitive_files:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                # Skip if it matches baseline catch-all response
                if is_false_positive(resp, baselines):
                    continue
                content_preview = resp.text[:100].replace('\n', ' ')
                severity = 'CRITICAL' if any(
                    word in path for word in [
                        '.env', 'config', 'database', 'backup',
                        '.git', 'wp-config', 'settings'
                    ]
                ) else 'HIGH'
                results.append({
                    'owasp': 'A05 - Security Misconfiguration',
                    'severity': severity,
                    'status': 'VULNERABLE',
                    'title': f'Sensitive file exposed: {path}',
                    'evidence': (
                        f"GET {url}\n"
                        f"  HTTP Status: 200 OK\n"
                        f"  Content size: {len(resp.content)} bytes\n"
                        f"  Content preview: {content_preview}..."
                    ),
                    'details': f"Sensitive file '{path}' is publicly accessible - may contain credentials, API keys, database passwords or server configuration",
                    'recommendation': f"Immediately restrict access to '{path}' - move sensitive files outside web root or block via server configuration"
                })
                if verbose:
                    print(f"  [!] {severity}: Sensitive file exposed - {url}")
        except:
            pass

    # ================================================
    # CHECK 3 - Directory Listing
    # ================================================
    if verbose:
        print("  [*] Checking for directory listing...")

    dir_paths = [
        '/uploads', '/images', '/files', '/assets',
        '/static', '/media', '/backup', '/logs',
        '/temp', '/tmp', '/css', '/js', '/img'
    ]

    for path in dir_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                if is_false_positive(resp, baselines):
                    continue
                body = resp.text.lower()
                if any(sign in body for sign in [
                    'index of /', 'directory listing',
                    'parent directory', '[to parent directory]'
                ]):
                    results.append({
                        'owasp': 'A05 - Security Misconfiguration',
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': f'Directory listing enabled at {path}',
                        'evidence': (
                            f"GET {url}\n"
                            f"  HTTP Status: 200 OK\n"
                            f"  Directory listing indicators found in response\n"
                            f"  Preview: {resp.text[:150].strip()}..."
                        ),
                        'details': f"Directory listing is enabled at '{path}' - attacker can browse all files in this directory",
                        'recommendation': "Disable directory listing - add 'Options -Indexes' in Apache or 'autoindex off' in Nginx"
                    })
                    if verbose:
                        print(f"  [!] HIGH: Directory listing enabled at {url}")
        except:
            pass

    # ================================================
    # CHECK 4 - Verbose Error Pages
    # ================================================
    if verbose:
        print("  [*] Checking for verbose error pages...")

    error_urls = [
        base + '/this-page-definitely-does-not-exist-12345',
        base + '/index.php?id=\'',
        base + '/?error=1',
    ]

    for url in error_urls:
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code in [404, 500]:
                body = resp.text.lower()
                verbose_signs = [
                    'stack trace', 'traceback', 'exception',
                    'at system.', 'at microsoft.', 'line number',
                    'django.', 'rails', 'laravel', 'symfony',
                    'php fatal error', 'parse error',
                    'mysql error', 'sql syntax',
                    'internal server error details',
                    'file not found in', 'no such file'
                ]
                found_signs = [s for s in verbose_signs if s in body]
                if found_signs:
                    results.append({
                        'owasp': 'A05 - Security Misconfiguration',
                        'severity': 'MEDIUM',
                        'status': 'VULNERABLE',
                        'title': 'Verbose error page reveals server information',
                        'evidence': (
                            f"GET {url}\n"
                            f"  HTTP Status: {resp.status_code}\n"
                            f"  Sensitive info in error page: {', '.join(found_signs)}\n"
                            f"  Preview: {resp.text[:200].strip()}..."
                        ),
                        'details': 'Error pages reveal internal server details - helps attackers plan targeted attacks',
                        'recommendation': 'Implement custom error pages - disable debug mode in production - never show stack traces to users'
                    })
                    if verbose:
                        print(f"  [!] MEDIUM: Verbose error page at {url}")
                    break
        except:
            pass

    # ================================================
    # CHECK 5 - Server Version Disclosure
    # ================================================
    if verbose:
        print("  [*] Checking server version disclosure...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        headers = resp.headers
        disclosure_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version',
            'X-AspNetMvc-Version', 'X-Generator'
        ]
        for h in disclosure_headers:
            if h in headers:
                results.append({
                    'owasp': 'A05 - Security Misconfiguration',
                    'severity': 'LOW',
                    'status': 'VULNERABLE',
                    'title': f'Server version disclosed in {h} header',
                    'evidence': (
                        f"Response header: {h}: {headers[h]}\n"
                        f"  Found on: {target}"
                    ),
                    'details': f"Server reveals version via '{h}: {headers[h]}' - helps attackers identify vulnerable software",
                    'recommendation': f"Remove or obscure the '{h}' header in server configuration"
                })
                if verbose:
                    print(f"  [!] LOW: {h}: {headers[h]} - version disclosed")
    except:
        pass

    if not results:
        results.append({
            'owasp': 'A05 - Security Misconfiguration',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No security misconfigurations detected',
            'evidence': 'Security headers present, no sensitive files exposed, no directory listing',
            'details': 'Basic security misconfiguration checks passed',
            'recommendation': 'Regularly audit server configuration and keep all software updated'
        })
        if verbose:
            print("  [+] No security misconfigurations detected")

    return results