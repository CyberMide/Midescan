# MideScan v1.0 - by Cybermide
# Module: Web Crawler & Subdomain Enumerator

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import socket
import os

# ================================================
# BASELINE & FALSE POSITIVE DETECTION
# ================================================
def get_baseline_response(target, session):
    """
    Get baseline response for a non-existent page.
    Used to detect catch-all routes that return 200 for everything.
    """
    test_urls = [
        target.rstrip('/') + '/this-page-definitely-does-not-exist-xyz-123',
        target.rstrip('/') + '/another-fake-page-abc-456',
        target.rstrip('/') + '/midescan-baseline-check-789',
    ]
    baselines = []
    for url in test_urls:
        try:
            resp = session.get(url, timeout=5, verify=False)
            baselines.append({
                'status': resp.status_code,
                'size': len(resp.content),
                'content_hash': hash(resp.text[:500])
            })
        except:
            pass
    return baselines

def is_false_positive(resp, baselines):
    """
    Check if a response matches the baseline catch-all response.
    Returns True if the response is likely a false positive.
    """
    if not baselines:
        return False
    for baseline in baselines:
        if (resp.status_code == baseline['status'] and
            abs(len(resp.content) - baseline['size']) < 50):
            return True
        if hash(resp.text[:500]) == baseline['content_hash']:
            return True
    return False

# ================================================
# WORDLIST LOADER
# ================================================
def get_wordlist(filename):
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, 'wordlists', filename)
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# ================================================
# PAGE CRAWLER
# ================================================
def crawl_pages(target, session, verbose=True):
    """Crawl the target and extract all internal links"""
    found_pages = set()
    to_visit = [target]
    visited = set()
    base_domain = urlparse(target).netloc

    if verbose:
        print(f"\n  [*] Crawling {target} for pages...")

    while to_visit and len(found_pages) < 50:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            resp = session.get(url, timeout=5, verify=False)
            found_pages.add(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for tag in soup.find_all(['a', 'form']):
                href = tag.get('href') or tag.get('action')
                if href:
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    if parsed.netloc == base_domain and full_url not in visited:
                        to_visit.append(full_url)
        except:
            pass

    if verbose:
        print(f"  [+] Found {len(found_pages)} pages")
    return list(found_pages)

# ================================================
# ADMIN PAGE ENUMERATION
# ================================================
def enumerate_admin_pages(target, session, baselines=[], verbose=True):
    """Check for common admin and sensitive pages"""
    found = []
    admin_paths = get_wordlist('admin_pages.txt')
    base = target.rstrip('/')

    if verbose:
        print(f"\n  [*] Checking {len(admin_paths)} common admin/sensitive paths...")

    for path in admin_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code in [200, 201, 202, 204, 301, 302, 403]:
                # Skip if it matches baseline catch-all response
                if is_false_positive(resp, baselines):
                    continue
                found.append({
                    'url': url,
                    'status': resp.status_code,
                    'size': len(resp.content)
                })
                if verbose:
                    status_label = "FOUND" if resp.status_code == 200 else f"REDIRECT/FORBIDDEN ({resp.status_code})"
                    print(f"  [!] {status_label}: {url}")
        except:
            pass

    return found

# ================================================
# SUBDOMAIN ENUMERATION
# ================================================
def enumerate_subdomains(target, method='wordlist', verbose=True):
    """Enumerate subdomains using wordlist or DNS brute force"""
    found = []
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    domain = domain.replace('www.', '')
    scheme = parsed.scheme or 'https'
    subdomains = get_wordlist('subdomains.txt')

    if verbose:
        print(f"\n  [*] Enumerating subdomains for {domain}")
        print(f"  [*] Method: {method.upper()} ({len(subdomains)} subdomains to check)")

    for sub in subdomains:
        hostname = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            url = f"{scheme}://{hostname}"
            found.append({'subdomain': hostname, 'ip': ip, 'url': url})
            if verbose:
                print(f"  [+] Found: {hostname} -> {ip}")
        except:
            pass

    if verbose:
        print(f"  [+] Found {len(found)} subdomains")
    return found

# ================================================
# PLATFORM DETECTION
# ================================================
def detect_platform(target, session):
    """Detect what platform/CMS the target is running"""
    platform = "Unknown"
    try:
        resp = session.get(target, timeout=5, verify=False)
        headers = resp.headers
        body = resp.text.lower()

        if 'wp-content' in body or 'wp-includes' in body:
            platform = "WordPress"
        elif 'joomla' in body or '/components/com_' in body:
            platform = "Joomla"
        elif 'drupal' in body or 'sites/default/files' in body:
            platform = "Drupal"
        elif 'laravel' in body or 'laravel_session' in str(headers):
            platform = "Laravel"
        elif 'django' in body or 'csrfmiddlewaretoken' in body:
            platform = "Django"
        elif 'x-powered-by' in headers:
            platform = headers['x-powered-by']
    except:
        pass
    return platform