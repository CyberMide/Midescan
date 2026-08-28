# MideScan v1.0 - by Cybermide
# Module: A09 - Security Logging and Monitoring Failures

import requests
from bs4 import BeautifulSoup
import re
import time

def scan(target, session, verbose=True):
    results = []
    base = target.rstrip('/')

    if verbose:
        print("\n  [*] A09 - Checking Security Logging and Monitoring Failures...")

    # ================================================
    # CHECK 1 - Verbose Error Messages
    # ================================================
    if verbose:
        print("  [*] Checking for verbose error messages...")

    error_triggers = [
        base + '/this-page-does-not-exist-12345',
        base + '/index.php?id=999999999',
        base + '/index.php?id=\'',
        base + '/api/user/99999999',
        base + '/%invalid%path%',
        base + '/index.php?debug=true',
        base + '/?error=1',
    ]

    verbose_signs = {
        'stack trace': 'CRITICAL',
        'traceback': 'CRITICAL',
        'at system.': 'CRITICAL',
        'at microsoft.': 'CRITICAL',
        'unhandled exception': 'CRITICAL',
        'php fatal error': 'CRITICAL',
        'php parse error': 'CRITICAL',
        'php warning': 'HIGH',
        'mysql error': 'CRITICAL',
        'sql syntax': 'CRITICAL',
        'ora-': 'CRITICAL',
        'postgresql error': 'CRITICAL',
        'django.': 'HIGH',
        'flask debugger': 'CRITICAL',
        'werkzeug debugger': 'CRITICAL',
        'rails error': 'HIGH',
        'laravel': 'HIGH',
        'symfony': 'HIGH',
        'line number': 'HIGH',
        'file not found': 'MEDIUM',
        'no such file': 'MEDIUM',
        'permission denied': 'MEDIUM',
        'internal server error details': 'HIGH',
        'debug mode': 'HIGH',
        'debug = true': 'HIGH',
    }

    for url in error_triggers:
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code in [400, 404, 500, 501, 502, 503]:
                body = resp.text.lower()
                for sign, severity in verbose_signs.items():
                    if sign in body:
                        # Get a snippet around the error
                        idx = body.find(sign)
                        snippet = resp.text[max(0, idx-50):idx+150].strip()

                        results.append({
                            'owasp': 'A09 - Security Logging and Monitoring Failures',
                            'severity': severity,
                            'status': 'VULNERABLE',
                            'title': f'Verbose error message reveals internal information',
                            'evidence': (
                                f"URL triggered: {url}\n"
                                f"  HTTP Status: {resp.status_code}\n"
                                f"  Sensitive keyword found: '{sign}'\n"
                                f"  Error snippet: {snippet[:200]}"
                            ),
                            'details': f"Error page reveals internal server details via '{sign}' - helps attackers understand server architecture and plan targeted attacks",
                            'recommendation': 'Implement custom error pages - disable debug mode in production - log errors server-side only - never expose stack traces to users'
                        })
                        if verbose:
                            print(f"  [!] {severity}: Verbose error '{sign}' found at {url}")
                        break
        except:
            pass

    # ================================================
    # CHECK 2 - Debug Mode Detection
    # ================================================
    if verbose:
        print("  [*] Checking for debug mode indicators...")

    debug_paths = [
        '/?debug=true', '/?debug=1', '/?XDEBUG_SESSION_START=1',
        '/debug', '/debugger', '/_debug', '/__debug__',
        '/console', '/_profiler', '/app_dev.php',
        '/laravel-debugbar', '/telescope', '/horizon',
    ]

    for path in debug_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                debug_signs = [
                    'debug', 'profiler', 'timeline',
                    'queries', 'memory usage', 'execution time',
                    'werkzeug', 'django debug', 'laravel debugbar',
                    'symfony profiler', 'xdebug'
                ]
                found = [s for s in debug_signs if s in body]
                if found:
                    results.append({
                        'owasp': 'A09 - Security Logging and Monitoring Failures',
                        'severity': 'CRITICAL',
                        'status': 'VULNERABLE',
                        'title': 'Debug mode or profiler accessible in production',
                        'evidence': (
                            f"URL: {url}\n"
                            f"  HTTP Status: 200 OK\n"
                            f"  Debug indicators found: {', '.join(found)}\n"
                            f"  Page size: {len(resp.content)} bytes"
                        ),
                        'details': f"Debug interface accessible at '{path}' - exposes application internals, database queries, configuration and potentially allows code execution",
                        'recommendation': 'Immediately disable debug mode in production - restrict profiler access by IP - use environment variables to control debug settings'
                    })
                    if verbose:
                        print(f"  [!] CRITICAL: Debug mode accessible at {url}")
        except:
            pass

    # ================================================
    # CHECK 3 - Security Reporting Headers
    # ================================================
    if verbose:
        print("  [*] Checking security reporting headers...")

    try:
        resp = session.get(target, timeout=5, verify=False)
        headers = resp.headers

        reporting_headers = {
            'Report-To': 'Allows browser to report security violations to a collector endpoint',
            'NEL': 'Network Error Logging - monitors network-level failures',
            'Content-Security-Policy-Report-Only': 'CSP in report-only mode for monitoring violations',
        }

        missing_reporting = []
        for header, description in reporting_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing_reporting.append(header)

        if missing_reporting:
            results.append({
                'owasp': 'A09 - Security Logging and Monitoring Failures',
                'severity': 'LOW',
                'status': 'POTENTIAL',
                'title': 'Security reporting headers not configured',
                'evidence': (
                    f"GET {target}\n"
                    f"  Missing reporting headers: {', '.join(missing_reporting)}\n"
                    f"  These headers enable browser-level security monitoring"
                ),
                'details': 'Security reporting headers not configured - browser-level violations and network errors will not be reported to monitoring systems',
                'recommendation': 'Implement Report-To and NEL headers to collect browser security violation reports - set up a reporting endpoint'
            })
            if verbose:
                print(f"  [~] LOW: Missing security reporting headers: {', '.join(missing_reporting)}")

    except:
        pass

    # ================================================
    # CHECK 4 - Exposed Log Files
    # ================================================
    if verbose:
        print("  [*] Checking for exposed log files...")

    log_paths = [
        '/logs', '/log', '/error.log', '/access.log',
        '/app.log', '/application.log', '/debug.log',
        '/error_log', '/php_error.log', '/server.log',
        '/logs/error.log', '/logs/access.log',
        '/storage/logs/laravel.log',
        '/var/log/apache2/error.log',
        '/wp-content/debug.log',
    ]

    for path in log_paths:
        url = base + path
        try:
            resp = session.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.content) > 100:
                body = resp.text.lower()
                log_signs = [
                    'error', 'exception', 'warning',
                    'critical', 'debug', 'info',
                    'stack trace', 'traceback', 'fatal'
                ]
                if any(sign in body for sign in log_signs):
                    results.append({
                        'owasp': 'A09 - Security Logging and Monitoring Failures',
                        'severity': 'HIGH',
                        'status': 'VULNERABLE',
                        'title': f'Log file publicly accessible: {path}',
                        'evidence': (
                            f"GET {url}\n"
                            f"  HTTP Status: 200 OK\n"
                            f"  Content size: {len(resp.content)} bytes\n"
                            f"  Log content preview: {resp.text[:200].strip()}"
                        ),
                        'details': f"Log file at '{path}' is publicly accessible - may contain sensitive data including credentials, internal IPs, file paths and error details",
                        'recommendation': f"Immediately restrict access to '{path}' - move log files outside web root - configure server to block access to log files"
                    })
                    if verbose:
                        print(f"  [!] HIGH: Log file exposed at {url}")
        except:
            pass

    # ================================================
    # CHECK 5 - Response Time Analysis for Blind Issues
    # ================================================
    if verbose:
        print("  [*] Checking response time consistency...")

    try:
        times = []
        for _ in range(3):
            start = time.time()
            session.get(target, timeout=10, verify=False)
            times.append(time.time() - start)
            time.sleep(0.5)

        avg_time = sum(times) / len(times)
        if avg_time > 5:
            results.append({
                'owasp': 'A09 - Security Logging and Monitoring Failures',
                'severity': 'LOW',
                'status': 'POTENTIAL',
                'title': 'Slow server response time detected',
                'evidence': (
                    f"Average response time: {avg_time:.2f} seconds\n"
                    f"  Individual times: {', '.join([f'{t:.2f}s' for t in times])}"
                ),
                'details': 'Slow response times may indicate a server under load, misconfigured infrastructure or potential DoS vulnerability',
                'recommendation': 'Investigate server performance - implement monitoring and alerting for response time anomalies'
            })
            if verbose:
                print(f"  [~] LOW: Slow average response time: {avg_time:.2f}s")
        else:
            if verbose:
                print(f"  [+] Response time normal: {avg_time:.2f}s average")

    except:
        pass

    if not results:
        results.append({
            'owasp': 'A09 - Security Logging and Monitoring Failures',
            'severity': 'INFO',
            'status': 'SAFE',
            'title': 'No logging and monitoring failures detected',
            'evidence': 'No verbose errors, debug mode or exposed logs found',
            'details': 'Basic logging and monitoring checks passed',
            'recommendation': 'Implement centralised logging, set up alerts for suspicious activity and conduct regular log reviews'
        })
        if verbose:
            print("  [+] No logging and monitoring failures detected")

    return results