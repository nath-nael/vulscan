class HeadersScanner:
    def __init__(self):
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'HTTP Strict Transport Security (HSTS)',
                'severity': 'HIGH',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
            },
            'Content-Security-Policy': {
                'description': 'Content Security Policy (CSP)',
                'severity': 'HIGH',
                'recommendation': "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
            },
            'X-Frame-Options': {
                'description': 'Clickjacking Protection',
                'severity': 'MEDIUM',
                'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'MIME Type Sniffing Protection',
                'severity': 'MEDIUM',
                'recommendation': 'Add: X-Content-Type-Options: nosniff'
            },
            'X-XSS-Protection': {
                'description': 'XSS Filter (Legacy)',
                'severity': 'LOW',
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'description': 'Referrer Information Control',
                'severity': 'LOW',
                'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Browser Features Control',
                'severity': 'LOW',
                'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
            },
            'Cache-Control': {
                'description': 'Cache Control for Sensitive Pages',
                'severity': 'LOW',
                'recommendation': 'Add: Cache-Control: no-store, no-cache, must-revalidate'
            },
        }

    def scan(self, crawl_data, progress_callback=None):
        results = {
            'missing_headers': [],
            'misconfigured_headers': [],
            'information_headers': [],
            'cookie_issues': []
        }

        # Check main page headers
        for url, headers in crawl_data.get('response_headers', {}).items():
            if progress_callback:
                progress_callback(f"Analyzing headers for: {url}")

            # Check missing security headers
            for header_name, header_info in self.security_headers.items():
                if header_name not in headers:
                    results['missing_headers'].append({
                        'type': f'Missing Security Header: {header_name}',
                        'severity': header_info['severity'],
                        'url': url,
                        'header': header_name,
                        'description': f"{header_info['description']} header is missing",
                        'recommendation': header_info['recommendation']
                    })

            # Check for misconfigured headers
            misconfigs = self._check_misconfigurations(url, headers)
            results['misconfigured_headers'].extend(misconfigs)

            # Check for information disclosure headers
            info_headers = self._check_info_headers(url, headers)
            results['information_headers'].extend(info_headers)

        # Check cookie security
        for cookie_name, cookie_value in crawl_data.get('cookies', {}).items():
            cookie_issues = self._check_cookie_security(cookie_name, cookie_value)
            results['cookie_issues'].extend(cookie_issues)

        return results

    def _check_misconfigurations(self, url, headers):
        issues = []

        # Check CSP for unsafe directives
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy']
            unsafe_patterns = [
                ("'unsafe-inline'", "CSP allows unsafe-inline scripts", 'HIGH'),
                ("'unsafe-eval'", "CSP allows unsafe-eval", 'HIGH'),
                ("*", "CSP uses wildcard source", 'MEDIUM'),
                ("data:", "CSP allows data: URIs", 'MEDIUM'),
            ]
            for pattern, desc, severity in unsafe_patterns:
                if pattern in csp:
                    issues.append({
                        'type': 'Weak CSP Directive',
                        'severity': severity,
                        'url': url,
                        'header': 'Content-Security-Policy',
                        'value': csp[:200],
                        'issue': pattern,
                        'description': desc,
                        'recommendation': f"Remove '{pattern}' from CSP"
                    })

        # Check HSTS configuration
        if 'Strict-Transport-Security' in headers:
            hsts = headers['Strict-Transport-Security']
            if 'max-age' in hsts:
                import re
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        issues.append({
                            'type': 'Weak HSTS Configuration',
                            'severity': 'MEDIUM',
                            'url': url,
                            'header': 'Strict-Transport-Security',
                            'value': hsts,
                            'description': f'HSTS max-age is too short: {max_age}s',
                            'recommendation': 'Set max-age to at least 31536000 (1 year)'
                        })

        # Check CORS
        if 'Access-Control-Allow-Origin' in headers:
            cors = headers['Access-Control-Allow-Origin']
            if cors == '*':
                issues.append({
                    'type': 'Permissive CORS',
                    'severity': 'HIGH',
                    'url': url,
                    'header': 'Access-Control-Allow-Origin',
                    'value': cors,
                    'description': 'CORS allows all origins (*)',
                    'recommendation': 'Restrict CORS to specific trusted origins'
                })

        return issues

    def _check_info_headers(self, url, headers):
        info_issues = []

        disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version',
                             'X-Generator', 'Via', 'X-Backend-Server']

        for header in disclosure_headers:
            if header in headers:
                info_issues.append({
                    'type': 'Information Disclosure Header',
                    'severity': 'LOW',
                    'url': url,
                    'header': header,
                    'value': headers[header],
                    'description': f"Header '{header}' discloses server information",
                    'recommendation': f"Remove or obscure the '{header}' header"
                })

        return info_issues

    def _check_cookie_security(self, name, value):
        issues = []
        sensitive_names = ['session', 'auth', 'token', 'user', 'sid', 'login']

        if any(s in name.lower() for s in sensitive_names):
            issues.append({
                'type': 'Cookie Security Check',
                'severity': 'MEDIUM',
                'cookie_name': name,
                'description': f"Session cookie '{name}' - verify HttpOnly, Secure, and SameSite flags",
                'recommendation': 'Set HttpOnly=true, Secure=true, SameSite=Strict on session cookies'
            })

        return issues
