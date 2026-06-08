import re
from .utils import safe_request

class CSRFScanner:
    def __init__(self):
        self.vulnerabilities = []

    def scan(self, crawl_data, progress_callback=None):
        results = {
            'missing_csrf_token': [],
            'weak_csrf_token': [],
            'missing_samesite': [],
            'vulnerable_forms': []
        }

        # Analyze forms for CSRF
        for form in crawl_data.get('forms', []):
            if progress_callback:
                progress_callback(f"CSRF scanning form: {form['action']}")

            if form['method'] == 'POST':
                vuln = self._analyze_form_csrf(form)
                if vuln:
                    results['missing_csrf_token'].append(vuln)

        # Analyze cookies for SameSite
        for cookie_name, cookie_value in crawl_data.get('cookies', {}).items():
            cookie_vuln = self._analyze_cookie(cookie_name, cookie_value)
            if cookie_vuln:
                results['missing_samesite'].append(cookie_vuln)

        # Check response headers
        for url, headers in crawl_data.get('response_headers', {}).items():
            header_vulns = self._analyze_headers_csrf(url, headers)
            results['missing_samesite'].extend(header_vulns)

        return results

    def _analyze_form_csrf(self, form):
        if not form['has_csrf_token']:
            # Check if it's a sensitive form
            sensitive_inputs = ['password', 'email', 'username', 'user', 'login',
                              'register', 'transfer', 'amount', 'payment', 'delete',
                              'update', 'edit', 'admin', 'account']

            form_inputs_str = ' '.join([i['name'].lower() for i in form['inputs']])
            form_action_str = form['action'].lower()

            is_sensitive = any(s in form_inputs_str or s in form_action_str 
                             for s in sensitive_inputs)

            severity = 'HIGH' if is_sensitive else 'MEDIUM'

            return {
                'type': 'Missing CSRF Token',
                'severity': severity,
                'url': form['action'],
                'method': form['method'],
                'form_inputs': [i['name'] for i in form['inputs'] if i['name']],
                'is_sensitive': is_sensitive,
                'description': f"POST form at {form['action']} lacks CSRF protection",
                'recommendation': 'Add CSRF token to all state-changing forms'
            }
        else:
            # Check for weak CSRF tokens
            for input_field in form['inputs']:
                if any(t in input_field['name'].lower() for t in ['csrf', 'token', 'nonce']):
                    token_value = input_field.get('value', '')
                    if token_value and self._is_weak_token(token_value):
                        return {
                            'type': 'Weak CSRF Token',
                            'severity': 'MEDIUM',
                            'url': form['action'],
                            'token_name': input_field['name'],
                            'token_value': token_value[:20] + '...',
                            'description': 'CSRF token appears to be weak or predictable',
                            'recommendation': 'Use cryptographically secure random tokens'
                        }
        return None

    def _is_weak_token(self, token):
        # Check if token is too short
        if len(token) < 16:
            return True
        # Check if token is sequential or simple
        if re.match(r'^[0-9]+$', token):
            return True
        # Check if token is common weak value
        weak_tokens = ['undefined', 'null', 'true', 'false', '0', '1', 'token']
        if token.lower() in weak_tokens:
            return True
        return False

    def _analyze_cookie(self, name, value):
        sensitive_names = ['session', 'auth', 'token', 'user', 'login', 'sid', 'ssid']
        if any(s in name.lower() for s in sensitive_names):
            return {
                'type': 'Cookie Missing SameSite',
                'severity': 'MEDIUM',
                'cookie_name': name,
                'description': f"Session cookie '{name}' may be missing SameSite attribute",
                'recommendation': 'Set SameSite=Strict or SameSite=Lax on session cookies'
            }
        return None

    def _analyze_headers_csrf(self, url, headers):
        vulnerabilities = []

        # Check for missing CORS headers that could enable CSRF
        if 'Access-Control-Allow-Origin' in headers:
            if headers['Access-Control-Allow-Origin'] == '*':
                vulnerabilities.append({
                    'type': 'Permissive CORS Policy',
                    'severity': 'HIGH',
                    'url': url,
                    'header': 'Access-Control-Allow-Origin: *',
                    'description': 'Wildcard CORS policy allows any origin to make requests',
                    'recommendation': 'Restrict CORS to specific trusted origins'
                })

        return vulnerabilities
