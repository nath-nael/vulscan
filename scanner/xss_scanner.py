import re
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from .utils import safe_request

class XSSScanner:
    def __init__(self):
        self.vulnerabilities = []

        # XSS Payloads
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=\"javascript:alert('XSS')\">",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "';alert('XSS')//",
            "\";alert('XSS')//",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "<input type=\"text\" value=\"`\" onfocus=\"alert('XSS')\">",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\">",
            "<a href=\"javascript:alert('XSS')\">Click Me</a>",
            "<div style=\"background-image: url(javascript:alert('XSS'))\">",
            "<STYLE>@import'javascript:alert(\"XSS\")';</STYLE>",
            "<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->",
            "<BASE HREF=\"javascript:alert('XSS');//\">",
        ]

        # DOM-based XSS patterns
        self.dom_patterns = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'document\.location',
            r'window\.location',
            r'location\.href',
            r'location\.hash',
            r'location\.search',
            r'document\.URL',
            r'document\.referrer',
            r'\.src\s*=',
            r'\.href\s*=',
        ]

    def scan(self, crawl_data, progress_callback=None):
        results = {
            'reflected_xss': [],
            'stored_xss_indicators': [],
            'dom_xss': [],
            'vulnerable_params': [],
            'vulnerable_forms': []
        }

        # Scan URL parameters
        for url, params in crawl_data.get('parameters', {}).items():
            if progress_callback:
                progress_callback(f"XSS scanning URL params: {url}")

            param_vulns = self._scan_url_params(url, params)
            results['reflected_xss'].extend(param_vulns)

        # Scan forms
        for form in crawl_data.get('forms', []):
            if progress_callback:
                progress_callback(f"XSS scanning form: {form['action']}")

            form_vulns = self._scan_form(form)
            results['vulnerable_forms'].extend(form_vulns)

        # Scan for DOM XSS in scripts
        for script in crawl_data.get('scripts', []):
            dom_vulns = self._scan_dom_xss(script)
            results['dom_xss'].extend(dom_vulns)

        return results

    def _scan_url_params(self, url, params_string):
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            for payload in self.payloads[:10]:  # Limit for speed
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload

                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                response = safe_request(test_url)

                if response and payload in response.text:
                    vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"Payload reflected in response",
                        'description': f"Parameter '{param_name}' reflects user input without sanitization"
                    })
                    break  # Found vulnerability, move to next param

        return vulnerabilities

    def _scan_form(self, form):
        vulnerabilities = []

        for payload in self.payloads[:8]:
            form_data = {}

            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] in ['text', 'search', 'email', 'url', 'textarea', '']:
                        form_data[input_field['name']] = payload
                    elif input_field['type'] == 'hidden':
                        form_data[input_field['name']] = input_field['value'] or payload
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'

            if not form_data:
                continue

            response = safe_request(
                form['action'],
                method=form['method'],
                data=form_data
            )

            if response and payload in response.text:
                vulnerabilities.append({
                    'type': 'Form XSS',
                    'severity': 'HIGH',
                    'url': form['action'],
                    'method': form['method'],
                    'payload': payload,
                    'form_inputs': [i['name'] for i in form['inputs'] if i['name']],
                    'evidence': 'Payload reflected in form response',
                    'description': f"Form at {form['action']} reflects XSS payload"
                })
                break

        return vulnerabilities

    def _scan_dom_xss(self, script):
        vulnerabilities = []
        content = script.get('content', '')

        if not content:
            return vulnerabilities

        for pattern in self.dom_patterns:
            matches = re.findall(pattern, content)
            if matches:
                # Check if user input flows into dangerous sink
                context_lines = []
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        start = max(0, i-2)
                        end = min(len(lines), i+3)
                        context_lines.append('\n'.join(lines[start:end]))

                vulnerabilities.append({
                    'type': 'DOM XSS Indicator',
                    'severity': 'MEDIUM',
                    'source': script.get('source', ''),
                    'script_src': script.get('src', 'inline'),
                    'pattern': pattern,
                    'occurrences': len(matches),
                    'context': context_lines[:3],
                    'description': f"Dangerous DOM manipulation pattern found: {pattern}"
                })

        return vulnerabilities
