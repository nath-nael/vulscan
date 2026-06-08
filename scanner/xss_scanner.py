import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from .utils import get_headers

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '{{7*7}}',
]


def run_xss_scan(urls: list, session: requests.Session = None) -> list:
    findings = []
    sess = session or requests.Session()

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = sess.get(
                        test_url,
                        headers=get_headers(),
                        timeout=10,
                        verify=False
                    )

                    if payload in resp.text:
                        findings.append({
                            "type": "XSS - Reflected",
                            "severity": "High",
                            "url": test_url,
                            "detail": f"Reflected XSS in parameter '{param}'.",
                            "evidence": f"Payload reflected: {payload}",
                            "recommendation": "Encode all user input before rendering. Use Content-Security-Policy."
                        })
                        break

                except requests.RequestException:
                    continue

        # Also test forms
        try:
            resp = sess.get(url, headers=get_headers(), timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", url)
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")

                form_data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        form_data[name] = XSS_PAYLOADS[0]

                if not form_data:
                    continue

                try:
                    if method == "post":
                        r = sess.post(action, data=form_data, headers=get_headers(), timeout=10, verify=False)
                    else:
                        r = sess.get(action, params=form_data, headers=get_headers(), timeout=10, verify=False)

                    if XSS_PAYLOADS[0] in r.text:
                        findings.append({
                            "type": "XSS - Reflected (Form)",
                            "severity": "High",
                            "url": action,
                            "detail": "Reflected XSS via form submission.",
                            "evidence": f"Payload reflected: {XSS_PAYLOADS[0]}",
                            "recommendation": "Sanitize and encode all form inputs before rendering."
                        })
                except requests.RequestException:
                    continue

        except requests.RequestException:
            continue

    return findings
