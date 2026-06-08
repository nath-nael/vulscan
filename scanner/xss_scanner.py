from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from .utils import Utils
import logging
import re

logger = logging.getLogger(__name__)

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<IMG SRC=javascript:alert('XSS')>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "';alert('XSS');//",
    "\"><img src=x onerror=alert('XSS')>",
    "<details/open/ontoggle=alert('XSS')>",
]

DOM_XSS_SOURCES = [
    "document.URL",
    "document.documentURI",
    "document.location",
    "document.referrer",
    "window.location",
    "location.href",
    "location.search",
    "location.hash",
]

DOM_XSS_SINKS = [
    "document.write",
    "document.writeln",
    "innerHTML",
    "outerHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "execScript",
    "document.execCommand",
]


class XSSScanner:
    def __init__(self, utils: Utils, forms: list = None):
        self.utils = utils
        self.forms = forms or []
        self.findings = []
        self.tested_urls = set()

    def scan(self, progress_callback=None) -> list:
        if progress_callback:
            progress_callback("Scanning for XSS vulnerabilities...")

        self._scan_forms(progress_callback)
        self._scan_url_parameters(progress_callback)
        self._scan_dom_xss(progress_callback)
        return self.findings

    def _scan_forms(self, progress_callback=None):
        for form in self.forms:
            if progress_callback:
                progress_callback(f"Testing XSS in form at: {form.get('url', '')}")

            action = form.get("action", "")
            method = form.get("method", "get")
            base_url = form.get("url", self.utils.target_url)
            target_url = self.utils.normalize_url(action, base_url) if action else base_url

            for payload in XSS_PAYLOADS[:5]:
                form_data = {}
                for inp in form.get("inputs", []):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    input_type = inp.get("type", "text").lower()
                    if input_type in ["text", "search", "email", "url", "textarea", ""]:
                        form_data[name] = payload
                    elif input_type == "hidden":
                        form_data[name] = inp.get("value", "")
                    else:
                        form_data[name] = inp.get("value", "test")

                if not form_data:
                    continue

                if method == "post":
                    response = self.utils.post(target_url, form_data)
                else:
                    response = self.utils.get(target_url, params=form_data)

                if response and self._check_reflection(payload, response.text):
                    self.findings.append(
                        self.utils.create_finding(
                            vuln_type="XSS",
                            severity="High",
                            title="Reflected XSS Vulnerability",
                            description="User input is reflected in the response without proper sanitization.",
                            url=target_url,
                            evidence=f"Payload reflected: {payload[:100]}",
                            recommendation="Implement proper input validation and output encoding. Use Content-Security-Policy.",
                        )
                    )
                    break
                self.utils.rate_limit(0.3)

    def _scan_url_parameters(self, progress_callback=None):
        response = self.utils.get(self.utils.target_url)
        if not response:
            return

        soup = BeautifulSoup(response.text, "lxml")
        links_with_params = []

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = self.utils.normalize_url(href, self.utils.target_url)
            if full_url and "?" in full_url and self.utils.is_same_domain(full_url):
                links_with_params.append(full_url)

        for url in links_with_params[:10]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                for payload in XSS_PAYLOADS[:3]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                    if progress_callback:
                        progress_callback(f"Testing XSS parameter: {param_name}")

                    response = self.utils.get(test_url, params=test_params)
                    if response and self._check_reflection(payload, response.text):
                        self.findings.append(
                            self.utils.create_finding(
                                vuln_type="XSS",
                                severity="High",
                                title="Reflected XSS in URL Parameter",
                                description=f"Parameter '{param_name}' is vulnerable to XSS.",
                                url=test_url,
                                evidence=f"Parameter: {param_name}, Payload: {payload[:100]}",
                                recommendation="Sanitize and encode all URL parameters before reflecting them in responses.",
                            )
                        )
                        break
                    self.utils.rate_limit(0.3)

    def _scan_dom_xss(self, progress_callback=None):
        if progress_callback:
            progress_callback("Checking for DOM-based XSS patterns...")

        response = self.utils.get(self.utils.target_url)
        if not response:
            return

        soup = BeautifulSoup(response.text, "lxml")
        scripts = soup.find_all("script")

        for script in scripts:
            script_content = script.string or ""
            if not script_content:
                continue

            sources_found = [s for s in DOM_XSS_SOURCES if s in script_content]
            sinks_found = [s for s in DOM_XSS_SINKS if s in script_content]

            if sources_found and sinks_found:
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="XSS",
                        severity="Medium",
                        title="Potential DOM-based XSS",
                        description="JavaScript code uses user-controllable sources with dangerous sinks.",
                        url=self.utils.target_url,
                        evidence=f"Sources: {sources_found}, Sinks: {sinks_found}",
                        recommendation="Avoid using user-controlled data in dangerous JavaScript sinks. Use safe DOM APIs.",
                    )
                )

    def _check_reflection(self, payload: str, response_text: str) -> bool:
        return payload.lower() in response_text.lower()
