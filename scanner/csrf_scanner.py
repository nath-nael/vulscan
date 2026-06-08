from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .utils import Utils
import logging
import re

logger = logging.getLogger(__name__)

CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf",
    "xsrftoken", "_token", "authenticity_token",
    "csrfmiddlewaretoken", "requestverificationtoken",
    "__requestverificationtoken", "antiforgery",
]


class CSRFScanner:
    def __init__(self, utils: Utils, forms: list = None):
        self.utils = utils
        self.forms = forms or []
        self.findings = []

    def scan(self, progress_callback=None) -> list:
        if progress_callback:
            progress_callback("Scanning for CSRF vulnerabilities...")

        self._scan_forms(progress_callback)
        self._check_samesite_cookies(progress_callback)
        self._check_custom_headers(progress_callback)
        return self.findings

    def _scan_forms(self, progress_callback=None):
        post_forms = [f for f in self.forms if f.get("method") == "post"]

        if not post_forms:
            if progress_callback:
                progress_callback("No POST forms found for CSRF testing.")
            return

        for form in post_forms:
            if progress_callback:
                progress_callback(f"Checking CSRF protection in form at: {form.get('url', '')}")

            has_csrf = form.get("has_csrf_token", False)

            if not has_csrf:
                has_csrf = self._check_inputs_for_csrf(form.get("inputs", []))

            if not has_csrf:
                has_csrf = self._check_meta_csrf(form.get("url", ""))

            if not has_csrf:
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="CSRF",
                        severity="High",
                        title="Missing CSRF Protection",
                        description=(
                            "A POST form was found without CSRF token protection. "
                            "This could allow attackers to perform unauthorized actions on behalf of users."
                        ),
                        url=form.get("url", self.utils.target_url),
                        evidence=(
                            f"Form action: {form.get('action', 'N/A')}, "
                            f"Method: {form.get('method', 'N/A')}, "
                            f"No CSRF token found in inputs"
                        ),
                        recommendation=(
                            "Implement CSRF tokens in all state-changing forms. "
                            "Use the SameSite cookie attribute and verify Origin/Referer headers."
                        ),
                    )
                )
            else:
                self._check_csrf_token_strength(form)

    def _check_inputs_for_csrf(self, inputs: list) -> bool:
        for inp in inputs:
            name = inp.get("name", "").lower()
            inp_id = inp.get("id", "").lower()
            if any(token in name for token in CSRF_TOKEN_NAMES):
                return True
            if any(token in inp_id for token in CSRF_TOKEN_NAMES):
                return True
        return False

    def _check_meta_csrf(self, url: str) -> bool:
        response = self.utils.get(url or self.utils.target_url)
        if not response:
            return False

        soup = BeautifulSoup(response.text, "lxml")
        for meta in soup.find_all("meta"):
            name = meta.get("name", "").lower()
            if any(token in name for token in CSRF_TOKEN_NAMES):
                return True

        for header_name in response.headers:
            if any(token in header_name.lower() for token in CSRF_TOKEN_NAMES):
                return True

        return False

    def _check_csrf_token_strength(self, form: dict):
        for inp in form.get("inputs", []):
            name = inp.get("name", "").lower()
            if any(token in name for token in CSRF_TOKEN_NAMES):
                value = inp.get("value", "")
                if len(value) < 16:
                    self.findings.append(
                        self.utils.create_finding(
                            vuln_type="CSRF",
                            severity="Medium",
                            title="Weak CSRF Token",
                            description="CSRF token appears to be too short or weak.",
                            url=form.get("url", self.utils.target_url),
                            evidence=f"Token length: {len(value)} characters",
                            recommendation="Use cryptographically secure random tokens of at least 32 characters.",
                        )
                    )
                if value and self._is_predictable(value):
                    self.findings.append(
                        self.utils.create_finding(
                            vuln_type="CSRF",
                            severity="High",
                            title="Predictable CSRF Token",
                            description="CSRF token appears to be predictable or sequential.",
                            url=form.get("url", self.utils.target_url),
                            evidence=f"Token value: {value[:20]}...",
                            recommendation="Use cryptographically secure random token generation.",
                        )
                    )

    def _is_predictable(self, token: str) -> bool:
        if token.isdigit():
            return True
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    token, re.IGNORECASE):
            return False
        sequential_patterns = [
            r"^(0+)$",
            r"^(1+)$",
            r"^(123)+$",
            r"^(abc)+$",
        ]
        for pattern in sequential_patterns:
            if re.match(pattern, token, re.IGNORECASE):
                return True
        return False

    def _check_samesite_cookies(self, progress_callback=None):
        if progress_callback:
            progress_callback("Checking SameSite cookie attributes...")

        response = self.utils.get(self.utils.target_url)
        if not response:
            return

        for cookie in response.cookies:
            samesite = cookie._rest.get("SameSite", "").lower() if hasattr(cookie, "_rest") else ""
            if not samesite:
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="CSRF",
                        severity="Medium",
                        title=f"Cookie Missing SameSite Attribute: {cookie.name}",
                        description=(
                            f"Cookie '{cookie.name}' does not have the SameSite attribute, "
                            "which helps prevent CSRF attacks."
                        ),
                        url=self.utils.target_url,
                        evidence=f"Cookie: {cookie.name}",
                        recommendation="Set SameSite=Strict or SameSite=Lax on all cookies.",
                    )
                )

    def _check_custom_headers(self, progress_callback=None):
        if progress_callback:
            progress_callback("Checking CSRF header protections...")

        response = self.utils.get(self.utils.target_url)
        if not response:
            return

        headers = {k.lower(): v for k, v in response.headers.items()}
        has_protection = (
            "x-frame-options" in headers
            or "content-security-policy" in headers
        )

        if not has_protection:
            self.findings.append(
                self.utils.create_finding(
                    vuln_type="CSRF",
                    severity="Low",
                    title="No Additional CSRF Header Protections",
                    description="No X-Frame-Options or CSP headers found that could help prevent CSRF.",
                    url=self.utils.target_url,
                    evidence="Missing X-Frame-Options and Content-Security-Policy headers",
                    recommendation="Implement X-Frame-Options and Content-Security-Policy headers as defense-in-depth.",
                )
            )
