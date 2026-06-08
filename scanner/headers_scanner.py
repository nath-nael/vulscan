from .utils import Utils
import logging

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces secure (HTTPS) connections to the server.",
        "severity": "High",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks.",
        "severity": "High",
        "recommendation": "Implement a strict Content-Security-Policy header.",
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks.",
        "severity": "Medium",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing.",
        "severity": "Medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests.",
        "severity": "Low",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "description": "Controls browser features and APIs.",
        "severity": "Low",
        "recommendation": "Implement Permissions-Policy to restrict unnecessary browser features.",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still checked).",
        "severity": "Low",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' for legacy browser support.",
    },
    "Cache-Control": {
        "description": "Controls caching behavior.",
        "severity": "Low",
        "recommendation": "Add appropriate Cache-Control headers for sensitive pages.",
    },
}

INSECURE_HEADERS = {
    "Server": {
        "description": "Reveals server software information.",
        "severity": "Low",
        "recommendation": "Remove or obscure the Server header to prevent information disclosure.",
    },
    "X-Powered-By": {
        "description": "Reveals technology stack information.",
        "severity": "Low",
        "recommendation": "Remove the X-Powered-By header.",
    },
    "X-AspNet-Version": {
        "description": "Reveals ASP.NET version information.",
        "severity": "Low",
        "recommendation": "Remove the X-AspNet-Version header.",
    },
    "X-AspNetMvc-Version": {
        "description": "Reveals ASP.NET MVC version.",
        "severity": "Low",
        "recommendation": "Remove the X-AspNetMvc-Version header.",
    },
}


class HeadersScanner:
    def __init__(self, utils: Utils):
        self.utils = utils
        self.findings = []

    def scan(self, progress_callback=None) -> list:
        if progress_callback:
            progress_callback("Scanning security headers...")

        response = self.utils.get(self.utils.target_url)
        if not response:
            return []

        headers = {k.lower(): v for k, v in response.headers.items()}
        self._check_missing_headers(headers, response.url)
        self._check_insecure_headers(response.headers, response.url)
        self._check_cookie_security(response, response.url)
        self._check_cors(response.headers, response.url)
        return self.findings

    def _check_missing_headers(self, headers: dict, url: str):
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="Missing Security Header",
                        severity=info["severity"],
                        title=f"Missing Header: {header}",
                        description=info["description"],
                        url=url,
                        evidence=f"Header '{header}' not found in response",
                        recommendation=info["recommendation"],
                    )
                )
            else:
                self._validate_header_value(
                    header, headers[header.lower()], url
                )

    def _validate_header_value(self, header: str, value: str, url: str):
        if header == "Strict-Transport-Security":
            if "max-age" not in value.lower():
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="Misconfigured Header",
                        severity="Medium",
                        title="Weak HSTS Configuration",
                        description="HSTS header is present but may be misconfigured.",
                        url=url,
                        evidence=f"Strict-Transport-Security: {value}",
                        recommendation="Ensure max-age is set to at least 31536000.",
                    )
                )
        elif header == "X-Frame-Options":
            if value.upper() not in ["DENY", "SAMEORIGIN"]:
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="Misconfigured Header",
                        severity="Medium",
                        title="Weak X-Frame-Options Configuration",
                        description="X-Frame-Options has an invalid or weak value.",
                        url=url,
                        evidence=f"X-Frame-Options: {value}",
                        recommendation="Use 'DENY' or 'SAMEORIGIN'.",
                    )
                )
        elif header == "Content-Security-Policy":
            weak_directives = ["unsafe-inline", "unsafe-eval", "*"]
            for directive in weak_directives:
                if directive in value:
                    self.findings.append(
                        self.utils.create_finding(
                            vuln_type="Misconfigured Header",
                            severity="Medium",
                            title="Weak Content-Security-Policy",
                            description=f"CSP contains potentially unsafe directive: {directive}",
                            url=url,
                            evidence=f"Content-Security-Policy: {value}",
                            recommendation="Avoid using unsafe-inline, unsafe-eval, or wildcard (*) in CSP.",
                        )
                    )
                    break

    def _check_insecure_headers(self, headers: dict, url: str):
        for header, info in INSECURE_HEADERS.items():
            if header in headers:
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="Information Disclosure Header",
                        severity=info["severity"],
                        title=f"Information Disclosure: {header}",
                        description=info["description"],
                        url=url,
                        evidence=f"{header}: {headers[header]}",
                        recommendation=info["recommendation"],
                    )
                )

    def _check_cookie_security(self, response, url: str):
        for cookie in response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite attribute")

            if issues:
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="Insecure Cookie",
                        severity="Medium",
                        title=f"Insecure Cookie: {cookie.name}",
                        description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                        url=url,
                        evidence=f"Cookie: {cookie.name}={cookie.value[:20]}...",
                        recommendation="Set Secure, HttpOnly, and SameSite=Strict flags on all cookies.",
                    )
                )

    def _check_cors(self, headers: dict, url: str):
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            self.findings.append(
                self.utils.create_finding(
                    vuln_type="CORS Misconfiguration",
                    severity="High",
                    title="Wildcard CORS Policy",
                    description="The server allows requests from any origin (*).",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    recommendation="Restrict CORS to specific trusted origins.",
                )
            )
