import ssl
import socket
import datetime
from urllib.parse import urlparse
from .utils import Utils
import logging

logger = logging.getLogger(__name__)


class SSLScanner:
    def __init__(self, utils: Utils):
        self.utils = utils
        self.findings = []

    def scan(self, progress_callback=None) -> list:
        if progress_callback:
            progress_callback("Scanning SSL/TLS configuration...")

        parsed = urlparse(self.utils.target_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            self.findings.append(
                self.utils.create_finding(
                    vuln_type="SSL/TLS",
                    severity="Critical",
                    title="No HTTPS",
                    description="The website does not use HTTPS.",
                    url=self.utils.target_url,
                    evidence="URL uses HTTP scheme",
                    recommendation="Implement HTTPS with a valid SSL/TLS certificate.",
                )
            )
            return self.findings

        try:
            cert_info = self._get_certificate(hostname, port)
            if cert_info:
                self._check_certificate_expiry(cert_info, hostname)
                self._check_certificate_validity(cert_info, hostname)
                self._check_weak_signature(cert_info, hostname)
        except Exception as e:
            logger.error(f"SSL scan error: {e}")
            self.findings.append(
                self.utils.create_finding(
                    vuln_type="SSL/TLS",
                    severity="High",
                    title="SSL Certificate Error",
                    description=f"Could not retrieve SSL certificate: {str(e)}",
                    url=self.utils.target_url,
                    evidence=str(e),
                    recommendation="Ensure a valid SSL certificate is installed.",
                )
            )

        self._check_protocol_versions(hostname, port)
        self._check_http_redirect(hostname)
        return self.findings

    def _get_certificate(self, hostname: str, port: int) -> dict | None:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "cert": cert,
                        "cipher": cipher,
                        "version": version,
                    }
        except Exception as e:
            logger.error(f"Certificate retrieval error: {e}")
            return None

    def _check_certificate_expiry(self, cert_info: dict, hostname: str):
        cert = cert_info.get("cert", {})
        if not cert:
            return

        expire_date_str = cert.get("notAfter", "")
        if expire_date_str:
            try:
                expire_date = datetime.datetime.strptime(
                    expire_date_str, "%b %d %H:%M:%S %Y %Z"
                )
                days_until_expiry = (expire_date - datetime.datetime.utcnow()).days

                if days_until_expiry < 0:
                    self.findings.append(
                        self.utils.create_finding(
                            vuln_type="SSL/TLS",
                            severity="Critical",
                            title="SSL Certificate Expired",
                            description="The SSL certificate has expired.",
                            url=self.utils.target_url,
                            evidence=f"Certificate expired on: {expire_date_str}",
                            recommendation="Renew the SSL certificate immediately.",
                        )
                    )
                elif days_until_expiry < 30:
                    self.findings.append(
                        self.utils.create_finding(
                            vuln_type="SSL/TLS",
                            severity="High",
                            title="SSL Certificate Expiring Soon",
                            description=f"SSL certificate expires in {days_until_expiry} days.",
                            url=self.utils.target_url,
                            evidence=f"Certificate expires: {expire_date_str}",
                            recommendation="Renew the SSL certificate before it expires.",
                        )
                    )
                elif days_until_expiry < 90:
                    self.findings.append(
                        self.utils.create_finding(
                            vuln_type="SSL/TLS",
                            severity="Medium",
                            title="SSL Certificate Expiring",
                            description=f"SSL certificate expires in {days_until_expiry} days.",
                            url=self.utils.target_url,
                            evidence=f"Certificate expires: {expire_date_str}",
                            recommendation="Plan to renew the SSL certificate soon.",
                        )
                    )
            except ValueError as e:
                logger.error(f"Date parsing error: {e}")

    def _check_certificate_validity(self, cert_info: dict, hostname: str):
        cert = cert_info.get("cert", {})
        if not cert:
            return

        subject = dict(x[0] for x in cert.get("subject", []))
        san = cert.get("subjectAltName", [])
        san_domains = [s[1] for s in san if s[0] == "DNS"]

        if not san_domains:
            self.findings.append(
                self.utils.create_finding(
                    vuln_type="SSL/TLS",
                    severity="Medium",
                    title="No Subject Alternative Names",
                    description="Certificate has no Subject Alternative Names (SANs).",
                    url=self.utils.target_url,
                    evidence=f"Subject: {subject}",
                    recommendation="Use certificates with proper SAN entries.",
                )
            )

    def _check_weak_signature(self, cert_info: dict, hostname: str):
        cert = cert_info.get("cert", {})
        if not cert:
            return

        sig_alg = cert.get("signatureAlgorithm", "")
        if sig_alg and any(
            weak in sig_alg.lower() for weak in ["md5", "sha1"]
        ):
            self.findings.append(
                self.utils.create_finding(
                    vuln_type="SSL/TLS",
                    severity="High",
                    title="Weak Certificate Signature Algorithm",
                    description=f"Certificate uses weak signature algorithm: {sig_alg}",
                    url=self.utils.target_url,
                    evidence=f"Signature Algorithm: {sig_alg}",
                    recommendation="Use SHA-256 or stronger signature algorithm.",
                )
            )

    def _check_protocol_versions(self, hostname: str, port: int):
        weak_protocols = [
            ("SSLv2", ssl.PROTOCOL_TLS),
            ("SSLv3", ssl.PROTOCOL_TLS),
            ("TLSv1.0", ssl.PROTOCOL_TLS),
            ("TLSv1.1", ssl.PROTOCOL_TLS),
        ]

        for protocol_name, protocol in weak_protocols:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                if protocol_name == "TLSv1.0":
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1
                elif protocol_name == "TLSv1.1":
                    try:
                        context.minimum_version = ssl.TLSVersion.TLSv1_1
                        context.maximum_version = ssl.TLSVersion.TLSv1_1
                    except AttributeError:
                        continue

                with socket.create_connection(
                    (hostname, port), timeout=5
                ) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=hostname
                    ) as ssock:
                        self.findings.append(
                            self.utils.create_finding(
                                vuln_type="SSL/TLS",
                                severity="High",
                                title=f"Weak Protocol Supported: {protocol_name}",
                                description=f"Server supports deprecated protocol {protocol_name}.",
                                url=self.utils.target_url,
                                evidence=f"Successfully connected using {protocol_name}",
                                recommendation=f"Disable {protocol_name} and use TLS 1.2 or higher.",
                            )
                        )
            except Exception:
                pass

    def _check_http_redirect(self, hostname: str):
        http_url = f"http://{hostname}"
        try:
            response = self.utils.get(http_url)
            if response and response.url.startswith("http://"):
                self.findings.append(
                    self.utils.create_finding(
                        vuln_type="SSL/TLS",
                        severity="Medium",
                        title="No HTTP to HTTPS Redirect",
                        description="HTTP requests are not redirected to HTTPS.",
                        url=http_url,
                        evidence=f"HTTP request stayed at: {response.url}",
                        recommendation="Implement HTTP to HTTPS redirect.",
                    )
                )
        except Exception:
            pass
