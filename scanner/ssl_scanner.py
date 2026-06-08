import ssl
import socket
import requests
import datetime
from urllib.parse import urlparse
from .utils import get_headers

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "ADH", "AECDH", "EXP"
]


def get_cert_info(hostname: str, port: int = 443) -> dict:
    """Retrieve SSL certificate details."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
                return {
                    "cert": cert,
                    "protocol": protocol,
                    "cipher": cipher,
                    "error": None
                }
    except ssl.SSLCertVerificationError as e:
        return {"cert": None, "protocol": None, "cipher": None, "error": f"Cert verification failed: {e}"}
    except ssl.SSLError as e:
        return {"cert": None, "protocol": None, "cipher": None, "error": f"SSL error: {e}"}
    except Exception as e:
        return {"cert": None, "protocol": None, "cipher": None, "error": str(e)}


def check_cert_expiry(cert: dict) -> tuple:
    """Check if certificate is expired or expiring soon."""
    try:
        not_after = cert.get("notAfter", "")
        expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        days_left = (expire_date - now).days
        return expire_date, days_left
    except Exception:
        return None, None


def check_weak_protocol(protocol: str) -> bool:
    return any(weak in protocol for weak in WEAK_PROTOCOLS) if protocol else False


def check_weak_cipher(cipher: tuple) -> bool:
    if not cipher:
        return False
    cipher_name = cipher[0] if cipher else ""
    return any(weak in cipher_name for weak in WEAK_CIPHERS)


def check_hsts(url: str) -> bool:
    """Check if HSTS header is present."""
    try:
        resp = requests.get(url, headers=get_headers(), timeout=10, verify=False)
        return "strict-transport-security" in {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return False


def check_http_redirect(hostname: str) -> bool:
    """Check if HTTP redirects to HTTPS."""
    try:
        resp = requests.get(
            f"http://{hostname}",
            headers=get_headers(),
            timeout=10,
            allow_redirects=True,
            verify=False
        )
        return resp.url.startswith("https://")
    except Exception:
        return False


def check_self_signed(cert: dict) -> bool:
    """Detect self-signed certificates."""
    if not cert:
        return False
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    return issuer == subject


def run_ssl_scan(target_url: str) -> list:
    """Run all SSL/TLS checks."""
    findings = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme != "https":
        findings.append({
            "type": "SSL/TLS - No HTTPS",
            "severity": "High",
            "url": target_url,
            "detail": "Target is not using HTTPS.",
            "evidence": f"Scheme: {parsed.scheme}",
            "recommendation": "Enforce HTTPS across the entire site."
        })
        return findings

    info = get_cert_info(hostname, port)

    # Connection error
    if info["error"]:
        findings.append({
            "type": "SSL/TLS - Connection Error",
            "severity": "High",
            "url": target_url,
            "detail": "Could not establish SSL connection.",
            "evidence": info["error"],
            "recommendation": "Ensure the server has a valid SSL/TLS configuration."
        })
        return findings

    cert = info["cert"]
    protocol = info["protocol"]
    cipher = info["cipher"]

    # Certificate expiry
    expire_date, days_left = check_cert_expiry(cert)
    if days_left is not None:
        if days_left < 0:
            findings.append({
                "type": "SSL/TLS - Expired Certificate",
                "severity": "Critical",
                "url": target_url,
                "detail": f"SSL certificate expired {abs(days_left)} days ago.",
                "evidence": f"Expiry: {expire_date}",
                "recommendation": "Renew the SSL certificate immediately."
            })
        elif days_left < 30:
            findings.append({
                "type": "SSL/TLS - Certificate Expiring Soon",
                "severity": "Medium",
                "url": target_url,
                "detail": f"SSL certificate expires in {days_left} days.",
                "evidence": f"Expiry: {expire_date}",
                "recommendation": "Renew the SSL certificate before it expires."
            })

    # Self-signed
    if check_self_signed(cert):
        findings.append({
            "type": "SSL/TLS - Self-Signed Certificate",
            "severity": "High",
            "url": target_url,
            "detail": "Certificate is self-signed and not trusted by browsers.",
            "evidence": f"Issuer == Subject",
            "recommendation": "Use a certificate from a trusted Certificate Authority (CA)."
        })

    # Weak protocol
    if check_weak_protocol(protocol):
        findings.append({
            "type": "SSL/TLS - Weak Protocol",
            "severity": "High",
            "url": target_url,
            "detail": f"Weak protocol in use: {protocol}",
            "evidence": f"Protocol: {protocol}",
            "recommendation": "Disable TLS 1.0/1.1 and SSLv2/v3. Use TLS 1.2 or TLS 1.3 only."
        })

    # Weak cipher
    if check_weak_cipher(cipher):
        findings.append({
            "type": "SSL/TLS - Weak Cipher",
            "severity": "High",
            "url": target_url,
            "detail": f"Weak cipher suite in use.",
            "evidence": f"Cipher: {cipher[0] if cipher else 'Unknown'}",
            "recommendation": "Disable weak cipher suites. Use AES-GCM or ChaCha20-Poly1305."
        })

    # HSTS
    if not check_hsts(target_url):
        findings.append({
            "type": "SSL/TLS - Missing HSTS",
            "severity": "Medium",
            "url": target_url,
            "detail": "HTTP Strict Transport Security (HSTS) header is missing.",
            "evidence": "Strict-Transport-Security header not found.",
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
        })

    # HTTP to HTTPS redirect
    if not check_http_redirect(hostname):
        findings.append({
            "type": "SSL/TLS - No HTTP to HTTPS Redirect",
            "severity": "Medium",
            "url": target_url,
            "detail": "HTTP traffic is not redirected to HTTPS.",
            "evidence": f"http://{hostname} does not redirect to https://",
            "recommendation": "Configure your server to redirect all HTTP traffic to HTTPS."
        })

    # All good message
    if not findings:
        findings.append({
            "type": "SSL/TLS - OK",
            "severity": "Info",
            "url": target_url,
            "detail": f"SSL/TLS configuration looks good. Protocol: {protocol}, Cipher: {cipher[0] if cipher else 'N/A'}",
            "evidence": f"Certificate valid for {days_left} more days.",
            "recommendation": "Continue monitoring certificate expiry."
        })

    return findings
