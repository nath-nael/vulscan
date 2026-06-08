import requests
import re
from urllib.parse import urlparse
from .utils import get_headers

# Patterns for sensitive information
SENSITIVE_PATTERNS = {
    "Email Address": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    "IP Address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?i)aws(.{0,20})?secret(.{0,20})?[\'"\s:=]+([A-Za-z0-9/+=]{40})',
    "Private Key Block": r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "GitHub Token": r'ghp_[0-9a-zA-Z]{36}',
    "JWT Token": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    "Basic Auth in URL": r'https?://[^:]+:[^@]+@',
    "Phone Number": r'\b(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
    "Credit Card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    "Password in HTML": r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]?[^\s\'"]{4,}',
    "Internal Path": r'(?i)(\/home\/|\/var\/|\/etc\/|C:\\Users\\|C:\\Windows\\)',
    "Stack Trace": r'(?i)(traceback|stack trace|at [a-zA-Z0-9_.]+\([a-zA-Z0-9_.]+\.java:\d+\))',
    "SQL Error": r'(?i)(sql syntax|mysql_fetch|ORA-\d{5}|sqlite_error|pg_query|SQLSTATE)',
    "PHP Error": r'(?i)(fatal error|parse error|warning:.*php)',
    "Debug Info": r'(?i)(debug|var_dump|console\.log|print_r\()',
    "Version Disclosure": r'(?i)(apache\/\d|nginx\/\d|php\/\d|openssl\/\d|iis\/\d)',
    "Social Security Number": r'\b\d{3}-\d{2}-\d{4}\b',
    "Bearer Token": r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*',
    "API Key Generic": r'(?i)(api[_-]?key|apikey)\s*[=:]\s*[\'"]?[a-zA-Z0-9]{16,}',
}

# Sensitive files to check
SENSITIVE_FILES = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/config.php",
    "/wp-config.php",
    "/config.yml",
    "/config.yaml",
    "/settings.py",
    "/database.yml",
    "/secrets.yml",
    "/.htpasswd",
    "/.htaccess",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/admin/config.php",
    "/composer.json",
    "/package.json",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.dockerenv",
    "/proc/self/environ",
    "/server-status",
    "/server-info",
    "/.bash_history",
    "/.ssh/id_rsa",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/error_log",
    "/access_log",
    "/debug.log",
]

# Sensitive response headers
SENSITIVE_HEADERS = [
    "X-Powered-By",
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "X-Backend-Server",
    "X-CF-Powered-By",
]


def scan_page_content(url: str, html_content: str) -> list:
    """Scan page HTML content for sensitive information patterns."""
    findings = []

    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, html_content)
        if matches:
            unique_matches = list(set(
                [m if isinstance(m, str) else m[0] for m in matches]
            ))[:5]  # Limit to 5 examples
            findings.append({
                "type": "Info Leakage - Content",
                "severity": _get_severity(pattern_name),
                "url": url,
                "detail": f"Pattern '{pattern_name}' found in page content.",
                "evidence": f"Matches (up to 5): {unique_matches}",
                "recommendation": f"Remove or mask sensitive data matching '{pattern_name}' from public-facing pages."
            })

    return findings


def scan_sensitive_files(base_url: str, session: requests.Session = None) -> list:
    """Check for exposed sensitive files."""
    findings = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    sess = session or requests.Session()

    for path in SENSITIVE_FILES:
        target_url = base + path
        try:
            resp = sess.get(
                target_url,
                headers=get_headers(),
                timeout=8,
                allow_redirects=False,
                verify=False
            )
            if resp.status_code == 200 and len(resp.text) > 0:
                severity = _file_severity(path)
                findings.append({
                    "type": "Info Leakage - Sensitive File",
                    "severity": severity,
                    "url": target_url,
                    "detail": f"Sensitive file accessible: {path}",
                    "evidence": f"HTTP {resp.status_code} | Size: {len(resp.content)} bytes | Snippet: {resp.text[:100].strip()}",
                    "recommendation": f"Restrict access to '{path}' via server configuration or remove it from the web root."
                })
        except requests.RequestException:
            continue

    return findings


def scan_response_headers(url: str, session: requests.Session = None) -> list:
    """Check response headers for information disclosure."""
    findings = []
    sess = session or requests.Session()

    try:
        resp = sess.get(
            url,
            headers=get_headers(),
            timeout=10,
            verify=False
        )
        response_headers = dict(resp.headers)

        for header in SENSITIVE_HEADERS:
            if header.lower() in {k.lower(): v for k, v in response_headers.items()}:
                value = next(
                    v for k, v in response_headers.items()
                    if k.lower() == header.lower()
                )
                findings.append({
                    "type": "Info Leakage - Response Header",
                    "severity": "Low",
                    "url": url,
                    "detail": f"Header '{header}' discloses server information.",
                    "evidence": f"{header}: {value}",
                    "recommendation": f"Remove or obscure the '{header}' header in your server configuration."
                })

        # Check for directory listing hints
        if "Index of /" in resp.text or "Directory listing" in resp.text:
            findings.append({
                "type": "Info Leakage - Directory Listing",
                "severity": "Medium",
                "url": url,
                "detail": "Directory listing appears to be enabled.",
                "evidence": "Page contains 'Index of /' or 'Directory listing'",
                "recommendation": "Disable directory listing in your web server configuration."
            })

    except requests.RequestException as e:
        findings.append({
            "type": "Info Leakage - Error",
            "severity": "Info",
            "url": url,
            "detail": "Could not retrieve response headers.",
            "evidence": str(e),
            "recommendation": "Ensure the target URL is accessible."
        })

    return findings


def scan_comments(url: str, html_content: str) -> list:
    """Scan HTML comments for sensitive information."""
    findings = []
    comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
    comments = comment_pattern.findall(html_content)

    sensitive_keywords = [
        "password", "passwd", "secret", "token", "api_key",
        "apikey", "todo", "fixme", "hack", "bug", "credentials",
        "username", "admin", "debug", "test", "private"
    ]

    for comment in comments:
        comment_lower = comment.lower()
        matched_keywords = [kw for kw in sensitive_keywords if kw in comment_lower]
        if matched_keywords:
            findings.append({
                "type": "Info Leakage - HTML Comment",
                "severity": "Low",
                "url": url,
                "detail": f"HTML comment contains sensitive keywords: {matched_keywords}",
                "evidence": comment.strip()[:200],
                "recommendation": "Remove sensitive information from HTML comments before deploying to production."
            })

    return findings


def run_info_leakage_scan(urls: list, session: requests.Session = None) -> list:
    """Run all info leakage checks across discovered URLs."""
    all_findings = []
    sess = session or requests.Session()

    if not urls:
        return all_findings

    # Use first URL as base for sensitive file scanning
    base_url = urls[0]

    # Scan sensitive files once per domain
    all_findings.extend(scan_sensitive_files(base_url, sess))

    # Scan each URL
    for url in urls:
        try:
            resp = sess.get(
                url,
                headers=get_headers(),
                timeout=10,
                verify=False
            )
            html = resp.text

            all_findings.extend(scan_page_content(url, html))
            all_findings.extend(scan_response_headers(url, sess))
            all_findings.extend(scan_comments(url, html))

        except requests.RequestException:
            continue

    return all_findings


def _get_severity(pattern_name: str) -> str:
    """Map pattern name to severity level."""
    critical = ["AWS Secret Key", "Private Key Block", "Credit Card",
                "Social Security Number", "GitHub Token", "JWT Token"]
    high = ["AWS Access Key", "Google API Key", "Password in HTML",
            "Basic Auth in URL", "Bearer Token", "API Key Generic"]
    medium = ["SQL Error", "PHP Error", "Stack Trace",
              "Internal Path", "Version Disclosure"]
    low = ["Email Address", "Phone Number", "Debug Info", "IP Address"]

    if pattern_name in critical:
        return "Critical"
    elif pattern_name in high:
        return "High"
    elif pattern_name in medium:
        return "Medium"
    elif pattern_name in low:
        return "Low"
    return "Info"


def _file_severity(path: str) -> str:
    """Map file path to severity level."""
    critical_files = ["/.env", "/.git/config", "/wp-config.php",
                      "/config.php", "/.ssh/id_rsa", "/.htpasswd",
                      "/backup.sql", "/dump.sql", "/db.sql"]
    high_files = ["/phpinfo.php", "/info.php", "/web.config",
                  "/settings.py", "/database.yml", "/secrets.yml"]

    if any(path.startswith(f) or path == f for f in critical_files):
        return "Critical"
    elif any(path.startswith(f) or path == f for f in high_files):
        return "High"
    return "Medium"
