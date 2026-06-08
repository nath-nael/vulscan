import requests
from .utils import get_headers

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
    },
    "Content-Security-Policy": {
        "severity": "High",
        "recommendation": "Define a Content-Security-Policy to prevent XSS and data injection."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking."
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "recommendation": "Add a Permissions-Policy header to control browser features."
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' for legacy browser protection."
    },
}

INSECURE_HEADERS = {
    "Server": "Reveals server software version.",
    "X-Powered-By": "Reveals backend technology.",
    "X-AspNet-Version": "Reveals ASP.NET version.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version.",
}


def run_headers_scan(urls: list, session: requests.Session = None) -> list:
    findings = []
    sess = session or requests.Session()
    scanned = set()

    for url in urls:
        if url in scanned:
            continue
        scanned.add(url)

        try:
            resp = sess.get(url, headers=get_headers(), timeout=10, verify=False)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            # Check missing security headers
            for header, meta in REQUIRED_HEADERS.items():
                if header.lower() not in resp_headers_lower:
                    findings.append({
                        "type": f"Headers - Missing {header}",
                        "severity": meta["severity"],
                        "url": url,
                        "detail": f"Security header '{header}' is missing.",
                        "evidence": f"Header not present in response.",
                        "recommendation": meta["recommendation"]
                    })

            # Check insecure headers
            for header, detail in INSECURE_HEADERS.items():
                if header.lower() in resp_headers_lower:
                    findings.append({
                        "type": f"Headers - Information Disclosure ({header})",
                        "severity": "Low",
                        "url": url,
                        "detail": detail,
                        "evidence": f"{header}: {resp_headers_lower[header.lower()]}",
                        "recommendation": f"Remove or obscure the '{header}' header."
                    })

        except requests.RequestException:
            continue

    return findings
