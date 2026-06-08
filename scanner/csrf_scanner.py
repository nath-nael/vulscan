import requests
from bs4 import BeautifulSoup
from .utils import get_headers

CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "_token", "csrfmiddlewaretoken",
    "authenticity_token", "_csrf", "xsrf", "xsrf_token",
    "__requestverificationtoken", "csrf-token", "anti-csrf-token"
]


def run_csrf_scan(urls: list, session: requests.Session = None) -> list:
    findings = []
    sess = session or requests.Session()

    for url in urls:
        try:
            resp = sess.get(url, headers=get_headers(), timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                method = form.get("method", "get").lower()
                if method != "post":
                    continue

                inputs = form.find_all("input")
                input_names = [
                    (i.get("name") or "").lower()
                    for i in inputs
                ]
                input_types = [
                    (i.get("type") or "").lower()
                    for i in inputs
                ]

                has_csrf_token = any(
                    any(token in name for token in CSRF_TOKEN_NAMES)
                    for name in input_names
                ) or "hidden" in input_types and any(
                    any(token in name for token in CSRF_TOKEN_NAMES)
                    for name in input_names
                )

                if not has_csrf_token:
                    action = form.get("action", url)
                    findings.append({
                        "type": "CSRF - Missing Token",
                        "severity": "High",
                        "url": url,
                        "detail": f"POST form missing CSRF token. Action: {action}",
                        "evidence": f"Form inputs: {input_names}",
                        "recommendation": "Add a CSRF token to all POST forms."
                    })

            # Check SameSite cookie
            cookies = resp.cookies
            for cookie in cookies:
                same_site = cookie.__dict__.get("_rest", {}).get("SameSite", None)
                if not same_site:
                    findings.append({
                        "type": "CSRF - Missing SameSite Cookie",
                        "severity": "Medium",
                        "url": url,
                        "detail": f"Cookie '{cookie.name}' missing SameSite attribute.",
                        "evidence": f"Cookie: {cookie.name}",
                        "recommendation": "Set SameSite=Strict or SameSite=Lax on all cookies."
                    })

        except requests.RequestException:
            continue

    return findings
