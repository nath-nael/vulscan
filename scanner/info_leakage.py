import re
import json
from urllib.parse import urljoin
from .utils import safe_request

class InfoLeakageScanner:
    def __init__(self):
        self.vulnerabilities = []

        # Sensitive file paths to check
        self.sensitive_paths = [
            # Config files
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/config.php', '/config.js', '/config.json', '/config.yml', '/config.yaml',
            '/configuration.php', '/settings.py', '/settings.php',
            '/wp-config.php', '/wp-config.php.bak',

            # Backup files
            '/backup.sql', '/backup.zip', '/backup.tar.gz', '/backup.tar',
            '/db.sql', '/database.sql', '/dump.sql', '/site.sql',
            '/backup/', '/backups/', '/bak/',

            # Version control
            '/.git/HEAD', '/.git/config', '/.git/COMMIT_EDITMSG',
            '/.svn/entries', '/.hg/hgrc',
            '/.gitignore', '/.gitattributes',

            # Admin panels
            '/admin', '/admin/', '/administrator', '/admin/login',
            '/wp-admin', '/wp-login.php', '/phpmyadmin', '/pma',
            '/cpanel', '/webmail', '/plesk',

            # Log files
            '/error.log', '/access.log', '/debug.log', '/app.log',
            '/logs/', '/log/', '/error_log', '/php_error.log',

            # API docs
            '/api', '/api/v1', '/api/v2', '/swagger', '/swagger.json',
            '/swagger-ui.html', '/api-docs', '/openapi.json', '/graphql',

            # Common sensitive files
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/phpinfo.php', '/info.php', '/test.php', '/php.php',
            '/server-status', '/server-info', '/.htaccess', '/.htpasswd',
            '/web.config', '/app.config',

            # Package files
            '/package.json', '/composer.json', '/requirements.txt',
            '/Gemfile', '/Pipfile', '/yarn.lock', '/package-lock.json',

            # Docker/CI files
            '/Dockerfile', '/docker-compose.yml', '/.travis.yml',
            '/Jenkinsfile', '/.circleci/config.yml',

            # AWS/Cloud
            '/.aws/credentials', '/aws.json',

            # SSH keys
            '/.ssh/id_rsa', '/.ssh/id_rsa.pub', '/.ssh/authorized_keys',

            # Certificate files
            '/server.key', '/server.crt', '/ssl.key',

            # Common CMS
            '/readme.html', '/readme.txt', '/README.md', '/CHANGELOG.md',
            '/license.txt', '/LICENSE',

            # Exposed directories
            '/uploads/', '/upload/', '/files/', '/file/', '/media/',
            '/static/', '/assets/', '/public/',
        ]

        # Sensitive data patterns
        self.sensitive_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'SendGrid API Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'PayPal Client ID': r'A[0-9a-zA-Z]{79}',
            'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----',
            'DSA Private Key': r'-----BEGIN DSA PRIVATE KEY-----',
            'EC Private Key': r'-----BEGIN EC PRIVATE KEY-----',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'Basic Auth': r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]+',
            'Bearer Token': r'Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*',
            'Database URL': r'(mysql|postgresql|mongodb|redis):\/\/[^\s"\']+',
            'Password in URL': r'[?&]password=[^&\s]+',
            'Password in Code': r'password\s*=\s*["\'][^"\']{3,}["\']',
            'Secret in Code': r'secret\s*=\s*["\'][^"\']{3,}["\']',
            'API Key in Code': r'api_key\s*=\s*["\'][^"\']{3,}["\']',
            'Private Key in Code': r'private_key\s*=\s*["\'][^"\']{3,}["\']',
            'Internal IP': r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            'Email Address': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Phone Number': r'\b[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}\b',
        }

        # Technology fingerprints
        self.tech_fingerprints = {
            'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
            'Drupal': [r'Drupal', r'/sites/default/', r'drupal.js'],
            'Joomla': [r'Joomla', r'/components/com_', r'joomla'],
            'Laravel': [r'Laravel', r'laravel_session', r'XSRF-TOKEN'],
            'Django': [r'Django', r'csrfmiddlewaretoken', r'django'],
            'Ruby on Rails': [r'Rails', r'_rails_', r'X-Runtime'],
            'ASP.NET': [r'ASP\.NET', r'__VIEWSTATE', r'__EVENTVALIDATION'],
            'PHP': [r'\.php', r'PHPSESSID', r'X-Powered-By: PHP'],
            'Apache': [r'Apache', r'Server: Apache'],
            'Nginx': [r'nginx', r'Server: nginx'],
            'IIS': [r'IIS', r'Server: Microsoft-IIS'],
            'Express.js': [r'Express', r'X-Powered-By: Express'],
            'React': [r'react', r'__REACT', r'_reactFiber'],
            'Angular': [r'ng-version', r'angular', r'ng-app'],
            'Vue.js': [r'vue', r'__vue__', r'v-app'],
        }

    def scan(self, base_url, crawl_data, progress_callback=None):
        results = {
            'exposed_files': [],
            'sensitive_data': [],
            'technology_stack': [],
            'comments_with_info': [],
            'js_secrets': [],
            'directory_listing': [],
            'error_messages': [],
            'version_disclosure': []
        }

        # Check for exposed sensitive files
        if progress_callback:
            progress_callback("Checking for exposed sensitive files...")

        exposed = self._check_sensitive_files(base_url)
        results['exposed_files'] = exposed

        # Scan page content for sensitive data
        if progress_callback:
            progress_callback("Scanning for sensitive data leakage...")

        for url, page_data in crawl_data.get('page_data', {}).items():
            sensitive = self._scan_content_for_secrets(page_data.get('html', ''), url)
            results['sensitive_data'].extend(sensitive)

        # Scan JS files for secrets
        if progress_callback:
            progress_callback("Scanning JavaScript files for secrets...")

        for js_url in crawl_data.get('js_files', []):
            js_secrets = self._scan_js_file(js_url)
            results['js_secrets'].extend(js_secrets)

        # Analyze HTML comments
        for comment in crawl_data.get('comments', []):
            comment_info = self._analyze_comment(comment)
            if comment_info:
                results['comments_with_info'].append(comment_info)

        # Detect technology stack
        if progress_callback:
            progress_callback("Detecting technology stack...")

        tech_stack = self._detect_tech_stack(crawl_data)
        results['technology_stack'] = tech_stack

        # Check for version disclosure in headers
        for url, headers in crawl_data.get('response_headers', {}).items():
            version_info = self._check_version_disclosure(url, headers)
            results['version_disclosure'].extend(version_info)

        # Check for directory listing
        dirs_to_check = ['/uploads/', '/images/', '/files/', '/backup/', '/logs/', '/admin/']
        for dir_path in dirs_to_check:
            dir_url = urljoin(base_url, dir_path)
            dir_vuln = self._check_directory_listing(dir_url)
            if dir_vuln:
                results['directory_listing'].append(dir_vuln)

        return results

    def _check_sensitive_files(self, base_url):
        exposed = []

        for path in self.sensitive_paths:
            url = urljoin(base_url, path)
            response = safe_request(url)

            if response and response.status_code == 200:
                content_preview = response.text[:500] if response.text else ''

                severity = self._get_file_severity(path)

                exposed.append({
                    'type': 'Exposed Sensitive File',
                    'severity': severity,
                    'url': url,
                    'path': path,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_preview': content_preview[:200],
                    'description': f"Sensitive file accessible: {path}",
                    'recommendation': f"Restrict access to {path}"
                })

        return exposed

    def _get_file_severity(self, path):
        critical_paths = ['.env', '.git', 'config', 'password', 'secret', 
                         'key', 'credential', 'backup', '.sql', 'id_rsa']
        high_paths = ['admin', 'phpinfo', 'phpmyadmin', 'wp-config', 'htpasswd']

        path_lower = path.lower()
        if any(p in path_lower for p in critical_paths):
            return 'CRITICAL'
        elif any(p in path_lower for p in high_paths):
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _scan_content_for_secrets(self, content, url):
        findings = []

        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                # Filter out false positives
                unique_matches = list(set(matches))[:5]

                # Determine severity
                severity = 'HIGH'
                if pattern_name in ['Email Address', 'Phone Number', 'Internal IP']:
                    severity = 'LOW'
                elif pattern_name in ['Credit Card', 'SSN', 'RSA Private Key', 
                                      'AWS Access Key', 'AWS Secret Key']:
                    severity = 'CRITICAL'

                findings.append({
                    'type': f'Sensitive Data: {pattern_name}',
                    'severity': severity,
                    'url': url,
                    'pattern': pattern_name,
                    'matches': [str(m)[:50] + '...' if len(str(m)) > 50 else str(m) 
                               for m in unique_matches],
                    'count': len(matches),
                    'description': f"{pattern_name} found in page content",
                    'recommendation': f"Remove or protect {pattern_name} from public access"
                })

        return findings

    def _scan_js_file(self, js_url):
        findings = []
        response = safe_request(js_url)

        if not response:
            return findings

        content = response.text

        # Scan for secrets in JS
        js_patterns = {
            'API Key': r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']',
            'Secret': r'(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']',
            'Token': r'(?:token|auth)\s*[:=]\s*["\']([^"\']{10,})["\']',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Private Key': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            'Database URL': r'(?:mysql|postgresql|mongodb|redis):\/\/[^\s"\']+',
            'Hardcoded URL': r'https?:\/\/(?:localhost|127\.0\.0\.1|192\.168\.|10\.)[^\s"\']+',
            'Base64 Secret': r'(?:secret|password|key)\s*[:=]\s*["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
        }

        for pattern_name, pattern in js_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': f'JS Secret: {pattern_name}',
                    'severity': 'HIGH',
                    'url': js_url,
                    'pattern': pattern_name,
                    'matches': [str(m)[:50] for m in list(set(matches))[:3]],
                    'description': f"{pattern_name} found in JavaScript file",
                    'recommendation': 'Move secrets to server-side, never expose in JS'
                })

        return findings

    def _analyze_comment(self, comment):
        content = comment.get('content', '')

        sensitive_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'api', 'todo', 'fixme', 'hack', 'bug', 'vulnerability',
            'admin', 'root', 'debug', 'test', 'temp', 'temporary',
            'credentials', 'username', 'user', 'login', 'auth',
            'database', 'db', 'sql', 'server', 'host', 'port',
            'internal', 'private', 'confidential', 'sensitive'
        ]

        content_lower = content.lower()
        found_keywords = [kw for kw in sensitive_keywords if kw in content_lower]

        if found_keywords:
             ▏
