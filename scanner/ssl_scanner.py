import ssl
import socket
import datetime
from urllib.parse import urlparse
from .utils import safe_request

class SSLScanner:
    def __init__(self):
        self.vulnerabilities = []

    def scan(self, url, progress_callback=None):
        results = {
            'certificate_info': {},
            'ssl_issues': [],
            'protocol_issues': [],
            'cipher_issues': []
        }

        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        port = 443

        if progress_callback:
            progress_callback(f"Scanning SSL/TLS for {hostname}...")

        # Get certificate info
        cert_info = self._get_certificate_info(hostname, port)
        results['certificate_info'] = cert_info

        # Check SSL issues
        if cert_info:
            ssl_issues = self._analyze_certificate(cert_info, hostname)
            results['ssl_issues'] = ssl_issues

        # Check if HTTP redirects to HTTPS
        http_url = f"http://{hostname}"
        http_response = safe_request(http_url, allow_redirects=False)

        if http_response:
            if http_response.status_code not in [301, 302, 307, 308]:
                results['ssl_issues'].append({
                    'type': 'No HTTPS Redirect',
                    'severity': 'HIGH',
                    'description': 'HTTP traffic is not redirected to HTTPS',
                    'recommendation': 'Configure server to redirect all HTTP to HTTPS'
                })
            elif 'Location' in http_response.headers:
                location = http_response.headers['Location']
                if not location.startswith('https://'):
                    results['ssl_issues'].append({
                        'type': 'Insecure Redirect',
                        'severity': 'HIGH',
                        'description': 'HTTP redirect does not go to HTTPS',
                        'recommendation': 'Ensure redirect target uses HTTPS'
                    })

        return results

    def _get_certificate_info(self, hostname, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', []),
                        'cipher': cipher,
                        'protocol': version,
                    }
        except ssl.SSLError as e:
            return {'error': f'SSL Error: {str(e)}'}
        except socket.timeout:
            return {'error': 'Connection timeout'}
        except Exception as e:
            return {'error': str(e)}

    def _analyze_certificate(self, cert_info, hostname):
        issues = []

        if 'error' in cert_info:
            issues.append({
                'type': 'SSL Certificate Error',
                'severity': 'CRITICAL',
                'description': cert_info['error'],
                'recommendation': 'Fix SSL certificate configuration'
            })
            return issues

        # Check expiration
        if cert_info.get('not_after'):
            try:
                expiry = datetime.datetime.strptime(
                    cert_info['not_after'], '%b %d %H:%M:%S %Y %Z'
                )
                days_until_expiry = (expiry - datetime.datetime.utcnow()).days

                if days_until_expiry < 0:
                    issues.append({
                        'type': 'Expired SSL Certificate',
                        'severity': 'CRITICAL',
                        'description': f'Certificate expired {abs(days_until_expiry)} days ago',
                        'recommendation': 'Renew SSL certificate immediately'
                    })
                elif days_until_expiry < 30:
                    issues.append({
                        'type': 'SSL Certificate Expiring Soon',
                        'severity': 'HIGH',
                        'description': f'Certificate expires in {days_until_expiry} days',
                        'recommendation': 'Renew SSL certificate before expiration'
                    })
            except:
                pass

        # Check protocol version
        protocol = cert_info.get('protocol', '')
        weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        if any(wp in protocol for wp in weak_protocols):
            issues.append({
                'type': 'Weak SSL/TLS Protocol',
                'severity': 'HIGH',
                'protocol': protocol,
                'description': f'Weak protocol in use: {protocol}',
                'recommendation': 'Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. Use TLS 1.2 or 1.3'
            })

        # Check cipher
        cipher = cert_info.get('cipher', [])
        if cipher:
            cipher_name = cipher[0] if cipher else ''
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']
            if any(wc in cipher_name for wc in weak_ciphers):
                issues.append({
                    'type': 'Weak Cipher Suite',
                    'severity': 'HIGH',
                    'cipher': cipher_name,
                    'description': f'Weak cipher suite in use: {cipher_name}',
                    'recommendation': 'Disable weak cipher suites, use AES-256-GCM or ChaCha20'
                })

        return issues
