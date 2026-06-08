import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
from collections import deque
import re
from .utils import safe_request, is_same_domain, get_random_headers
import time

class WebCrawler:
    def __init__(self, base_url, max_pages=50, max_depth=3):
        self.base_url = base_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited_urls = set()
        self.all_urls = set()
        self.forms = []
        self.links = []
        self.scripts = []
        self.comments = []
        self.emails = []
        self.phone_numbers = []
        self.api_endpoints = []
        self.js_files = []
        self.css_files = []
        self.images = []
        self.external_links = []
        self.parameters = {}
        self.cookies = {}
        self.response_headers = {}
        self.page_data = {}

    def crawl(self, progress_callback=None):
        queue = deque([(self.base_url, 0)])
        pages_crawled = 0

        while queue and pages_crawled < self.max_pages:
            current_url, depth = queue.popleft()

            if current_url in self.visited_urls or depth > self.max_depth:
                continue

            self.visited_urls.add(current_url)

            if progress_callback:
                progress_callback(f"Crawling: {current_url}")

            response = safe_request(current_url)
            if not response:
                continue

            pages_crawled += 1

            # Store response data
            self.response_headers[current_url] = dict(response.headers)
            self.cookies.update(dict(response.cookies))

            # Parse page
            try:
                soup = BeautifulSoup(response.text, 'lxml')
            except:
                soup = BeautifulSoup(response.text, 'html.parser')

            self.page_data[current_url] = {
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'title': soup.title.string if soup.title else 'No Title',
                'html': response.text
            }

            # Extract all elements
            self._extract_links(soup, current_url, queue, depth)
            self._extract_forms(soup, current_url)
            self._extract_scripts(soup, current_url)
            self._extract_comments(soup, current_url)
            self._extract_sensitive_data(response.text, current_url)
            self._extract_api_endpoints(response.text, current_url)

            time.sleep(0.3)  # Be polite

        return self._get_results()

    def _extract_links(self, soup, current_url, queue, depth):
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href', '')
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            full_url = urljoin(current_url, href)
            parsed = urlparse(full_url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if is_same_domain(full_url, self.base_url):
                self.all_urls.add(clean_url)
                self.links.append({
                    'url': full_url,
                    'text': tag.get_text(strip=True)[:100],
                    'source': current_url
                })
                if clean_url not in self.visited_urls:
                    queue.append((full_url, depth + 1))

                # Extract URL parameters
                if parsed.query:
                    self.parameters[full_url] = parsed.query
            else:
                self.external_links.append({
                    'url': full_url,
                    'text': tag.get_text(strip=True)[:100],
                    'source': current_url
                })

        # Extract from src attributes
        for tag in soup.find_all(['script', 'img', 'iframe', 'frame'], src=True):
            src = tag.get('src', '')
            if src:
                full_url = urljoin(current_url, src)
                if tag.name == 'script':
                    self.js_files.append(full_url)
                elif tag.name == 'img':
                    self.images.append(full_url)

    def _extract_forms(self, soup, current_url):
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(current_url, form.get('action', current_url)),
                'method': form.get('method', 'GET').upper(),
                'source': current_url,
                'inputs': [],
                'has_csrf_token': False,
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
            }

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'id': input_tag.get('id', ''),
                    'placeholder': input_tag.get('placeholder', '')
                }
                form_data['inputs'].append(input_data)

                # Check for CSRF tokens
                name = input_data['name'].lower()
                if any(token in name for token in ['csrf', 'token', '_token', 'nonce', 'authenticity']):
                    form_data['has_csrf_token'] = True

            self.forms.append(form_data)

    def _extract_scripts(self, soup, current_url):
        for script in soup.find_all('script'):
            script_data = {
                'src': script.get('src', ''),
                'content': script.string or '',
                'source': current_url
            }
            if script_data['src']:
                full_src = urljoin(current_url, script_data['src'])
                self.js_files.append(full_src)
                # Fetch and analyze JS file
                js_response = safe_request(full_src)
                if js_response:
                    script_data['content'] = js_response.text
            self.scripts.append(script_data)

    def _extract_comments(self, soup, current_url):
        from bs4 import Comment
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_text = str(comment).strip()
            if len(comment_text) > 5:
                self.comments.append({
                    'content': comment_text,
                    'source': current_url
                })

    def _extract_sensitive_data(self, html_content, current_url):
        # Email extraction
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html_content)
        for email in emails:
            if email not in [e['value'] for e in self.emails]:
                self.emails.append({'value': email, 'source': current_url})

        # Phone numbers
        phones = re.findall(r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}', html_content)
        for phone in phones:
            self.phone_numbers.append({'value': phone, 'source': current_url})

    def _extract_api_endpoints(self, content, current_url):
        # Find API endpoints in JS and HTML
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*?open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match not in [e['endpoint'] for e in self.api_endpoints]:
                    self.api_endpoints.append({
                        'endpoint': match,
                        'source': current_url
                    })

    def _get_results(self):
        return {
            'visited_urls': list(self.visited_urls),
            'all_urls': list(self.all_urls),
            'forms': self.forms,
            'links': self.links,
            'scripts': self.scripts,
            'comments': self.comments,
            'emails': self.emails,
            'phone_numbers': self.phone_numbers,
            'api_endpoints': self.api_endpoints,
            'js_files': list(set(self.js_files)),
            'images': self.images,
            'external_links': self.external_links,
            'parameters': self.parameters,
            'cookies': self.cookies,
            'response_headers': self.response_headers,
            'page_data': self.page_data
        }
