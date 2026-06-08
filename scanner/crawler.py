from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import deque
from .utils import Utils
import logging
import re

logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, utils: Utils, max_pages: int = 50, max_depth: int = 3):
        self.utils = utils
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited_urls: set = set()
        self.all_urls: set = set()
        self.forms: list = []
        self.emails: set = set()
        self.comments: list = []
        self.external_links: set = set()
        self.js_files: set = set()
        self.page_data: dict = {}

    def crawl(self, progress_callback=None) -> dict:
        queue = deque([(self.utils.target_url, 0)])
        self.visited_urls.add(self.utils.target_url)

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            if progress_callback:
                progress_callback(f"Crawling: {current_url}")

            response = self.utils.get(current_url)
            if not response:
                continue

            self.utils.rate_limit(0.3)
            self._parse_page(current_url, response)

            if depth < self.max_depth:
                for link in self._extract_links(current_url, response.text):
                    if link not in self.visited_urls:
                        self.visited_urls.add(link)
                        queue.append((link, depth + 1))

        return self._compile_results()

    def _parse_page(self, url: str, response):
        try:
            soup = BeautifulSoup(response.text, "lxml")
            self.page_data[url] = {
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "title": self._get_title(soup),
                "forms": self._extract_forms(url, soup),
                "comments": self._extract_comments(soup),
                "emails": self._extract_emails(response.text),
                "js_files": self._extract_js_files(url, soup),
            }
            self.forms.extend(self.page_data[url]["forms"])
            self.comments.extend(self.page_data[url]["comments"])
            self.emails.update(self.page_data[url]["emails"])
            self.js_files.update(self.page_data[url]["js_files"])
        except Exception as e:
            logger.error(f"Error parsing {url}: {e}")

    def _get_title(self, soup: BeautifulSoup) -> str:
        title = soup.find("title")
        return title.text.strip() if title else "No title"

    def _extract_links(self, base_url: str, html: str) -> list:
        links = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all(["a", "link"], href=True):
                href = tag.get("href", "")
                full_url = self.utils.normalize_url(href, base_url)
                if not full_url or not self.utils.is_valid_url(full_url):
                    continue
                if self.utils.is_same_domain(full_url):
                    links.append(full_url)
                    self.all_urls.add(full_url)
                else:
                    self.external_links.add(full_url)

            for tag in soup.find_all(["form"], action=True):
                action = tag.get("action", "")
                if action:
                    full_url = self.utils.normalize_url(action, base_url)
                    if self.utils.is_same_domain(full_url):
                        links.append(full_url)
        except Exception as e:
            logger.error(f"Error extracting links from {base_url}: {e}")
        return list(set(links))

    def _extract_forms(self, url: str, soup: BeautifulSoup) -> list:
        forms = []
        for form in soup.find_all("form"):
            form_data = {
                "url": url,
                "action": form.get("action", ""),
                "method": form.get("method", "get").lower(),
                "inputs": [],
                "has_csrf_token": False,
            }
            csrf_indicators = [
                "csrf", "token", "_token", "authenticity_token",
                "csrfmiddlewaretoken", "xsrf"
            ]
            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                    "id": inp.get("id", ""),
                }
                if any(
                    csrf_ind in input_data["name"].lower()
                    for csrf_ind in csrf_indicators
                ):
                    form_data["has_csrf_token"] = True
                form_data["inputs"].append(input_data)
            forms.append(form_data)
        return forms

    def _extract_comments(self, soup: BeautifulSoup) -> list:
        comments = []
        for comment in soup.find_all(string=lambda text: isinstance(text, str)):
            if "<!--" in str(comment):
                comments.append(str(comment).strip())
        from bs4 import Comment
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            stripped = comment.strip()
            if stripped:
                comments.append(stripped)
        return comments

    def _extract_emails(self, text: str) -> set:
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        return set(re.findall(email_pattern, text))

    def _extract_js_files(self, base_url: str, soup: BeautifulSoup) -> set:
        js_files = set()
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                full_url = self.utils.normalize_url(src, base_url)
                if full_url:
                    js_files.add(full_url)
        return js_files

    def _compile_results(self) -> dict:
        return {
            "visited_urls": list(self.visited_urls),
            "all_urls": list(self.all_urls),
            "forms": self.forms,
            "emails": list(self.emails),
            "comments": self.comments,
            "external_links": list(self.external_links),
            "js_files": list(self.js_files),
            "page_data": self.page_data,
            "total_pages": len(self.visited_urls),
        }
