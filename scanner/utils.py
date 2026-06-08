import requests
import urllib3
import tldextract
import validators
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
import time
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Utils:
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.session = self._create_session()
        self.base_domain = self._get_base_domain()

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        try:
            ua = UserAgent()
            user_agent = ua.random
        except Exception:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        return session

    def _get_base_domain(self) -> str:
        extracted = tldextract.extract(self.target_url)
        return f"{extracted.domain}.{extracted.suffix}"

    def get(self, url: str, **kwargs) -> requests.Response | None:
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                **kwargs,
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"GET request failed for {url}: {e}")
            return None

    def post(self, url: str, data: dict, **kwargs) -> requests.Response | None:
        try:
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                **kwargs,
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"POST request failed for {url}: {e}")
            return None

    def is_same_domain(self, url: str) -> bool:
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            return domain == self.base_domain
        except Exception:
            return False

    def is_valid_url(self, url: str) -> bool:
        try:
            return bool(validators.url(url))
        except Exception:
            return False

    def normalize_url(self, url: str, base: str = None) -> str:
        base = base or self.target_url
        if not url:
            return ""
        if url.startswith(("http://", "https://")):
            return url.rstrip("/")
        if url.startswith("//"):
            parsed = urlparse(base)
            return f"{parsed.scheme}:{url}".rstrip("/")
        if url.startswith("/"):
            parsed = urlparse(base)
            return f"{parsed.scheme}://{parsed.netloc}{url}".rstrip("/")
        return urljoin(base, url).rstrip("/")

    @staticmethod
    def severity_color(severity: str) -> str:
        colors = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
            "Info": "⚪",
        }
        return colors.get(severity, "⚪")

    @staticmethod
    def create_finding(
        vuln_type: str,
        severity: str,
        title: str,
        description: str,
        url: str,
        evidence: str = "",
        recommendation: str = "",
    ) -> dict:
        return {
            "type": vuln_type,
            "severity": severity,
            "title": title,
            "description": description,
            "url": url,
            "evidence": evidence,
            "recommendation": recommendation,
        }

    @staticmethod
    def rate_limit(seconds: float = 0.5):
        time.sleep(seconds)
