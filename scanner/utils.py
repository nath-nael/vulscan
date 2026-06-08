import requests
import random
import time
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
import re

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
]

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

def safe_request(url, method="GET", data=None, timeout=10, allow_redirects=True, verify=False):
    try:
        headers = get_random_headers()
        if method == "GET":
            response = requests.get(
                url, headers=headers, timeout=timeout,
                allow_redirects=allow_redirects, verify=verify
            )
        elif method == "POST":
            response = requests.post(
                url, data=data, headers=headers, timeout=timeout,
                allow_redirects=allow_redirects, verify=verify
            )
        return response
    except requests.exceptions.SSLError:
        try:
            return requests.get(url, headers=get_random_headers(), timeout=timeout, verify=False)
        except:
            return None
    except Exception as e:
        return None

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')

def is_same_domain(url, base_url):
    try:
        base_domain = urlparse(base_url).netloc
        url_domain = urlparse(url).netloc
        return base_domain == url_domain or url_domain.endswith('.' + base_domain)
    except:
        return False

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc

def severity_color(severity):
    colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪"
    }
    return colors.get(severity, "⚪")
