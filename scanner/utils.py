import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 Safari/604.1",
]


def get_headers() -> dict:
    """Return randomized request headers."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }


def is_same_domain(url: str, base_url: str) -> bool:
    """Check if URL belongs to the same domain as base_url."""
    from urllib.parse import urlparse
    try:
        return urlparse(url).netloc == urlparse(base_url).netloc
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """Remove fragments and trailing slashes."""
    from urllib.parse import urlparse, urlunparse
    try:
        parsed = urlparse(url)
        normalized = parsed._replace(fragment="")
        return urlunparse(normalized).rstrip("/")
    except Exception:
        return url
