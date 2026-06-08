import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from .utils import get_headers, is_same_domain, normalize_url


def crawl(base_url: str, max_urls: int = 20) -> list:
    """
    Crawl a website starting from base_url.
    Returns a list of discovered URLs on the same domain.
    """
    visited = set()
    to_visit = [base_url]
    found = []

    session = requests.Session()
    session.verify = False

    while to_visit and len(found) < max_urls:
        url = to_visit.pop(0)
        url = normalize_url(url)

        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(
                url,
                headers=get_headers(),
                timeout=10,
                allow_redirects=True,
                verify=False
            )

            if resp.status_code != 200:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                continue

            found.append(url)

            soup = BeautifulSoup(resp.text, "html.parser")

            for tag in soup.find_all(["a", "form"], href=True):
                href = tag.get("href") or tag.get("action")
                if not href:
                    continue
                full_url = normalize_url(urljoin(base_url, href))
                if (
                    is_same_domain(full_url, base_url)
                    and full_url not in visited
                    and full_url not in to_visit
                    and full_url.startswith("http")
                ):
                    to_visit.append(full_url)

            # Also grab form actions
            for form in soup.find_all("form"):
                action = form.get("action")
                if action:
                    full_url = normalize_url(urljoin(base_url, action))
                    if (
                        is_same_domain(full_url, base_url)
                        and full_url not in visited
                        and full_url not in to_visit
                        and full_url.startswith("http")
                    ):
                        to_visit.append(full_url)

        except requests.RequestException:
            continue

    return found
