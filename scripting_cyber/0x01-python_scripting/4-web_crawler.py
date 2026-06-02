#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2):
    visited = set()

    def crawl(url, depth):
        if depth > max_depth or url in visited:
            return

        try:
            print(f"Crawling: {url}")
            visited.add(url)

            response = requests.get(url, timeout=3)
            soup = BeautifulSoup(response.text, "html.parser")

            base_domain = urlparse(start_url).netloc

            for link in soup.find_all("a", href=True):
                href = link.get("href")

                full_url = urljoin(url, href)
                parsed_url = urlparse(full_url)

                # rester dans le même domaine
                if parsed_url.netloc == base_domain:
                    crawl(full_url, depth + 1)

        except Exception:
            return

    crawl(start_url, 0)
    return visited
