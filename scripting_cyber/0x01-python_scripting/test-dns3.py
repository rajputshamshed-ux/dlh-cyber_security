#!/usr/bin/env python3

import requests

def get_http_headers(url):
    try:
        response = requests.get(url)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers)
        }
    except requests.exceptions.RequestException:
        return None


# ✅ Liste des sites à tester
test_urls = [
    "https://www.google.com",
    "https://github.com",
    "https://example.com",
    "https://holbertonschool.com",
    "https://this-site-does-not-exist.com"
]

print("HTTP HEADER TEST")
print("=" * 50)

for url in test_urls:
    print(f"\n🔍 {url}")

    result = get_http_headers(url)

    if result is None:
        print("❌ Failed to retrieve headers")
        continue

    print(f"✅ Status Code: {result['status_code']}")
    print("Headers:")

    for key, value in result['headers'].items():
        print(f"  {key}: {value}")

print("\n" + "=" * 50)
