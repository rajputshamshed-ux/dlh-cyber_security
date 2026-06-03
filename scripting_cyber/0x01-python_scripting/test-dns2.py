#!/usr/bin/env python3

import dns.resolver

def query_dns_records(domain_name):
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            results[record_type] = answers
        except (dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers):
            continue
        except Exception:
            continue

    return results


# ✅ TEST DIRECT
test_domains = [
    "holbertonschool.com",
    "google.com",
    "github.com",
    "example.com",
    "this-is-not-a-site.com",
]

print("DNS TEST")
print("=" * 40)

for domain in test_domains:
    print(f"\n{domain}")

    results = query_dns_records(domain)

    if not results:
        print("Failed to resolve")
        continue

    for record_type in results:
        print(record_type)

print("\n" + "=" * 40)
