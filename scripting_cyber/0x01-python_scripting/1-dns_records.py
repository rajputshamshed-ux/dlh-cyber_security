#!/usr/bin/env python3

import dns.resolver

def query_dns_records(domain_name):
    results = {}

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

    try:
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain_name, record_type)
                results[record_type] = answers

            except (dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers):
                continue  # ignorer erreurs

        return results

    except Exception:
        return {}
``
