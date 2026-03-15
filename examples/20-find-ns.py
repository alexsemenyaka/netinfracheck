#!/usr/bin/env python3
"""
Demonstrates the difference between naive NS resolution and intelligent zone apex discovery.
"""

import sys
import logging
import netinfracheck

# Disable debug logs to keep output clean
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

def main():
    target = "www.kyivcity.gov.ua"
    print(f"=== Intelligent NS Discovery for {target} ===\n")

    # 1. Naive approach
    print("1. Naive DNS query (looking for NS directly on the specific host):")
    naive_ns = netinfracheck.resolve_domain(target, 'NS')
    if naive_ns:
        print(f"   Result: {', '.join(naive_ns)}\n")
    else:
        print("   Result: No records found (host lacks its own delegation).\n")

    # 2. Smart approach
    print("2. Smart DNS query (walking up to the zone apex):")
    zone_apex = netinfracheck.get_zone_apex(target)
    print(f"   Found zone apex: {zone_apex}")

    smart_ns = netinfracheck.find_ns(target)
    if smart_ns:
        print(f"   Authoritative NS: {', '.join(smart_ns)}")
    else:
        print("   Authoritative NS: No records found.")

if __name__ == "__main__":
    main()
