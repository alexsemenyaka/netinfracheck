#!/usr/bin/env python3
import logging

import netinfracheck

# Enable DEBUG to see the chain traversal in logs
logging.basicConfig(level=logging.DEBUG, format="%(message)s")


def main():
    domain = "cloudflare.com"
    print(f"=== Synchronous Deep DNSSEC Check for {domain} ===")

    is_secure = netinfracheck.has_dnssec(domain, deep=True, resolvers = ['8.8.8.8', '1.1.1.1'])
    print(f"\nFinal Result: DNSSEC is {'SECURE' if is_secure else 'INSECURE/BROKEN'}")


if __name__ == "__main__":
    main()
