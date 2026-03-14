#!/usr/bin/env python3
import logging

import infracheck

# Enable DEBUG to see the chain traversal in logs
logging.basicConfig(level=logging.DEBUG, format="%(message)s")


def main():
    domain = "cloudflare.com"
    print(f"=== Synchronous Deep DNSSEC Check for {domain} ===")

    is_secure = infracheck.has_dnssec(domain, deep=True)
    print(f"\nFinal Result: DNSSEC is {'SECURE' if is_secure else 'INSECURE/BROKEN'}")


if __name__ == "__main__":
    main()
