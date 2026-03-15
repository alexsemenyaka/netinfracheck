#!/usr/bin/env python3
"""
Demonstrates concurrent intelligent NS discovery for multiple specific hosts.
"""

import sys
import asyncio
import logging
import netinfracheck

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

async def check_target(domain: str):
    """Fetches and prints the authoritative nameservers for a given domain."""
    ns_records = await netinfracheck.aio_find_ns(domain)

    if ns_records:
        print(f"[+] {domain:<25} -> {', '.join(ns_records)}")
    else:
        print(f"[-] {domain:<25} -> No authoritative NS found")

async def main():
    targets = [
        "hightech.gov.am",
        "www.kyivcity.gov.ua",
        "cloudflare.com",
        "mail.ukr.net"
    ]

    print("=== Async Intelligent NS Discovery ===\n")
    print("Fetching authoritative nameservers concurrently...\n")

    # Launch all discovery tasks simultaneously
    tasks = [asyncio.create_task(check_target(domain)) for domain in targets]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
