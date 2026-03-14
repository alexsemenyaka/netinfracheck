#!/usr/bin/env python3
import asyncio
import logging

import infracheck

logging.basicConfig(level=logging.DEBUG, format="%(message)s")


async def main():
    domain = "cloudflare.com"
    print(f"=== Asynchronous Deep DNSSEC Check for {domain} ===")

    is_secure = await infracheck.aio_has_dnssec(domain, deep=True)
    print(f"\nFinal Result: DNSSEC is {'SECURE' if is_secure else 'INSECURE/BROKEN'}")


if __name__ == "__main__":
    asyncio.run(main())
