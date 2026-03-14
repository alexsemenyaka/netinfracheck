#!/usr/bin/env python3
import asyncio

import netinfracheck


async def main():
    domain = "cloudflare.com"
    print(f"=== Asynchronous DNS Resolution for {domain} ===")

    # Run multiple queries concurrently
    a_task = netinfracheck.aio_resolve_domain(domain, qtype="A")
    soa_task = netinfracheck.aio_resolve_domain(domain, qtype="SOA")

    a_records, soa_records = await asyncio.gather(a_task, soa_task)

    print("\n[A Records]")
    for record in a_records:
        print(f"  - {record}")

    print("\n[SOA Record]")
    for record in soa_records:
        print(f"  - {record}")


if __name__ == "__main__":
    asyncio.run(main())
