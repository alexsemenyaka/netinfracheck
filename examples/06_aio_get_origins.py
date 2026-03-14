#!/usr/bin/env python3
import asyncio

import netinfracheck


async def main():
    ip = "8.8.8.8"
    print(f"=== Asynchronous BGP Origins for {ip} ===")

    asns = await netinfracheck.aio_get_origins(ip)

    if asns:
        print(f"Announced by: {', '.join(asns)}")
    else:
        print("No announcing ASNs found.")


if __name__ == "__main__":
    asyncio.run(main())
