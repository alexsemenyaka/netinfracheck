#!/usr/bin/env python3
import asyncio

import netinfracheck


async def main():
    asn = "AS174"
    print(f"=== Asynchronous ASPA Check for {asn} ===")

    exists = await netinfracheck.aio_has_aspa(asn)
    print(f"ASPA record exists: {exists}")


if __name__ == "__main__":
    asyncio.run(main())
