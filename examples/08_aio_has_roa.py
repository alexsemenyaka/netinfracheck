#!/usr/bin/env python3
import asyncio

import infracheck


async def main():
    ip = "1.1.1.1"
    print(f"=== Asynchronous ROA Check for {ip} ===")

    # Standard check
    prefix, is_valid = await infracheck.aio_has_roa(ip, deep=False)
    print(f"[Standard] Most Specific Prefix: {prefix} | ROA Valid: {is_valid}")

    # Deep check
    print("\n[Deep] Full Announcement Chain:")
    prefixes, verdicts = await infracheck.aio_has_roa(ip, deep=True)

    if not prefixes:
        print("No announcements found.")
        return

    print(f"{'BGP Prefix':<20} | {'RPKI Status':<10}")
    print("-" * 35)
    for p, v in zip(prefixes, verdicts, strict=True):
        print(f"{p:<20} | {'VALID' if v else 'INVALID'}")


if __name__ == "__main__":
    asyncio.run(main())
