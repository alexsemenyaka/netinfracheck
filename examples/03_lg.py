#!/usr/bin/env python3
import netinfracheck


def main():
    target = "1.1.1.1"
    print(f"=== Synchronous Looking Glass Data for {target} ===")

    announcements = netinfracheck.lg_data(target)

    if not announcements:
        print("No visibility data found.")
        return

    print(f"Found {len(announcements)} unique announcements:")
    for prefix, asn in announcements:
        print(f"  - Prefix {prefix:<18} is originated by {asn}")


if __name__ == "__main__":
    main()
