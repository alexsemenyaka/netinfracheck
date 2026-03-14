#!/usr/bin/env python3
import netinfracheck


def main():
    ip = "1.1.1.1"
    print(f"=== Synchronous ROA Check for {ip} ===")

    # Standard check (deep=False)
    prefix, is_valid = netinfracheck.has_roa(ip, deep=False)
    print(f"[Standard] Most Specific Prefix: {prefix} | ROA Valid: {is_valid}")

    # Deep check (deep=True)
    print("\n[Deep] Full Announcement Chain:")
    prefixes, verdicts = netinfracheck.has_roa(ip, deep=True)

    if not prefixes:
        print("No announcements found.")
        return

    print(f"{'BGP Prefix':<20} | {'RPKI Status':<10}")
    print("-" * 35)
    for p, v in zip(prefixes, verdicts, strict=True):
        print(f"{p:<20} | {'VALID' if v else 'INVALID'}")


if __name__ == "__main__":
    main()
