#!/usr/bin/env python3
import netinfracheck


def main():
    domain = "cloudflare.com"
    print(f"=== Synchronous DNS Resolution for {domain} ===")

    # Query A records (default)
    ips = netinfracheck.resolve_domain(domain)
    print("\n[A Records]")
    if ips:
        for ip in ips:
            print(f"  - {ip}")
    else:
        print("  No A records found.")

    # Query NS records
    ns_records = netinfracheck.resolve_domain(domain, qtype="NS")
    print("\n[NS Records]")
    if ns_records:
        for ns in ns_records:
            print(f"  - {ns}")
    else:
        print("  No NS records found.")

    # Query MX records
    mx_records = netinfracheck.resolve_domain(domain, qtype="MX")
    print("\n[MX Records]")
    if mx_records:
        for mx in mx_records:
            print(f"  - {mx}")
    else:
        print("  No MX records found.")


if __name__ == "__main__":
    main()
