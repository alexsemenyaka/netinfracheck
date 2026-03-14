#!/usr/bin/env python3
import netinfracheck


def main():
    ip = "8.8.8.8"
    print(f"=== Synchronous BGP Origins for {ip} ===")

    asns = netinfracheck.get_origins(ip)

    if asns:
        print(f"Announced by: {', '.join(asns)}")
    else:
        print("No announcing ASNs found.")


if __name__ == "__main__":
    main()
