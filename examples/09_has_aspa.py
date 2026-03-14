#!/usr/bin/env python3
import infracheck


def main():
    asn = "AS174"
    print(f"=== Synchronous ASPA Check for {asn} ===")

    exists = infracheck.has_aspa(asn)
    print(f"ASPA record exists: {exists}")


if __name__ == "__main__":
    main()
