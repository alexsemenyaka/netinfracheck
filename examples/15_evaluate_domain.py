#!/usr/bin/env python3
import sys
import logging
import netinfracheck

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr
)

def main():
    target_domain = "cloudflare.com"

    print(f"=== Synchronous Domain Evaluation for {target_domain} ===")

    # Passing deep=False to keep the output reasonable, but enabling NS and MX checks.
    json_result = netinfracheck.evaluate_domain(
        target_domain,
        deep=False,
        ns=True,
        mx=True,
        soa=False
    )

    print(json_result)

if __name__ == "__main__":
    main()
