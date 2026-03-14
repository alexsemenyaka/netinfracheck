#!/usr/bin/env python3
import asyncio
import netinfracheck

async def main():
    target_domain = "cloudflare.com"

    print(f"=== Asynchronous Domain Evaluation for {target_domain} ===")

    # Enabling all checks including SOA paranoia mode
    json_result = await netinfracheck.aio_evaluate_domain(
        target_domain,
        deep=False,
        ns=True,
        mx=True,
        soa=True
    )

    print(json_result)

if __name__ == "__main__":
    asyncio.run(main())
