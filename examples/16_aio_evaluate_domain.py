#!/usr/bin/env python3
import json
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
        soa=True,
        resolvers=['8.8.8.8', '1.1.1.1']
    )

    print(json.dumps(json_result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
