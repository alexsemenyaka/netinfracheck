#!/usr/bin/env python3

import sys
import asyncio
import logging
import infracheck

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

def format_colored_metric(val: float) -> str:
    """Formats the float value with strict ANSI colors."""
    c_reset = "\033[0m"
    c_green = "\033[1;32m"
    c_yellow = "\033[1;33m"
    c_red = "\033[1;91m"

    num = float(val)
    text = f"{num:.2f}"

    if num == 1.0:
        return f"{c_green}{text}{c_reset}"
    elif 0.5 < num < 1.0:
        return f"{c_yellow}{text}{c_reset}"
    else:
        return f"{c_red}{text}{c_reset}"

async def main():
    domain = "cloudflare.com"
    print(f"=== Evaluating Route Security for NS servers of {domain} ===\n")

    # 1. Gather all NS records
    ns_records = await infracheck.aio_resolve_domain(domain, 'NS')
    if not ns_records:
        print("No NS records found.")
        return

    # 2. Resolve all NS names to a flat list of unique IP addresses
    all_ips = []
    for ns in ns_records:
        ips = await infracheck.aio_resolve_domain(ns.rstrip('.'), 'A')
        all_ips.extend(ips)

    unique_ips = list(set(all_ips))
    print(f"Discovered {len(unique_ips)} unique IP addresses serving DNS.")
    print("Fetching BGP evaluations... Please wait.\n")

    # 3. Evaluate all IPs concurrently
    tasks = [infracheck.aio_evaluate_ip(ip, deep=True) for ip in unique_ips]
    evaluations = await asyncio.gather(*tasks)

    # 4. Summarize the entire Set
    summary = infracheck.summarize_ipset(evaluations)

    print("[ IPSet Infrastructure Summary ]")

    prefixes = summary.get('most_specific_prefixes', [])
    print(f"1) Most specific prefixes: {', '.join(prefixes)}")

    avg_spec = format_colored_metric(summary.get('roa_average_specific', 0.0))
    print(f"2) ROA Average (Specific): {avg_spec}")

    avg_all = format_colored_metric(summary.get('roa_average_all', 0.0))
    print(f"3) ROA Average (All Deep): {avg_all}")

    asns = summary.get('asns', [])
    print(f"4) Associated ASNs:        {', '.join(asns)}")

    aspa_avg = format_colored_metric(summary.get('aspa_average', 0.0))
    print(f"5) Average ASPA status:    {aspa_avg}")

if __name__ == "__main__":
    asyncio.run(main())
