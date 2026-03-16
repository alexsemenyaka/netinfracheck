#!/usr/bin/env python3
import sys
import asyncio
import logging
import netinfracheck

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

def format_colored_metric(val: float | bool, is_bool: bool = False) -> str:
    """Formats the value with strict ANSI colors."""
    c_reset = "\033[0m"
    c_green = "\033[1;32m"
    c_yellow = "\033[1;33m"
    c_red = "\033[1;91m"

    if is_bool:
        num = 1.0 if val else 0.0
        text = "VALID/SECURE" if val else "NONE/INVALID"
    else:
        num = float(val)
        text = f"{num:.2f}"

    if num == 1.0:
        return f"{c_green}{text}{c_reset}"
    elif 0.5 < num < 1.0:
        return f"{c_yellow}{text}{c_reset}"
    else:
        return f"{c_red}{text}{c_reset}"

def print_ipset(summary: dict, indent: str = "    "):
    """Helper to consistently print IPSet summaries."""
    if not summary:
        print(f"{indent}No IP infrastructure data found.")
        return

    prefixes = summary.get('most_specific_prefixes', [])
    print(f"{indent}Most specific prefixes: {', '.join(prefixes) if prefixes else 'None'}")

    avg_spec = format_colored_metric(summary.get('roa_average_specific', 0.0))
    print(f"{indent}ROA Avg (Specific):     {avg_spec}")

    avg_all = format_colored_metric(summary.get('roa_average_all', 0.0))
    print(f"{indent}ROA Avg (All Deep):     {avg_all}")

    asns = summary.get('asns', [])
    asns_str = ', '.join([f"AS{a}" for a in asns]) if asns else 'None'
    print(f"{indent}Announcing ASNs:        {asns_str}")

    aspa_avg = format_colored_metric(summary.get('aspa_average', 0.0))
    print(f"{indent}ASPA Status Average:    {aspa_avg}")

async def main():
    domain = "cloudflare.com"
    print(f"=== Deep Infrastructure Summary for {domain} ===\n")
    print("Fetching global DNS, PTR, DNSSEC, IPv4/IPv6, ROA, and ASPA data...")
    print("This will take a few seconds...\n")

    # Run the heavy recursive evaluation
    eval_json = await netinfracheck.aio_evaluate_domain(
        domain,
        deep=True,
        ns=True,
        mx=True,
        soa=False,
        resolvers=['8.8.8.8', '1.1.1.1']
    )

    # Process it into the high-level summary
    summary = netinfracheck.summarize_domain(eval_json)

    # Print the 9-point list
    dnssec_main = format_colored_metric(summary.get('dnssec', False), is_bool=True)
    print(f"1) Main Domain DNSSEC:            {dnssec_main}")

    backresolv_main = format_colored_metric(summary.get('backresolv', 0.0))
    print(f"2) Main Domain Backresolv (PTR):  {backresolv_main}")

    print("3) Main Domain IP Infrastructure (IPv4 & IPv6):")
    print_ipset(summary.get('ipset'))

    print("-" * 55)

    ns_dnssec = format_colored_metric(summary.get('ns_dnssec_average', 0.0))
    print(f"4) NS Domains DNSSEC Average:     {ns_dnssec}")

    ns_backresolv = format_colored_metric(summary.get('ns_backresolv_average', 0.0))
    print(f"5) NS Domains Backresolv Average: {ns_backresolv}")

    print("6) NS Servers IP Infrastructure (IPv4 & IPv6):")
    print_ipset(summary.get('ns_ipset'))

    print("-" * 55)

    mx_dnssec = format_colored_metric(summary.get('mx_dnssec_average', 0.0))
    print(f"7) MX Domains DNSSEC Average:     {mx_dnssec}")

    mx_backresolv = format_colored_metric(summary.get('mx_backresolv_average', 0.0))
    print(f"8) MX Domains Backresolv Average: {mx_backresolv}")

    print("9) MX Servers IP Infrastructure (IPv4 & IPv6):")
    print_ipset(summary.get('mx_ipset'))

if __name__ == "__main__":
    asyncio.run(main())
