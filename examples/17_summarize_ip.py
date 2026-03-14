#!/usr/bin/env python3
import sys
import logging
import netinfracheck

# Disable debug logs to keep the console clean
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

def format_colored_metric(val: float | str, is_status: bool = False) -> str:
    """Formats the metric with ANSI colors according to strict thresholds."""
    c_reset = "\033[0m"
    c_green = "\033[1;32m"     # Bold Green
    c_yellow = "\033[1;33m"    # Bold Dark Yellow
    c_red = "\033[1;91m"       # Bold Bright Red

    if is_status:
        text = str(val).upper()
        # For direct status, VALID is green, everything else is red
        num = 1.0 if text == "VALID" else 0.0
    else:
        text = f"{float(val):.2f}"
        num = float(val)

    if num == 1.0:
        return f"{c_green}{text}{c_reset}"
    elif 0.5 < num < 1.0:
        return f"{c_yellow}{text}{c_reset}"
    else:
        return f"{c_red}{text}{c_reset}"

def main():
    ip = "1.1.1.1"
    print(f"=== Evaluating and Summarizing IP: {ip} ===")
    print("Fetching deep infrastructure data... Please wait.\n")

    # Generate the full JSON tree internally
    eval_dict = netinfracheck.evaluate_ip(ip, deep=True)

    # Process it through our new summary function
    summary = netinfracheck.summarize_ip(eval_dict)

    print("[ Final Summary ]")

    prefix = summary.get('most_specific_prefix')
    print(f"1) Most specific prefix: {prefix if prefix else 'None found'}")

    roa_stat = format_colored_metric(summary.get('roa_status', 'UNKNOWN'), is_status=True)
    print(f"2) ROA status:           {roa_stat}")

    roa_avg = format_colored_metric(summary.get('roa_average', 0.0))
    print(f"3) Average ROA status:   {roa_avg}")

    asns = summary.get('asns', [])
    print(f"4) Announcing ASNs:      {', '.join(asns) if asns else 'None found'}")

    aspa_avg = format_colored_metric(summary.get('aspa_average', 0.0))
    print(f"5) Average ASPA status:  {aspa_avg}")

if __name__ == "__main__":
    main()
