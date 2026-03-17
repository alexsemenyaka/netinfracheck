#!/usr/bin/env python3
import json
import netinfracheck

def main():
    target_ip = "1.1.1.1"

    print(f"=== Synchronous Evaluation for {target_ip} (Standard) ===")
    json_result_standard = netinfracheck.evaluate_ip(target_ip, deep=False)
    print(json.dumps(json_result_standard, indent=2))

    print(f"\n=== Synchronous Evaluation for {target_ip} (Deep) ===")
    json_result_deep = netinfracheck.evaluate_ip(target_ip, deep=True)
    print(json.dumps(json_result_deep, indent=2))

if __name__ == "__main__":
    main()
