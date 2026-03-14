#!/usr/bin/env python3
import infracheck

def main():
    target_ip = "1.1.1.1"

    print(f"=== Synchronous Evaluation for {target_ip} (Standard) ===")
    json_result_standard = infracheck.evaluate_ip(target_ip, deep=False)
    print(json_result_standard)

    print(f"\n=== Synchronous Evaluation for {target_ip} (Deep) ===")
    json_result_deep = infracheck.evaluate_ip(target_ip, deep=True)
    print(json_result_deep)

if __name__ == "__main__":
    main()
