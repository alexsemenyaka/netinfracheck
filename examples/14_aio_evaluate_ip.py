#!/usr/bin/env python3
import asyncio
import netinfracheck

async def main():
    target_ip = "8.8.8.8"

    print(f"=== Asynchronous Evaluation for {target_ip} (Standard) ===")
    json_result_standard = await netinfracheck.aio_evaluate_ip(target_ip, deep=False)
    print(json_result_standard)

    print(f"\n=== Asynchronous Evaluation for {target_ip} (Deep) ===")
    json_result_deep = await netinfracheck.aio_evaluate_ip(target_ip, deep=True)
    print(json_result_deep)

if __name__ == "__main__":
    asyncio.run(main())
