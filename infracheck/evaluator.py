import json
import logging
import asyncio
from typing import Dict, Any, Union, List

from .checker import (
    has_roa,
    aio_has_roa,
    has_aspa,
    aio_has_aspa,
    has_dnssec,
    aio_has_dnssec,
)

from .utils import (
    resolve_domain,
    aio_resolve_domain,
    lg_data,
    aio_lg_data
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _evaluate_ip_dict(ip: str, deep: bool = False) -> Dict[str, Any]:
    """Internal synchronous function to evaluate an IP and bind ASNs to prefixes."""
    logger.debug(f"Evaluating IP {ip} (deep={deep})")

    announcements = lg_data(ip)
    routes = []

    if announcements:
        if deep:
            prefixes, statuses = has_roa(ip, deep=True)
            for i, (p, s) in enumerate(zip(prefixes, statuses, strict=True)):
                asn = announcements[i][1]
                routes.append({
                    "prefix": p,
                    "asn": asn,
                    "roa_status": s,
                    "aspa_status": has_aspa(asn)
                })
        else:
            p, s = has_roa(ip, deep=False)
            asn = announcements[0][1]
            routes.append({
                "prefix": p,
                "asn": asn,
                "roa_status": s,
                "aspa_status": has_aspa(asn)
            })

    return {
        "target": ip,
        "deep": deep,
        "routes": routes
    }


async def _aio_evaluate_ip_dict(ip: str, deep: bool = False) -> Dict[str, Any]:
    """Internal asynchronous function to evaluate an IP and bind ASNs to prefixes."""
    logger.debug(f"Async evaluating IP {ip} (deep={deep})")

    announcements = await aio_lg_data(ip)
    routes = []

    if announcements:
        unique_asns = list(set(a for p, a in announcements))
        aspa_tasks = [aio_has_aspa(asn) for asn in unique_asns]
        aspa_results = await asyncio.gather(*aspa_tasks)
        aspa_map = dict(zip(unique_asns, aspa_results, strict=True))

        if deep:
            prefixes, statuses = await aio_has_roa(ip, deep=True)
            for i, (p, s) in enumerate(zip(prefixes, statuses, strict=True)):
                asn = announcements[i][1]
                routes.append({
                    "prefix": p,
                    "asn": asn,
                    "roa_status": s,
                    "aspa_status": aspa_map[asn]
                })
        else:
            p, s = await aio_has_roa(ip, deep=False)
            asn = announcements[0][1]
            routes.append({
                "prefix": p,
                "asn": asn,
                "roa_status": s,
                "aspa_status": aspa_map[asn]
            })

    return {
        "target": ip,
        "deep": deep,
        "routes": routes
    }


def _evaluate_domain_dict(
    domain: str, deep: bool = False, ns: bool = False, mx: bool = False, soa: bool = False
) -> Dict[str, Any]:
    """Internal synchronous function to evaluate a domain recursively."""
    result: Dict[str, Any] = {"domain": domain, "dnssec": has_dnssec(domain, deep=deep), "ips": {}}
    if ns: result["ns"] = {}
    if mx: result["mx"] = {}
    if soa: result["soa"] = {}

    for ip in resolve_domain(domain, 'A'):
        result["ips"][ip] = _evaluate_ip_dict(ip, deep=deep)

    if ns:
        for record in resolve_domain(domain, 'NS'):
            ns_domain = record.rstrip('.')
            result["ns"][ns_domain] = _evaluate_domain_dict(ns_domain, deep, False, False, soa)

    if mx:
        for record in resolve_domain(domain, 'MX'):
            parts = record.split()
            if len(parts) > 1:
                mx_domain = parts[1].rstrip('.')
                result["mx"][mx_domain] = _evaluate_domain_dict(mx_domain, deep, True, False, soa)

    if soa:
        for record in resolve_domain(domain, 'SOA'):
            parts = record.split()
            if parts:
                soa_domain = parts[0].rstrip('.')
                result["soa"][soa_domain] = _evaluate_domain_dict(soa_domain, deep, True, False, soa)

    return result


async def _aio_evaluate_domain_dict(
    domain: str, deep: bool = False, ns: bool = False, mx: bool = False, soa: bool = False
) -> Dict[str, Any]:
    """Internal asynchronous function to evaluate a domain recursively."""
    result: Dict[str, Any] = {"domain": domain, "dnssec": False, "ips": {}}
    if ns: result["ns"] = {}
    if mx: result["mx"] = {}
    if soa: result["soa"] = {}

    dns_tasks = [aio_has_dnssec(domain, deep=deep), aio_resolve_domain(domain, 'A')]
    ns_idx, mx_idx, soa_idx = -1, -1, -1

    if ns:
        ns_idx = len(dns_tasks)
        dns_tasks.append(aio_resolve_domain(domain, 'NS'))
    if mx:
        mx_idx = len(dns_tasks)
        dns_tasks.append(aio_resolve_domain(domain, 'MX'))
    if soa:
        soa_idx = len(dns_tasks)
        dns_tasks.append(aio_resolve_domain(domain, 'SOA'))

    gathered = await asyncio.gather(*dns_tasks)
    result["dnssec"] = gathered[0]

    recursive_tasks = {}
    for ip in gathered[1]:
        recursive_tasks[("ip", ip)] = _aio_evaluate_ip_dict(ip, deep=deep)

    if ns:
        for record in gathered[ns_idx]:
            ns_domain = record.rstrip('.')
            recursive_tasks[("ns", ns_domain)] = _aio_evaluate_domain_dict(ns_domain, deep, False, False, soa)

    if mx:
        for record in gathered[mx_idx]:
            parts = record.split()
            if len(parts) > 1:
                mx_domain = parts[1].rstrip('.')
                recursive_tasks[("mx", mx_domain)] = _aio_evaluate_domain_dict(mx_domain, deep, True, False, soa)

    if soa:
        for record in gathered[soa_idx]:
            parts = record.split()
            if parts:
                soa_domain = parts[0].rstrip('.')
                recursive_tasks[("soa", soa_domain)] = _aio_evaluate_domain_dict(soa_domain, deep, True, False, soa)

    if recursive_tasks:
        keys = list(recursive_tasks.keys())
        results = await asyncio.gather(*list(recursive_tasks.values()))

        for (rtype, target), res in zip(keys, results, strict=True):
            if rtype == "ip": result["ips"][target] = res
            elif rtype == "ns": result["ns"][target] = res
            elif rtype == "mx": result["mx"][target] = res
            elif rtype == "soa": result["soa"][target] = res

    return result


def evaluate_ip(ip: str, deep: bool = False) -> str:
    """Synchronously evaluates an IP address and returns JSON."""
    return json.dumps(_evaluate_ip_dict(ip, deep=deep), indent=2)


async def aio_evaluate_ip(ip: str, deep: bool = False) -> str:
    """Asynchronously evaluates an IP address and returns JSON."""
    return json.dumps(await _aio_evaluate_ip_dict(ip, deep=deep), indent=2)


def evaluate_domain(
    domain: str, deep: bool = False, ns: bool = False, mx: bool = False, soa: bool = False
) -> str:
    """Synchronously evaluates a domain recursively and returns JSON."""
    return json.dumps(_evaluate_domain_dict(domain, deep=deep, ns=ns, mx=mx, soa=soa), indent=2)


async def aio_evaluate_domain(
    domain: str, deep: bool = False, ns: bool = False, mx: bool = False, soa: bool = False
) -> str:
    """Asynchronously evaluates a domain recursively and returns JSON."""
    return json.dumps(await _aio_evaluate_domain_dict(domain, deep=deep, ns=ns, mx=mx, soa=soa), indent=2)


def _calc_roa_avg(roa_dict: Dict[str, str]) -> float:
    """Helper to calculate ROA average, ignoring INVALID."""
    valid, total = 0, 0
    for status in roa_dict.values():
        s_up = str(status).upper()
        if s_up == "VALID":
            valid += 1
            total += 1
        elif s_up in ("NOT-FOUND", "NOT FOUND", "UNKNOWN"):
            total += 1
    return (valid / total) if total > 0 else 0.0


def summarize_ip(eval_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Summarizes a single IP evaluation JSON into strict metrics."""
    data = json.loads(eval_data) if isinstance(eval_data, str) else eval_data
    routes = data.get("routes", [])

    if not routes:
        return {
            "most_specific_prefix": None,
            "roa_status": "UNKNOWN",
            "roa_average": 0.0,
            "asns": [],
            "aspa_average": 0.0
        }

    ms_route = routes[0]
    ms_prefix = ms_route.get("prefix")

    # 3. Average ROA across all prefixes for this IP
    all_roas = {r.get("prefix"): r.get("roa_status") for r in routes if r.get("prefix")}
    roa_avg = _calc_roa_avg(all_roas)

    # 4. Gather ASNs that announce specifically the most specific prefix
    ms_asns = list(set(r.get("asn") for r in routes if r.get("prefix") == ms_prefix and r.get("asn")))

    # 5. Average ASPA for those exact ASNs
    valid_aspa = sum(1 for r in routes if r.get("prefix") == ms_prefix and r.get("aspa_status"))
    aspa_avg = (valid_aspa / len(ms_asns)) if ms_asns else 0.0

    return {
        "most_specific_prefix": ms_prefix,
        "roa_status": ms_route.get("roa_status", "UNKNOWN"),
        "roa_average": roa_avg,
        "asns": ms_asns,
        "aspa_average": aspa_avg
    }


def summarize_ipset(eval_datas: List[Union[str, Dict[str, Any]]]) -> Dict[str, Any]:
    """Summarizes an array of IP evaluations (e.g., all NS IPs) into aggregate metrics."""
    specific_prefixes = set()
    specific_roas = {}  # prefix -> status
    specific_asns = set()

    all_prefixes = set()
    all_roas = {}       # prefix -> status
    aspa_map = {}       # asn -> status

    for item in eval_datas:
        data = json.loads(item) if isinstance(item, str) else item
        routes = data.get("routes", [])
        if not routes:
            continue

        # Process the most specific prefix
        ms_route = routes[0]
        ms_p = ms_route.get("prefix")
        ms_roa = ms_route.get("roa_status")

        if ms_p:
            specific_prefixes.add(ms_p)
            specific_roas[ms_p] = ms_roa

        # Find all ASNs announcing this most specific prefix (handling multihoming)
        for r in routes:
            p = r.get("prefix")
            a = r.get("asn")
            if p:
                all_prefixes.add(p)
                all_roas[p] = r.get("roa_status")
            if a:
                aspa_map[a] = r.get("aspa_status")

            if p == ms_p and a:
                specific_asns.add(a)

    roa_avg_specific = _calc_roa_avg(specific_roas)
    roa_avg_all = _calc_roa_avg(all_roas)

    valid_aspa = sum(1 for asn in specific_asns if aspa_map.get(asn))
    aspa_avg = (valid_aspa / len(specific_asns)) if specific_asns else 0.0

    return {
        "most_specific_prefixes": list(specific_prefixes),
        "roa_average_specific": roa_avg_specific,
        "roa_average_all": roa_avg_all,
        "asns": list(specific_asns),
        "aspa_average": aspa_avg
    }
