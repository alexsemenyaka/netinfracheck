import logging

import dns.asyncresolver
import dns.resolver
import dns.name
import httpx

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _parse_lg_response(data: dict) -> list:
    """Parses the raw JSON response from RIPE Stat Looking Glass.

    Extracts BGP announcements and normalizes AS numbers.

    Args:
        data (dict): The parsed JSON data dictionary from the API.

    Returns:
        list: A list of tuples (prefix, asn) sorted by prefix length
        (most specific first).
    """
    announcements = set()
    for rrc in data.get("data", {}).get("rrcs", []):
        for peer in rrc.get("peers", []):
            prefix = peer.get("prefix")
            asn = peer.get("asn_origin")

            if prefix and asn:
                asn_str = str(asn).upper()
                if not asn_str.startswith("AS"):
                    asn_str = f"AS{asn_str}"
                announcements.add((prefix, asn_str))

    return sorted(list(announcements), key=lambda x: int(x[0].split("/")[-1]), reverse=True)


def lg_data(resource: str) -> list:
    """Synchronously retrieves and parses Looking Glass data for a resource.

    Args:
        resource (str): An IP address or BGP prefix.

    Returns:
        list: A sorted list of (prefix, asn) tuples, or an empty list on failure.
    """
    url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={resource}"
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(url)
            response.raise_for_status()
            return _parse_lg_response(response.json())
    except Exception as e:
        logger.error(f"Looking Glass query failed for {resource}: {e}")
        return []


async def aio_lg_data(resource: str) -> list:
    """Asynchronously retrieves and parses Looking Glass data for a resource.

    Args:
        resource (str): An IP address or BGP prefix.

    Returns:
        list: A sorted list of (prefix, asn) tuples, or an empty list on failure.
    """
    url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={resource}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            return _parse_lg_response(response.json())
    except Exception as e:
        logger.error(f"Async Looking Glass query failed for {resource}: {e}")
        return []


def resolve_domain(domain: str, qtype: str = "A") -> list:
    """Synchronously resolves a domain name for a specific DNS record type.

    Args:
        domain (str): The domain name to resolve.
        qtype (str): The DNS record type to query (e.g., 'A', 'NS', 'MX', 'SOA').
                     Defaults to 'A'.

    Returns:
        list: A list of resolved records as strings, or an empty list on failure.
    """
    try:
        logger.debug(f"Resolving {qtype} records for {domain}")
        answers = dns.resolver.resolve(domain, qtype)
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.warning(f"Resolution of {qtype} failed for {domain}: {e}")
        return []


async def aio_resolve_domain(domain: str, qtype: str = "A") -> list:
    """Asynchronously resolves a domain name for a specific DNS record type.

    Args:
        domain (str): The domain name to resolve.
        qtype (str): The DNS record type to query (e.g., 'A', 'NS', 'MX', 'SOA').
                     Defaults to 'A'.

    Returns:
        list: A list of resolved records as strings, or an empty list on failure.
    """
    try:
        logger.debug(f"Async resolving {qtype} records for {domain}")
        answers = await dns.asyncresolver.resolve(domain, qtype)
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.warning(f"Async resolution of {qtype} failed for {domain}: {e}")
        return []


def get_zone_apex(domain: str) -> dns.name.Name:
    """Synchronously finds the zone apex (where SOA is defined) for a domain."""
    try:
        target_name = dns.name.from_text(domain)
        current = target_name
        while current != dns.name.root:
            try:
                dns.resolver.resolve(current, dns.rdatatype.SOA)
                return current
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                current = current.parent()
        return dns.name.root
    except Exception:
        return dns.name.root


async def aio_get_zone_apex(domain: str) -> dns.name.Name:
    """Asynchronously finds the zone apex for a domain."""
    try:
        target_name = dns.name.from_text(domain)
        current = target_name
        while current != dns.name.root:
            try:
                await dns.asyncresolver.resolve(current, dns.rdatatype.SOA)
                return current
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                current = current.parent()
        return dns.name.root
    except Exception:
        return dns.name.root


def find_ns(domain: str) -> list:
    """Synchronously finds the authoritative Name Servers for a domain.

    Uses the zone apex to reliably locate NS records even for hosts
    without explicit delegation.
    """
    try:
        apex = get_zone_apex(domain)
        if apex == dns.name.root:
            return []
        logger.debug(f"Attempting to find NS for {apex}")
        answers = dns.resolver.resolve(apex, 'NS')
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.warning(f"Failed to find NS for {domain}: {e}")
        return []


async def aio_find_ns(domain: str) -> list:
    """Asynchronously finds the authoritative Name Servers for a domain."""
    try:
        apex = await aio_get_zone_apex(domain)
        if apex == dns.name.root:
            return []
        logger.debug(f"Async attempting to find NS for {apex}")
        answers = await dns.asyncresolver.resolve(apex, 'NS')
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.warning(f"Async failed to find NS for {domain}: {e}")
        return []
