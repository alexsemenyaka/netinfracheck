import logging

from rdnsresolver import resolve, aresolve, resolve_ptr, aresolve_ptr
import dns.asyncresolver
import dns.resolver
import dns.name
import rhttpx

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _parse_lg_response(data: dict) -> list:
    """Parses the raw JSON response from RIPE Stat Looking Glass."""
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
    """Synchronously retrieves and parses Looking Glass data for a resource."""
    url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={resource}"
    try:
        with rhttpx.RetryingClient(timeout=10.0) as client:
            response = client.get(url)
            response.raise_for_status()
            res = _parse_lg_response(response.json())
            logger.debug(f"Successfully retrieved LG data for {resource}: {len(res)} routes")
            return res
    except Exception as e:
        logger.error(f"Looking Glass query failed for {resource}: {e}")
        return []


async def aio_lg_data(resource: str) -> list:
    """Asynchronously retrieves and parses Looking Glass data for a resource."""
    url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={resource}"
    try:
        async with rhttpx.AsyncRetryingClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            res = _parse_lg_response(response.json())
            logger.debug(f"Async successfully retrieved LG data for {resource}: {len(res)} routes")
            return res
    except Exception as e:
        logger.error(f"Async Looking Glass query failed for {resource}: {e}")
        return []


def resolve_domain(domain: str, qtype: str = "A", resolvers: list = None) -> list:
    """Synchronously resolves a domain name for a specific DNS record type."""
    try:
        if resolvers is not None:
            dns.resolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        logger.debug(f"Resolving {qtype} records for {domain}")
        answers = resolve(domain, qtype)
        res = [str(rdata) for rdata in answers]
        logger.debug(f"Successfully resolved {qtype} for {domain}: {len(res)} records")
        return res
    except Exception as e:
        logger.warning(f"Resolution of {qtype} failed for {domain}: {e}")
        return []


async def aio_resolve_domain(domain: str, qtype: str = "A", resolvers: list = None) -> list:
    """Asynchronously resolves a domain name for a specific DNS record type."""
    try:
        if resolvers is not None:
            dns.asyncresolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        logger.debug(f"Async resolving {qtype} records for {domain}")
        answers = await aresolve(domain, qtype)
        res = [str(rdata) for rdata in answers]
        logger.debug(f"Async successfully resolved {qtype} for {domain}: {len(res)} records")
        return res
    except Exception as e:
        logger.warning(f"Async resolution of {qtype} failed for {domain}: {e}")
        return []


def get_zone_apex(domain: str, resolvers: list = None) -> dns.name.Name:
    """Synchronously finds the zone apex (where SOA is defined) for a domain."""
    try:
        if resolvers is not None:
            dns.resolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        current = dns.name.from_text(domain)
        while current != dns.name.root:
            try:
                resolve(current, dns.rdatatype.SOA)
                logger.debug(f"Found zone apex: {current} for domain {domain}")
                return current
            except Exception as e:
                logger.debug(f"Failed to get SOA for {current} ({e}), moving to parent {current.parent()}")
                current = current.parent()
        logger.warning(f"Reached root without finding SOA for {domain}")
        return dns.name.root
    except Exception as e:
        logger.error(f"Error while finding zone apex for {domain}: {e}")
        return dns.name.root


async def aio_get_zone_apex(domain: str, resolvers: list = None) -> dns.name.Name:
    """Asynchronously finds the zone apex (where SOA is defined) for a domain."""
    try:
        if resolvers is not None:
            dns.asyncresolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        current = dns.name.from_text(domain)
        while current != dns.name.root:
            try:
                await aresolve(current, dns.rdatatype.SOA)
                logger.debug(f"Async found zone apex: {current} for domain {domain}")
                return current
            except Exception as e:
                logger.debug(f"Async failed to get SOA for {current} ({e}), moving to parent {current.parent()}")
                current = current.parent()
        logger.warning(f"Async reached root without finding SOA for {domain}")
        return dns.name.root
    except Exception as e:
        logger.error(f"Async error while finding zone apex for {domain}: {e}")
        return dns.name.root


def find_ns(domain: str, resolvers: list = None) -> list:
    """Synchronously finds the authoritative Name Servers for a domain."""
    try:
        if resolvers is not None:
            dns.resolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        current = dns.name.from_text(domain)
        while current != dns.name.root:
            try:
                logger.debug(f"Attempting to find NS for {current}")
                answers = resolve(current, 'NS')
                res = [str(rdata) for rdata in answers]
                logger.debug(f"Successfully found NS for {domain} at {current}: {len(res)} records")
                return res
            except Exception as e:
                logger.debug(f"Failed to get NS for {current} ({e}), moving to parent {current.parent()}")
                current = current.parent()
        logger.warning(f"Reached root without finding NS for {domain}")
        return []
    except Exception as e:
        logger.warning(f"Failed to find NS for {domain}: {e}")
        return []


async def aio_find_ns(domain: str, resolvers: list = None) -> list:
    """Asynchronously finds the authoritative Name Servers for a domain."""
    try:
        if resolvers is not None:
            dns.asyncresolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        current = dns.name.from_text(domain)
        while current != dns.name.root:
            try:
                logger.debug(f"Async attempting to find NS for {current}")
                answers = await aresolve(current, 'NS')
                res = [str(rdata) for rdata in answers]
                logger.debug(f"Async successfully found NS for {domain} at {current}: {len(res)} records")
                return res
            except Exception as e:
                logger.debug(f"Async failed to get NS for {current} ({e}), moving to parent {current.parent()}")
                current = current.parent()
        logger.warning(f"Async reached root without finding NS for {domain}")
        return []
    except Exception as e:
        logger.warning(f"Async failed to find NS for {domain}: {e}")
        return []
