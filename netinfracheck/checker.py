import os
import time
import logging
import threading
import asyncio
import rhttpx
import dns.name
import dns.resolver
import dns.asyncresolver
import dns.reversename
from rdnsresolver import resolve, aresolve, resolve_ptr, aresolve_ptr

from .utils import (
    lg_data,
    aio_lg_data,
    resolve_domain,
    aio_resolve_domain,
    get_zone_apex,
    aio_get_zone_apex
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_ASPA_CACHE = set()
_ASPA_CACHE_TIME = 0.0
_ASPA_SYNC_LOCK = threading.Lock()
_ASPA_ASYNC_LOCK = asyncio.Lock()


def _get_cf_token() -> str | None:
    """Reads the Cloudflare API token from the local filesystem."""
    token_path = os.path.expanduser("~/.local/cloudflare/radar-token")
    try:
        with open(token_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        logger.debug(f"Could not read Cloudflare token: {e}")
        return None


def _update_aspa_cache_sync(token: str, cache_ttl: int) -> bool:
    """Synchronously fetches and caches the ASPA snapshot from Cloudflare."""
    global _ASPA_CACHE, _ASPA_CACHE_TIME

    with _ASPA_SYNC_LOCK:
        if time.time() - _ASPA_CACHE_TIME < cache_ttl:
            return True

        try:
            url = "https://api.cloudflare.com/client/v4/radar/bgp/rpki/aspa/snapshot"
            headers = {"Authorization": f"Bearer {token}"}

            logger.info("Fetching new ASPA snapshot from Cloudflare Radar (Sync)...")
            with rhttpx.RetryingClient(timeout=15.0) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()

                aspa_objects = data.get("result", {}).get("aspaObjects", [])
                new_cache = set()
                for obj in aspa_objects:
                    customer_asn = obj.get("customerAsn")
                    if customer_asn is not None:
                        new_cache.add(int(customer_asn))

                _ASPA_CACHE = new_cache
                _ASPA_CACHE_TIME = time.time()
                logger.debug(f"ASPA sync cache updated with {len(_ASPA_CACHE)} records.")
                return True

        except Exception as e:
            logger.error(f"Failed to update ASPA cache: {e}")
            return False


async def _update_aspa_cache_async(token: str, cache_ttl: int) -> bool:
    """Asynchronously fetches and caches the ASPA snapshot from Cloudflare."""
    global _ASPA_CACHE, _ASPA_CACHE_TIME

    async with _ASPA_ASYNC_LOCK:
        if time.time() - _ASPA_CACHE_TIME < cache_ttl:
            return True

        try:
            url = "https://api.cloudflare.com/client/v4/radar/bgp/rpki/aspa/snapshot"
            headers = {"Authorization": f"Bearer {token}"}

            logger.info("Fetching new ASPA snapshot from Cloudflare Radar (Async)...")
            async with rhttpx.AsyncRetryingClient(timeout=15.0) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()

                aspa_objects = data.get("result", {}).get("aspaObjects", [])
                new_cache = set()
                for obj in aspa_objects:
                    customer_asn = obj.get("customerAsn")
                    if customer_asn is not None:
                        new_cache.add(int(customer_asn))

                _ASPA_CACHE = new_cache
                _ASPA_CACHE_TIME = time.time()
                logger.debug(f"ASPA async cache updated with {len(_ASPA_CACHE)} records.")
                return True

        except Exception as e:
            logger.error(f"Failed to update async ASPA cache: {e}")
            return False


def has_roa(address: str, deep: bool = False):
    """Synchronously checks the RPKI ROA status for a given IP address."""
    announcements = lg_data(address)
    if not announcements:
        logger.debug(f"No BGP announcements found for {address}")
        return (None, "UNKNOWN") if not deep else ([], [])

    try:
        with rhttpx.RetryingClient(timeout=10.0) as client:
            def check_rpki(prefix, asn):
                url = (
                    f"https://stat.ripe.net/data/rpki-validation/data.json"
                    f"?resource={asn}&prefix={prefix}"
                )
                response = client.get(url)
                response.raise_for_status()
                status = response.json().get('data', {}).get('status', 'unknown').upper()
                logger.debug(f"ROA check for {prefix} {asn}: {status}")
                return status

            if not deep:
                target_prefix, target_asn = announcements[0]
                return target_prefix, check_rpki(target_prefix, target_asn)

            prefixes, verdicts = [], []
            for p, a in announcements:
                prefixes.append(p)
                verdicts.append(check_rpki(p, a))
            logger.debug(f"Deep ROA check for {address} completed successfully.")
            return prefixes, verdicts

    except Exception as e:
        logger.exception(f"ROA check failed for {address}: {e}")
        return (None, "UNKNOWN") if not deep else ([], [])


async def aio_has_roa(address: str, deep: bool = False):
    """Asynchronously checks the RPKI ROA status for a given IP address."""
    announcements = await aio_lg_data(address)
    if not announcements:
        logger.debug(f"Async: No BGP announcements found for {address}")
        return (None, "UNKNOWN") if not deep else ([], [])

    try:
        async with rhttpx.AsyncRetryingClient(timeout=10.0) as client:
            async def check_rpki(prefix, asn):
                url = (
                    f"https://stat.ripe.net/data/rpki-validation/data.json"
                    f"?resource={asn}&prefix={prefix}"
                )
                response = await client.get(url)
                response.raise_for_status()
                status = response.json().get('data', {}).get('status', 'unknown').upper()
                logger.debug(f"Async ROA check for {prefix} {asn}: {status}")
                return status

            if not deep:
                target_prefix, target_asn = announcements[0]
                return target_prefix, await check_rpki(target_prefix, target_asn)

            prefixes, verdicts = [], []
            for p, a in announcements:
                prefixes.append(p)
                verdicts.append(await check_rpki(p, a))
            logger.debug(f"Async deep ROA check for {address} completed successfully.")
            return prefixes, verdicts

    except Exception as e:
        logger.exception(f"Async ROA check failed for {address}: {e}")
        return (None, "UNKNOWN") if not deep else ([], [])


def get_origins(address: str) -> list:
    """Synchronously retrieves the originating ASNs for an IP address."""
    try:
        announcements = lg_data(address)
        asns = {asn for prefix, asn in announcements if asn}
        logger.debug(f"Origins for {address} retrieved: {list(asns)}")
        return list(asns)
    except Exception as e:
        logger.error(f"Error in get_origins for {address}: {e}")
        return []


async def aio_get_origins(address: str) -> list:
    """Asynchronously retrieves the originating ASNs for an IP address."""
    try:
        announcements = await aio_lg_data(address)
        asns = {asn for prefix, asn in announcements if asn}
        logger.debug(f"Async origins for {address} retrieved: {list(asns)}")
        return list(asns)
    except Exception as e:
        logger.error(f"Error in aio_get_origins for {address}: {e}")
        return []


def has_aspa(asn: str, cache_ttl: int = 3600) -> bool | None:
    """Synchronously checks if there are ASPA records for the given ASN."""
    token = _get_cf_token()
    if not token:
        logger.debug("Cloudflare token not found, skipping ASPA check.")
        return None

    if time.time() - _ASPA_CACHE_TIME > cache_ttl:
        success = _update_aspa_cache_sync(token, cache_ttl)
        if not success and not _ASPA_CACHE:
            return None

    try:
        clean_asn = int(asn.upper().replace("AS", ""))
        has_record = clean_asn in _ASPA_CACHE
        logger.debug(f"ASPA check for {asn}: {has_record}")
        return has_record
    except ValueError:
        logger.error(f"Invalid ASN format provided: {asn}")
        return None


async def aio_has_aspa(asn: str, cache_ttl: int = 3600) -> bool | None:
    """Asynchronously checks if there are ASPA records for the given ASN."""
    token = _get_cf_token()
    if not token:
        logger.debug("Cloudflare token not found, skipping async ASPA check.")
        return None

    if time.time() - _ASPA_CACHE_TIME > cache_ttl:
        success = await _update_aspa_cache_async(token, cache_ttl)
        if not success and not _ASPA_CACHE:
            return None

    try:
        clean_asn = int(asn.upper().replace("AS", ""))
        has_record = clean_asn in _ASPA_CACHE
        logger.debug(f"Async ASPA check for {asn}: {has_record}")
        return has_record
    except ValueError:
        logger.error(f"Invalid ASN format provided: {asn}")
        return None


def has_dnssec(domain: str, resolvers: list = None, deep: bool = False) -> bool:
    """Synchronously checks if a domain (or its parent zone) has DNSSEC enabled."""
    try:
        if resolvers is not None:
            dns.resolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        zone_apex = get_zone_apex(domain, resolvers=resolvers)

        if zone_apex == dns.name.root:
            logger.warning(f"Could not find SOA for {domain} before hitting root.")
            return False

        logger.debug(f"Found zone apex for {domain}: {zone_apex}")
        current = zone_apex

        if not deep:
            try:
                resolve(current, dns.rdatatype.DNSKEY)
                resolve(current, dns.rdatatype.DS)
                logger.debug(f"DNSSEC shallow check passed for {domain} at {current}")
                return True
            except Exception as e:
                logger.debug(f"DNSSEC shallow check failed for {domain} at {current}: {e}")
                return False

        while True:
            logger.debug(f"Deep check: verifying zone {current}")
            try:
                resolve(current, dns.rdatatype.DNSKEY)
            except Exception as e:
                logger.error(f"DNSSEC break: No DNSKEY found for {current} ({e})")
                return False

            if current == dns.name.root:
                logger.debug(f"DNSSEC deep check completed successfully up to root for {domain}")
                return True

            parent = current.parent()
            try:
                resolve(current, dns.rdatatype.DS)
            except Exception as e:
                logger.error(f"DNSSEC break: No DS record for {current} in zone {parent} ({e})")
                return False

            current = parent

    except Exception as e:
        logger.exception(f"DNSSEC validation error for {domain}: {e}")
        return False


async def aio_has_dnssec(domain: str, resolvers: list = None, deep: bool = False) -> bool:
    """Asynchronously checks if a domain (or its parent zone) has DNSSEC enabled."""
    try:
        if resolvers is not None:
            dns.asyncresolver.get_default_resolver().nameservers = resolvers
            logger.debug(f"DNS resolvers are set to {resolvers}")

        zone_apex = await aio_get_zone_apex(domain, resolvers=resolvers)

        if zone_apex == dns.name.root:
            logger.warning(f"Async could not find SOA for {domain} before hitting root.")
            return False

        logger.debug(f"Async found zone apex for {domain}: {zone_apex}")
        current = zone_apex

        if not deep:
            try:
                await aresolve(current, dns.rdatatype.DNSKEY)
                await aresolve(current, dns.rdatatype.DS)
                logger.debug(f"Async DNSSEC shallow check passed for {domain} at {current}")
                return True
            except Exception as e:
                logger.debug(f"Async DNSSEC shallow check failed for {domain} at {current}: {e}")
                return False

        while True:
            logger.debug(f"Async deep check: verifying zone {current}")
            try:
                await aresolve(current, dns.rdatatype.DNSKEY)
            except Exception as e:
                logger.error(f"DNSSEC break: No DNSKEY found for {current} ({e})")
                return False

            if current == dns.name.root:
                logger.debug(f"Async DNSSEC deep check completed successfully up to root for {domain}")
                return True

            parent = current.parent()
            try:
                await aresolve(current, dns.rdatatype.DS)
            except Exception as e:
                logger.error(f"DNSSEC break: No DS record for {current} in zone {parent} ({e})")
                return False

            current = parent

    except Exception as e:
        logger.exception(f"Async DNSSEC validation error for {domain}: {e}")
        return False


def check_backresolv(domain: str, resolvers: list = None) -> float:
    """Synchronously checks the fraction of PTR records that match the domain."""
    if resolvers is not None:
        dns.resolver.get_default_resolver().nameservers = resolvers
        logger.debug(f"DNS resolvers are set to {resolvers}")

    ips = resolve_domain(domain, 'A', resolvers=resolvers) + resolve_domain(domain, 'AAAA', resolvers=resolvers)
    if not ips:
        logger.debug(f"No IP addresses found for PTR check of {domain}")
        return 0.0

    ptr_names = []
    for ip in ips:
        try:
            answers = resolve_ptr(ip)
            for rdata in answers:
                ptr_names.append(rdata.target.to_text().rstrip('.'))
        except Exception as e:
            logger.debug(f"PTR resolution failed for IP {ip} ({domain}): {e}")

    if not ptr_names:
        logger.debug(f"No PTR records returned for any IPs of {domain}")
        return 0.0

    matches = sum(1 for name in ptr_names if name.lower() == domain.lower())
    fraction = matches / len(ptr_names)
    logger.debug(f"Backresolv matched {matches}/{len(ptr_names)} ({fraction:.2f}) for {domain}")
    return fraction


async def aio_check_backresolv(domain: str, resolvers: list = None) -> float:
    """Asynchronously checks the fraction of PTR records that match the domain."""
    if resolvers is not None:
        dns.asyncresolver.get_default_resolver().nameservers = resolvers
        logger.debug(f"DNS resolvers are set to {resolvers}")

    ips_a, ips_aaaa = await asyncio.gather(
        aio_resolve_domain(domain, 'A', resolvers=resolvers),
        aio_resolve_domain(domain, 'AAAA', resolvers=resolvers)
    )
    ips = ips_a + ips_aaaa
    if not ips:
        logger.debug(f"Async: No IP addresses found for PTR check of {domain}")
        return 0.0

    ptr_names = []
    async def fetch_ptr(ip):
        try:
            answers = await aresolve(ip)
            return [rdata.target.to_text().rstrip('.') for rdata in answers]
        except Exception as e:
            logger.debug(f"Async PTR resolution failed for IP {ip} ({domain}): {e}")
            return []

    results = await asyncio.gather(*(fetch_ptr(ip) for ip in ips))
    for res in results:
        ptr_names.extend(res)

    if not ptr_names:
        logger.debug(f"Async: No PTR records returned for any IPs of {domain}")
        return 0.0

    matches = sum(1 for name in ptr_names if name.lower() == domain.lower())
    fraction = matches / len(ptr_names)
    logger.debug(f"Async backresolv matched {matches}/{len(ptr_names)} ({fraction:.2f}) for {domain}")
    return fraction
