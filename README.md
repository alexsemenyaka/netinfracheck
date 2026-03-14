# netinfracheck Module Documentation

This module provides a suite of tools for synchronous and asynchronous auditing of network infrastructure, including RPKI validation (ROA, ASPA), BGP Origins checks, as well as analyzing DNSSEC status and PTR records quality (reverse resolving).

---

## 1. BGP & RPKI Checks

### `has_roa` / `aio_has_roa`
**Purpose:** Checks the Route Origin Authorization (ROA) status for a given IP address via the RIPE Stat API. This ensures the current route announcement is legitimate and protected against BGP hijacking.

**Arguments:** * `address` (str, required) — the target IP address or prefix.
* `deep` (bool, optional, default `False`) — if `True`, checks the entire chain of announcing prefixes (both less and more specific).

**Returns:** If `deep=False`, returns a tuple `(str: prefix, str: status)`. If `deep=True`, returns a tuple of two lists `(list[str]: prefixes, list[str]: statuses)`. Statuses can be `"VALID"`, `"INVALID"`, `"NOT-FOUND"`, or `"UNKNOWN"`.

**Errors and corner cases:** On network timeouts, API unavailability, or parsing errors, it does not crash but safely returns `(None, "UNKNOWN")` or empty lists.

### `get_origins` / `aio_get_origins`
**Purpose:** Extracts the list of unique Autonomous Systems (ASNs) that announce the specified IP address.

**Arguments:** * `address` (str, required) — the target IP address or prefix.

**Returns:** A list of strings containing AS numbers (e.g., `['AS13335']`).

**Errors and corner cases:** Returns an empty list `[]` if no data is found in the Looking Glass or if network errors occur.

### `has_aspa` / `aio_has_aspa`
**Purpose:** Checks for the presence of an Autonomous System Provider Authorization (ASPA) record to secure the routing path (AS-PATH). It uses the Cloudflare Radar API with a thread-safe (and async-safe) caching mechanism.

**Arguments:** * `asn` (str, required) — the Autonomous System Number (e.g., `"AS13335"` or `"13335"`).
* `cache_ttl` (int, optional, default `3600`) — cache time-to-live in seconds.

**Returns:** `bool` (`True` if ASPA exists, `False` otherwise) or `None` if the status is unknown.

**Errors and corner cases:** Returns `None` if the Cloudflare token is missing from the disk, if the API is unreachable with an empty cache, or if an invalid ASN format is provided.

---

## 2. DNS & Resolving Checks

### `has_dnssec` / `aio_has_dnssec`
**Purpose:** Validates the DNSSEC chain of trust. The function automatically walks up the DNS tree from the specified node to the zone apex (where the SOA record resides) before checking for the presence of DNSKEY and DS records.

**Arguments:** * `domain` (str, required) — the domain name or hostname.
* `deep` (bool, optional, default `False`) — if `True`, walks the chain of trust from the zone apex all the way to the root servers.

**Returns:** `bool` (`True` if DNSSEC is properly configured and keys are found, `False` if protection is missing or broken).

**Errors and corner cases:** Catches `NXDOMAIN` and timeouts (`NoAnswer`). If no SOA record is found while ascending to the root, it logs a warning and returns `False`.

### `check_backresolv` / `aio_check_backresolv`
**Purpose:** A metric for network hygiene. The function resolves a domain to its IP addresses (IPv4 and IPv6), performs a reverse lookup (PTR) for each IP, and checks if the resulting names match the original domain.

**Arguments:** * `domain` (str, required) — the domain name to check.

**Returns:** `float` (from `0.0` to `1.0`) — the fraction of successful reverse resolutions (e.g., if 2 out of 3 IPs resolve back to the original name, it returns `0.66`).

**Errors and corner cases:** If the domain has no A/AAAA records or if all PTR queries fail, it safely returns `0.0` without raising exceptions.

### `resolve_domain` / `aio_resolve_domain`
**Purpose:** A universal basic DNS resolving utility for the module's internal needs.

**Arguments:** * `domain` (str, required) — the domain name.
* `qtype` (str, optional, default `"A"`) — the requested DNS record type (`A`, `AAAA`, `NS`, `MX`, `SOA`).

**Returns:** A list of strings containing the resolved record values.

**Errors and corner cases:** Suppresses any resolution errors (including missing records) and returns an empty list.

### `lg_data` / `aio_lg_data`
**Purpose:** An internal utility to fetch and normalize raw routing data from the RIPE Stat Looking Glass API.

**Arguments:** * `resource` (str, required) — the target IP address or prefix.

**Returns:** A list of tuples `(prefix, ASN)`, sorted by mask length (from the most specific `/32` to the least specific `/8`).

**Errors and corner cases:** Returns an empty list on timeouts or HTTP errors. Automatically normalizes Autonomous System numbers by prepending `AS` if it is missing.

---

## 3. Data Evaluators

### `evaluate_ip` / `aio_evaluate_ip`
**Purpose:** Generates a detailed JSON report for a specific IP address. It queries the Looking Glass, strictly binds prefixes to their announcing ASNs, and collects ROA and ASPA statuses for each route.

**Arguments:** * `ip` (str, required) — the IP address to evaluate.
* `deep` (bool, optional, default `False`) — flag to enable deep ROA checks for the entire prefix chain.

**Returns:** A string in JSON format representing the structured infrastructure data.

**Errors and corner cases:** Resilient to network failures inside `has_roa` or `has_aspa`; uses safe fallback values in the JSON structure if upstream data is missing.

### `evaluate_domain` / `aio_evaluate_domain`
**Purpose:** Builds a comprehensive infrastructure tree for a domain. It gathers DNSSEC and PTR data, resolves IPv4/IPv6, and recursively collects the same metrics for name servers (NS), mail servers (MX), and the primary name server (SOA).

**Arguments:** * `domain` (str, required) — the target domain.
* `deep`, `ns`, `mx`, `soa` (bool, optional, default `False`) — flags to enable deep checks and specific branches of the DNS tree (NS, MX, SOA).

**Returns:** A string in JSON format representing the full multi-level structure.

**Errors and corner cases:** Ignores unreachable tree branches. For instance, if MX records are missing, the section remains empty without interrupting the rest of the evaluation process.

---

## 4. Data Summarizers

### `summarize_ip`
**Purpose:** Parses and condenses the JSON report generated by `evaluate_ip` into a flat set of high-level metrics.

**Arguments:** * `eval_data` (str or dict, required) — the JSON string or dictionary containing the IP evaluation results.

**Returns:** A dictionary with metrics: the most specific prefix, its ROA status, the average ROA score, a list of associated ASNs, and the average ASPA score.

**Errors and corner cases:** Excludes `INVALID` statuses from the denominator when calculating the ROA average, ensuring that potential hijackers do not skew the legitimate owner's statistics. Returns safe default zeroes if an empty report is provided.

### `summarize_ipset`
**Purpose:** Aggregates an array of `evaluate_ip` results (e.g., for a pool of NS addresses) into a single route protection score, correctly accounting for duplicate prefixes and autonomous systems.

**Arguments:** * `eval_datas` (list of str or dict, required) — a list of JSON reports for multiple IPs.

**Returns:** A dictionary with average ROA values (for both specific and deep prefixes) and ASPA, alongside lists of unique specific prefixes and ASNs.

**Errors and corner cases:** Correctly calculates averages even with an uneven distribution of IP addresses across servers; safely ignores empty results or missing data within the array.

### `summarize_domain`
**Purpose:** Transforms the massive JSON tree from `evaluate_domain` into a compact dictionary of 9 key infrastructure metrics (covering DNSSEC, PTR, and routing) suitable for quick console output.

**Arguments:** * `eval_data` (str or dict, required) — the JSON string or dictionary with the domain evaluation results.

**Returns:** A dictionary containing the DNSSEC status, Backresolv metric, and `summarize_ipset` results for the main domain, plus averaged values for the domains within the NS and MX branches.

**Errors and corner cases:** Robustly parses missing tree branches (e.g., if MX or NS evaluations were disabled or failed to resolve), safely substituting missing arrays with zeroes and `None`.
