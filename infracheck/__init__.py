"""
infracheck: Infrastructural checks for IP addresses and domain names.

Provides comprehensive validation for ROA, ASPA, BGP Origins, and DNSSEC.
Supports both synchronous and asynchronous (aio_) execution.
"""

import importlib.metadata

from .checker import (
    aio_get_origins,
    aio_has_aspa,
    aio_has_dnssec,
    aio_has_roa,
    get_origins,
    has_aspa,
    has_dnssec,
    has_roa,
    check_backresolv,
    aio_check_backresolv,
)
from .utils import lg_data, aio_lg_data, resolve_domain, aio_resolve_domain
from .evaluator import (
    evaluate_ip,
    aio_evaluate_ip,
    evaluate_domain,
    aio_evaluate_domain,
    summarize_ip,
    summarize_ipset,
    summarize_domain,
)

try:
    _metadata = importlib.metadata.metadata("infracheck")
    __version__ = _metadata["Version"]
    __author__ = _metadata["Author-email"]
    __license__ = _metadata["License"]
except importlib.metadata.PackageNotFoundError:
    __version__ = "unknown"
    __author__ = "unknown"
    __license__ = "unknown"

__all__ = [
    "has_roa",
    "aio_has_roa",
    "get_origins",
    "aio_get_origins",
    "has_aspa",
    "aio_has_aspa",
    "has_dnssec",
    "aio_has_dnssec",
    "resolve_domain",
    "aio_resolve_domain",
    "lg_data",
    "aio_lg_data",
    "check_backresolv",
    "aio_check_backresolv",
    "evaluate_ip",
    "aio_evaluate_ip",
    "evaluate_domain",
    "aio_evaluate_domain",
    "summarize_ip",
    "summarize_ipset",
    "summarize_domain",
]
