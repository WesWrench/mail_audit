"""
DomainAvailabilityChecker — three-stage domain availability pipeline.

Stage 1  DNS NS lookup
         → NS found          ⇒ UNAVAILABLE
         → NXDOMAIN          ⇒ proceed (might be reserved/premium)
         → timeout / error   ⇒ proceed

Stage 2  WHOIS (hybridwhois)
         → available=False   ⇒ UNAVAILABLE
         → available=True    ⇒ proceed to stage 3
         → available=None    ⇒ proceed to stage 3

Stage 3  Service checker (DomainAvailabilityServiceChecker)
         → available=True    ⇒ AVAILABLE
         → available=False   ⇒ UNAVAILABLE
         → available=None    ⇒ UNKNOWN
"""

from __future__ import annotations

import asyncio
import sys
import os
from typing import Callable, Awaitable

# Allow sibling packages to be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hybridwhois
from .dns_check import check_ns_async, DNSResult

# ---------------------------------------------------------------------------
# Availability status constants
# ---------------------------------------------------------------------------

STATUS_AVAILABLE   = "available"
STATUS_UNAVAILABLE = "unavailable"
STATUS_UNKNOWN     = "unknown"

# WHOIS domain_status values that mean "not available to register"
_UNAVAILABLE_STATUSES = frozenset({
    "reserved",
    "hold",
    "on-hold",
    "serverhold",
    "clienthold",
    "pendingdelete",
    "pendingcreate",
    "redemptionperiod",
    "pendingrestore",
    "banned",
    "blocked",
    "inactive",
    "prohibited",
    "quarantined",
})


def _whois_says_unavailable(whois_result: dict) -> bool:
    """Return True if the WHOIS result clearly indicates the domain is taken/reserved."""
    if whois_result.get("available") is False:
        return True
    for status in whois_result.get("domain_status") or []:
        if status.lower() in _UNAVAILABLE_STATUSES:
            return True
    return False


def _whois_says_available(whois_result: dict) -> bool:
    return whois_result.get("available") is True


def _build_result(
    domain:   str,
    status:   str,
    reason:   str,
    dns_r:    DNSResult | None,
    whois_r:  dict | None,
    svc_r:    dict | None,
    include_details: bool,
) -> dict:
    result: dict = {
        "domain":    domain,
        "status":    status,
        "available": status == STATUS_AVAILABLE,
        "reason":    reason,
    }
    if include_details:
        result["details"] = {
            "dns":     dns_r.to_dict()  if dns_r   else None,
            "whois":   whois_r          if whois_r  else None,
            "service": svc_r            if svc_r    else None,
        }
    return result


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class DomainAvailabilityChecker:
    """
    Three-stage domain availability checker: DNS → WHOIS → service checker.

    Parameters
    ----------
    max_total_concurrent:
        Maximum number of simultaneous in-flight queries across all stages and
        both underlying WHOIS/RDAP libraries.  Maps to ``max_total_concurrent``
        in the RDAP pool and ``max_concurrent`` in the WHOIS pool.
        ``None`` = no global limit.
    service_checker_sources:
        List of sources for :class:`DomainAvailabilityServiceChecker`.
        Valid values: ``"namecheap"``, ``"gandi"``, ``"wix"``, ``"ovh"``.
        Default: ``["namecheap"]``.
    service_checker_mode:
        ``"lax"`` (default) or ``"strict"``.
        ``"lax"`` = available if at least one source says so.
        ``"strict"`` = available only if all non-error sources agree.
    include_details:
        If ``True``, each result includes a ``"details"`` dict with raw DNS,
        WHOIS, and service-checker output.  Default: ``False``.
    whois_options:
        Extra kwargs forwarded to ``whoisitlegacy.domain_async()``.
    rdap_options:
        Extra kwargs forwarded to ``whoisit.domain_async()``.
    sleep_between_request:
        Global sleep between requests for all service-checker providers.
        Accepted formats: ``5`` (fixed 5 s), ``[5]`` (fixed 5 s),
        ``[5, 10]`` (random 5–10 s).  Default: ``[5, 10]``.
    sleep_source:
        Per-source sleep overrides, e.g.
        ``{"namecheap": [5, 10], "ovh": [3, 20]}``.
        Overrides ``sleep_between_request`` for the listed sources.
    """

    def __init__(
        self,
        max_total_concurrent:      int | None = None,
        service_checker_sources:   list[str] | None = None,
        service_checker_mode:      str = "lax",
        include_details:           bool = False,
        whois_options:             dict | None = None,
        rdap_options:              dict | None = None,
        sleep_between_request=None,
        sleep_source:              dict | None = None,
    ) -> None:
        self.include_details = include_details
        self.max_total_concurrent = max_total_concurrent

        # WHOIS + RDAP pools
        self._rdap_pool  = hybridwhois.create_rdap_pool(
            max_total_concurrent=max_total_concurrent,
        )
        self._whois_pool = hybridwhois.create_whois_pool(
            max_concurrent=max_total_concurrent,
        )
        self._whois_options = whois_options or {}
        self._rdap_options  = rdap_options  or {}

        # Service checker (stage 3) is optional: without the
        # domain_availability_service_checker package, stages 1-2 (NS, WHOIS/RDAP)
        # still run and inconclusive domains end as STATUS_UNKNOWN.
        sources = service_checker_sources or ["namecheap"]
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        self._service_checker = None
        self.service_checker_error: str | None = None
        try:
            from domain_availability_service_checker import DomainAvailabilityServiceChecker
            self._service_checker = DomainAvailabilityServiceChecker(
                sources=sources,
                mode=service_checker_mode,
                async_mode=True,
                sleep_between_request=sleep_between_request,
                sleep_source=sleep_source,
            )
        except Exception as exc:  # package removed or broken
            self.service_checker_error = f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _whois_check(self, domain: str) -> dict:
        """Run hybridwhois and return the normalised result."""
        try:
            return await hybridwhois.domain_async(
                domain,
                rdap_pool=self._rdap_pool,
                whois_pool=self._whois_pool,
                whois_options=self._whois_options or None,
                rdap_options=self._rdap_options  or None,
            )
        except Exception as exc:
            return {
                "available": None,
                "domain_status": [],
                "is_service_error": True,
                "_error": str(exc),
            }

    def _service_check_batch(self, domains: list[str]) -> dict[str, dict]:
        """
        Run the service checker on *domains* and return {domain: result_dict}.
        """
        if self._service_checker is None:
            reason = f"service checker unavailable ({self.service_checker_error})"
            return {d: {"domain": d, "available": None, "_error": reason} for d in domains}
        try:
            results = self._service_checker.check_domains_status(domains)
            return {r["domain"]: r for r in results}
        except Exception as exc:
            return {d: {"domain": d, "available": None, "_error": str(exc)}
                    for d in domains}

    async def _service_check_batch_async(
        self, domains: list[str]
    ) -> dict[str, dict]:
        """Run the (sync) service checker in a thread pool to avoid blocking."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._service_check_batch, domains
        )

    # ------------------------------------------------------------------ #
    # Single-domain pipeline
    # ------------------------------------------------------------------ #

    def _stage3_to_result(
        self,
        domain:   str,
        svc_data: dict,
        dns_r:    DNSResult,
        whois_r:  dict | None,
    ) -> dict:
        available = svc_data.get("available")
        if available is True:
            return _build_result(domain, STATUS_AVAILABLE,   "service_available",
                                 dns_r, whois_r, svc_data, self.include_details)
        if available is False:
            return _build_result(domain, STATUS_UNAVAILABLE, "service_unavailable",
                                 dns_r, whois_r, svc_data, self.include_details)
        return     _build_result(domain, STATUS_UNKNOWN,     "service_unknown",
                                 dns_r, whois_r, svc_data, self.include_details)

    # ------------------------------------------------------------------ #
    # Public sync API
    # ------------------------------------------------------------------ #

    def check_domain(self, domain: str) -> dict:
        """Check availability for a single domain (synchronous)."""
        return asyncio.run(self._check_domain_async_internal(domain))

    def check_domains(self, domains: list[str]) -> dict[str, dict]:
        """
        Check availability for multiple domains (synchronous).

        Returns ``{domain: result}`` dict.
        """
        return asyncio.run(self.check_domains_async(domains))

    # ------------------------------------------------------------------ #
    # Public async API
    # ------------------------------------------------------------------ #

    async def check_domain_async(self, domain: str) -> dict:
        """Check availability for a single domain (async)."""
        return await self._check_domain_async_internal(domain)

    async def check_domains_async(
        self,
        domains: list[str],
        callback: "Callable[[dict], Awaitable[None] | None] | None" = None,
        concurrency: int = 10,
    ) -> dict[str, dict]:
        """
        Check availability for multiple domains (async, batched pipeline).

        Stage 1 (DNS) and stage 2 (WHOIS) run concurrently across all domains;
        callbacks fire as each domain is resolved.  Stage 3 sends **all**
        remaining domains to the service checker in one batched call
        (DomainAvailabilityServiceChecker handles internal 64-domain chunking).

        Parameters
        ----------
        domains:
            List of fully-qualified domain names.
        callback:
            Optional callable invoked with each result as it completes.
            May be sync or async.
        concurrency:
            Maximum number of simultaneous WHOIS/RDAP checks in stage 2.
        """
        resolved:      dict[str, dict]    = {}
        dns_results:   dict[str, DNSResult] = {}
        whois_results: dict[str, dict]    = {}
        stage2_domains: list[str] = []
        stage3_domains: list[str] = []
        semaphore   = asyncio.Semaphore(concurrency)
        append_lock = asyncio.Lock()

        async def _invoke_cb(result: dict) -> None:
            if callback is not None:
                ret = callback(result)
                if asyncio.isfuture(ret) or asyncio.iscoroutine(ret):
                    await ret

        # ── Stage 1: DNS – all in parallel, streaming callbacks ──────────
        async def _dns_task(domain: str) -> None:
            dns_r = await check_ns_async(domain)
            dns_results[domain] = dns_r
            if dns_r.has_ns:
                r = _build_result(domain, STATUS_UNAVAILABLE, "has_ns",
                                  dns_r, None, None, self.include_details)
                resolved[domain] = r
                await _invoke_cb(r)
            else:
                async with append_lock:
                    stage2_domains.append(domain)

        await asyncio.gather(*[_dns_task(d) for d in domains])

        if not stage2_domains:
            return resolved

        # ── Stage 2: WHOIS – concurrency-limited, streaming callbacks ────
        async def _whois_task(domain: str) -> None:
            async with semaphore:
                whois_r = await self._whois_check(domain)
            whois_results[domain] = whois_r
            if _whois_says_unavailable(whois_r):
                r = _build_result(domain, STATUS_UNAVAILABLE, "whois_unavailable",
                                  dns_results[domain], whois_r, None, self.include_details)
                resolved[domain] = r
                await _invoke_cb(r)
            elif _whois_says_available(whois_r):
                r = _build_result(domain, STATUS_AVAILABLE, "whois_available",
                                  dns_results[domain], whois_r, None, self.include_details)
                resolved[domain] = r
                await _invoke_cb(r)
            else:
                async with append_lock:
                    stage3_domains.append(domain)

        await asyncio.gather(*[_whois_task(d) for d in stage2_domains])

        if not stage3_domains:
            return resolved

        # ── Stage 3: service checker – single batched call ────────────────
        # DomainAvailabilityServiceChecker handles internal 64-domain chunking
        svc_batch = await self._service_check_batch_async(stage3_domains)
        for domain in stage3_domains:
            svc_data = svc_batch.get(domain, {"available": None})
            r = self._stage3_to_result(
                domain, svc_data,
                dns_results[domain], whois_results.get(domain),
            )
            resolved[domain] = r
            await _invoke_cb(r)

        return resolved

    # ------------------------------------------------------------------ #
    # Internal pipeline (single domain — no service-check batching)
    # ------------------------------------------------------------------ #

    async def _check_domain_async_internal(self, domain: str) -> dict:
        """Full three-stage pipeline for a single domain."""
        # ── Stage 1: DNS ──────────────────────────────────────────────────
        dns_r = await check_ns_async(domain)

        if dns_r.has_ns:
            return _build_result(domain, STATUS_UNAVAILABLE, "has_ns",
                                 dns_r, None, None, self.include_details)

        # ── Stage 2: WHOIS ────────────────────────────────────────────────
        whois_r = await self._whois_check(domain)

        if _whois_says_unavailable(whois_r):
            return _build_result(domain, STATUS_UNAVAILABLE, "whois_unavailable",
                                 dns_r, whois_r, None, self.include_details)

        if _whois_says_available(whois_r):
            return _build_result(domain, STATUS_AVAILABLE, "whois_available",
                                 dns_r, whois_r, None, self.include_details)

        # ── Stage 3: Service checker (single-domain call) ─────────────────
        svc_batch = await self._service_check_batch_async([domain])
        svc_data  = svc_batch.get(domain, {"available": None})
        return self._stage3_to_result(domain, svc_data, dns_r, whois_r)

    # ------------------------------------------------------------------ #
    # Optimised batch pipeline (batches service-checker calls)
    # ------------------------------------------------------------------ #

    async def _check_domains_pipeline(
        self, domains: list[str]
    ) -> dict[str, dict]:
        """
        Optimised multi-domain pipeline that batches the service checker call.

        Stage 1 (DNS) and stage 2 (WHOIS) run in parallel across all domains.
        Domains resolved after stage 1 or 2 are collected; the remainder go to
        a single batched service-checker call.
        """
        resolved: dict[str, dict] = {}
        stage3_domains: list[str] = []
        dns_results:   dict[str, DNSResult] = {}
        whois_results: dict[str, dict]      = {}

        # ── Stage 1: DNS (all in parallel) ────────────────────────────────
        dns_coros = {d: check_ns_async(d) for d in domains}
        dns_gathered = await asyncio.gather(*dns_coros.values(), return_exceptions=True)
        for domain, dns_r in zip(dns_coros.keys(), dns_gathered):
            if isinstance(dns_r, BaseException):
                dns_r = type("_E", (), {
                    "has_ns": False, "ns_records": [], "server_used": None,
                    "nxdomain": False, "error": str(dns_r),
                    "to_dict": lambda self: {
                        "has_ns": False, "ns_records": [], "server_used": None,
                        "nxdomain": False, "error": self.error,
                    },
                })()
            dns_results[domain] = dns_r
            if dns_r.has_ns:
                resolved[domain] = _build_result(
                    domain, STATUS_UNAVAILABLE, "has_ns",
                    dns_r, None, None, self.include_details,
                )
            else:
                stage3_domains.append(domain)

        if not stage3_domains:
            return resolved

        # ── Stage 2: WHOIS (remaining, all in parallel) ───────────────────
        whois_coros = {d: self._whois_check(d) for d in stage3_domains}
        whois_gathered = await asyncio.gather(*whois_coros.values(), return_exceptions=True)
        remaining_for_svc: list[str] = []
        for domain, whois_r in zip(whois_coros.keys(), whois_gathered):
            if isinstance(whois_r, BaseException):
                whois_r = {"available": None, "domain_status": [],
                           "_error": str(whois_r)}
            whois_results[domain] = whois_r
            if _whois_says_unavailable(whois_r):
                resolved[domain] = _build_result(
                    domain, STATUS_UNAVAILABLE, "whois_unavailable",
                    dns_results[domain], whois_r, None, self.include_details,
                )
            elif _whois_says_available(whois_r):
                resolved[domain] = _build_result(
                    domain, STATUS_AVAILABLE, "whois_available",
                    dns_results[domain], whois_r, None, self.include_details,
                )
            else:
                remaining_for_svc.append(domain)

        if not remaining_for_svc:
            return resolved

        # ── Stage 3: Service checker (single batch call) ──────────────────
        svc_batch = await self._service_check_batch_async(remaining_for_svc)
        for domain in remaining_for_svc:
            svc_data = svc_batch.get(domain, {"available": None})
            resolved[domain] = self._stage3_to_result(
                domain, svc_data,
                dns_results[domain], whois_results.get(domain),
            )

        return resolved
