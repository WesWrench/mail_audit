"""AsyncPooledDNSResolver — dns.resolver.Resolver subclass with concurrency control.

Designed to be passed to checkdmarc functions via the ``resolver`` parameter,
enabling controlled concurrent DNS execution when called from asyncio.to_thread().

When checkdmarc receives a ``resolver`` object it skips its own resolver creation
and ignores the ``nameservers`` / ``timeout`` kwargs — so this resolver must be
fully pre-configured (nameservers, timeout, lifetime) before being passed in.

Two levels of rate limiting are applied on every :meth:`resolve` call:

* **Global limit**: cap on total concurrent DNS queries across all nameservers.
* **Per-nameserver limit**: cap per individual nameserver.  The least-loaded
  nameserver is preferred (non-blocking scan first, then blocking wait on the
  first one if all are at capacity).

Both limits use :class:`threading.Semaphore` which is safe for concurrent
access from multiple threads (e.g. via :func:`asyncio.to_thread`).
"""
from __future__ import annotations

import threading
from typing import Optional, Sequence

import dns.rdataclass
import dns.rdatatype
import dns.resolver


class AsyncPooledDNSResolver(dns.resolver.Resolver):
    """
    A :class:`dns.resolver.Resolver` subclass with built-in concurrency limiting.

    Parameters
    ----------
    nameservers:
        DNS server IPs/hostnames to use.  ``None`` or empty keeps the
        system-default resolvers (e.g. from ``/etc/resolv.conf`` or the OS).
    timeout:
        Per-query timeout **and** lifetime in seconds.  checkdmarc ignores its
        own ``timeout`` param when a resolver object is supplied, so the value
        must be configured here.  Default: ``5.0``.
    max_global_concurrent:
        Maximum total concurrent DNS queries across all nameservers.
        Default: ``50``.
    max_per_nameserver:
        Maximum concurrent queries per individual nameserver.
        Default: ``20``.

    Examples
    --------
    Create a resolver and pass it to checkdmarc::

        from lib.utils.async_dns_resolver import AsyncPooledDNSResolver
        from checkdmarc.spf import parse_spf_record

        resolver = AsyncPooledDNSResolver(
            nameservers=["8.8.8.8", "1.1.1.1"],
            timeout=5.0,
            max_global_concurrent=50,
            max_per_nameserver=20,
        )
        result = parse_spf_record(record, domain, resolver=resolver)
    """

    def __init__(
        self,
        nameservers: Optional[Sequence[str]] = None,
        timeout: float = 5.0,
        max_global_concurrent: int = 50,
        max_per_nameserver: int = 20,
    ) -> None:
        super().__init__()

        # Pre-configure nameservers and timeouts.
        # checkdmarc ignores its own nameservers/timeout args when a resolver
        # object is provided, so these MUST be set here.
        if nameservers:
            self.nameservers = list(nameservers)
        self.timeout = timeout
        self.lifetime = timeout

        self._max_global = max_global_concurrent
        self._max_per_ns = max_per_nameserver
        self._global_sem: threading.Semaphore = threading.Semaphore(max_global_concurrent)
        self._ns_sems: dict[str, threading.Semaphore] = {}
        self._ns_sems_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def max_global_concurrent(self) -> int:
        """Maximum total concurrent DNS queries (read-only)."""
        return self._max_global

    @property
    def max_per_nameserver(self) -> int:
        """Maximum concurrent queries per nameserver (read-only)."""
        return self._max_per_ns

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_ns_sem(self, ns: str) -> threading.Semaphore:
        """Return (creating if necessary) the per-nameserver semaphore."""
        with self._ns_sems_lock:
            if ns not in self._ns_sems:
                self._ns_sems[ns] = threading.Semaphore(self._max_per_ns)
            return self._ns_sems[ns]

    # ------------------------------------------------------------------
    # Overridden resolve()
    # ------------------------------------------------------------------

    def resolve(self, *args, **kwargs):  # type: ignore[override]
        """
        Resolve a DNS query with global + per-nameserver concurrency limiting.

        Acquires the global semaphore first, then the per-nameserver semaphore
        for the least-loaded configured nameserver (non-blocking scan first,
        then blocking wait on the first nameserver if all are at capacity).
        Both semaphores are released when the query completes or raises.

        All positional and keyword arguments are forwarded unchanged to
        :meth:`dns.resolver.Resolver.resolve` so the method remains fully
        compatible across dnspython 2.x versions.
        """
        # ── 1. Acquire global slot ────────────────────────────────────────
        self._global_sem.acquire()

        # ── 2. Acquire per-nameserver slot ───────────────────────────────
        ns_list = list(self.nameservers)
        acquired_ns_sem: Optional[threading.Semaphore] = None

        if ns_list:
            # Non-blocking scan: prefer a nameserver that is not saturated
            for ns in ns_list:
                sem = self._get_ns_sem(ns)
                if sem.acquire(blocking=False):
                    acquired_ns_sem = sem
                    break

            # All nameservers busy: block on the first configured one
            if acquired_ns_sem is None:
                acquired_ns_sem = self._get_ns_sem(ns_list[0])
                acquired_ns_sem.acquire(blocking=True)

        try:
            return super().resolve(*args, **kwargs)
        finally:
            if acquired_ns_sem is not None:
                acquired_ns_sem.release()
            self._global_sem.release()

    # ------------------------------------------------------------------
    # repr / str
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"AsyncPooledDNSResolver("
            f"nameservers={self.nameservers!r}, "
            f"timeout={self.timeout}, "
            f"max_global={self._max_global}, "
            f"max_per_ns={self._max_per_ns})"
        )
