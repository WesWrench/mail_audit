"""
DNS NS-record lookup for domain availability pre-check.

Tries three DNS resolvers in order:
  1. System default nameserver
  2. 1.1.1.1  (Cloudflare)
  3. 8.8.8.8  (Google)

Each resolver is tried up to MAX_ATTEMPTS times before moving to the next.
A confirmed NS record means the domain is in use (unavailable).
NXDOMAIN means the domain doesn't exist in DNS (proceed to WHOIS/service check).
Timeouts / errors on all resolvers are treated as inconclusive.
"""

from __future__ import annotations

import asyncio
import dns.asyncresolver
import dns.resolver
import dns.exception

MAX_ATTEMPTS = 3
DNS_TIMEOUT  = 3.0          # seconds per attempt
FALLBACK_SERVERS = ["1.1.1.1", "8.8.8.8"]


class DNSResult:
    __slots__ = ("has_ns", "ns_records", "server_used", "nxdomain", "error")

    def __init__(
        self,
        has_ns:     bool,
        ns_records: list[str],
        server_used: str | None,
        nxdomain:   bool,
        error:      str | None,
    ) -> None:
        self.has_ns      = has_ns
        self.ns_records  = ns_records
        self.server_used = server_used
        self.nxdomain    = nxdomain
        self.error       = error

    def to_dict(self) -> dict:
        return {
            "has_ns":      self.has_ns,
            "ns_records":  self.ns_records,
            "server_used": self.server_used,
            "nxdomain":    self.nxdomain,
            "error":       self.error,
        }


async def _query_ns_async(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
) -> tuple[bool, list[str], bool]:
    """
    Attempt up to MAX_ATTEMPTS NS queries on *resolver*.

    Returns ``(has_ns, ns_records, nxdomain)``.
    Raises the last exception if all attempts fail.
    """
    last_exc: Exception | None = None
    for _ in range(MAX_ATTEMPTS):
        try:
            answer = await resolver.resolve(domain, "NS", lifetime=DNS_TIMEOUT)
            return True, sorted(str(r) for r in answer), False
        except dns.resolver.NXDOMAIN:
            return False, [], True          # definitive — domain doesn't exist
        except dns.resolver.NoAnswer:
            return False, [], False         # domain exists but no NS record
        except (dns.resolver.Timeout, dns.exception.DNSException) as exc:
            last_exc = exc
            await asyncio.sleep(0)          # yield to event loop between retries
    raise last_exc or RuntimeError("DNS query failed")


async def check_ns_async(domain: str) -> DNSResult:
    """
    Perform an NS lookup for *domain* against system DNS → 1.1.1.1 → 8.8.8.8.

    Returns a :class:`DNSResult` with the outcome.
    """
    servers: list[tuple[str | None, dns.asyncresolver.Resolver]] = []

    # System resolver
    sys_resolver = dns.asyncresolver.Resolver()
    sys_resolver.timeout  = DNS_TIMEOUT
    sys_resolver.lifetime = DNS_TIMEOUT
    servers.append(("system", sys_resolver))

    # Fallback resolvers
    for srv_ip in FALLBACK_SERVERS:
        r = dns.asyncresolver.Resolver()
        r.nameservers = [srv_ip]
        r.timeout     = DNS_TIMEOUT
        r.lifetime    = DNS_TIMEOUT
        servers.append((srv_ip, r))

    last_error: str | None = None

    for server_label, resolver in servers:
        try:
            has_ns, ns_records, nxdomain = await _query_ns_async(resolver, domain)
            return DNSResult(
                has_ns=has_ns,
                ns_records=ns_records,
                server_used=server_label,
                nxdomain=nxdomain,
                error=None,
            )
        except Exception as exc:
            last_error = str(exc)
            continue

    # All resolvers failed — inconclusive
    return DNSResult(
        has_ns=False,
        ns_records=[],
        server_used=None,
        nxdomain=False,
        error=last_error or "All DNS resolvers failed",
    )


def check_ns_sync(domain: str) -> DNSResult:
    """Synchronous wrapper around :func:`check_ns_async`."""
    return asyncio.run(check_ns_async(domain))
