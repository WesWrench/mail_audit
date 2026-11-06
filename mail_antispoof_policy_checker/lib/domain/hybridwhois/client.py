"""
HybridWhoisClient — combines whoisitlegacy (WHOIS/TCP-43) and whoisit (RDAP/HTTPS)
to maximise the amount of information retrieved for any asset.

Flow for domain queries
-----------------------

1. Try ``first_method`` (default: ``"whois"``).
2. If the result is incomplete *and* ``fallback=True``, try the other method.
3. If ``both=True``, run both methods in parallel (async) or sequentially (sync)
   regardless of completeness, then merge.
4. Build the final result:

   {
       # Normalised fields (whoisitlegacy format)
       "name_servers":           [...],
       "create_date":            "YYYY-MM-DD" | None,
       "expiry_date":            "YYYY-MM-DD" | None,
       "update_date":            "YYYY-MM-DD" | None,
       "domain_status":          [...],
       "registrar":              {...},
       "registrant":             {...},
       "administrative_contact": {...},
       "technical_contact":      {...},
       "billing_contact":        {...},
       "available":              True | False | None,
       "availability_reason":    "...",
       "is_rate_limited":        bool,
       "is_service_error":       bool,
       "dnssec":                 bool | None,
       "sources_used":           ["whois"|"rdap", ...],
       # Raw source data (kept for inspection / downstream use)
       "whois": {
           "registry":  {...} | None,   # raw whoisitlegacy whois_registry entry
           "registrar": {...} | None,   # raw whoisitlegacy whois_registrar entry
           "error":     str  | None,
       },
       "rdap": {
           "registry":  {...} | None,   # raw whoisit parsed domain (registry)
           "registrar": {...} | None,   # raw whoisit parsed domain (registrar)
           "error":     str  | None,
       },
   }

For IP / ASN / entity queries only RDAP (whoisit) is used; the result is
returned as-is with a ``sources_used: ["rdap"]`` envelope added.
"""

from __future__ import annotations

import asyncio
import sys
import os

# Allow importing sibling packages via relative path (../whoisit, ../whoisitlegacy)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import whoisit
import whoisitlegacy

from .normalizer import (
    rdap_domain_to_normalized,
    whois_domain_to_normalized,
    merge_normalized,
    needs_fallback,
)


# ---------------------------------------------------------------------------
# Result builder helpers
# ---------------------------------------------------------------------------

def _whois_raw_sections(whois_result: dict | None, error: str | None = None) -> dict:
    if whois_result is None:
        return {"registry": None, "registrar": None, "error": error}
    return {
        "registry":  whois_result.get("whois_registry"),
        "registrar": whois_result.get("whois_registrar"),
        "error":     error,
    }


def _rdap_raw_sections(rdap_result: dict | None, error: str | None = None) -> dict:
    if rdap_result is None:
        return {"registry": None, "registrar": None, "error": error}
    if "registry" in rdap_result:
        return {
            "registry":  rdap_result.get("registry"),
            "registrar": rdap_result.get("registrar"),
            "error":     error,
        }
    return {"registry": rdap_result, "registrar": None, "error": error}


def _build_result(
    normalized: dict,
    sources_used: list[str],
    whois_raw: dict,
    rdap_raw: dict,
) -> dict:
    result = dict(normalized)
    result["sources_used"] = sources_used
    result["whois"] = whois_raw
    result["rdap"]  = rdap_raw
    return result


# ---------------------------------------------------------------------------
# HybridWhoisClient
# ---------------------------------------------------------------------------

class HybridWhoisClient:
    """
    Hybrid WHOIS + RDAP client.

    Parameters
    ----------
    rdap_options:
        Keyword arguments forwarded to ``whoisit.domain_async()`` /
        ``whoisit.domain()``.  Common options:
        ``follow_rdap_registrar`` (default True), ``follow_related`` (default True),
        ``return_on_error`` (default True).
    whois_options:
        Keyword arguments forwarded to ``whoisitlegacy.domain_async()`` /
        ``whoisitlegacy.domain()``.  Common options:
        ``follow_whois_registrar`` (default True),
        ``include_whois_registry`` (default True).
    first_method:
        Which source to try first: ``"whois"`` (default) or ``"rdap"``.
        WHOIS is preferred by default because its rate limits are generally
        more lenient than most RDAP endpoints.
    both:
        If ``True``, always query both sources (in parallel for async calls)
        regardless of completeness, then merge results.
    fallback:
        If ``True`` (default) and the primary result is incomplete, automatically
        try the secondary source and merge.
    rdap_pool:
        Optional pre-created :class:`whoisit.RDAPPool` instance. A default pool
        is created automatically if not provided.
    required_fields:
        Optional list of field names that must be non-empty for the result to be
        considered complete.  If any listed field is absent or empty after the
        primary query, the secondary source is tried (in addition to the standard
        completeness check).  Supports dotted paths for nested fields, e.g.
        ``["registrar.registrar_name", "expiry_date"]``.
    """

    def __init__(
        self,
        rdap_options:    dict | None = None,
        whois_options:   dict | None = None,
        first_method:    str  = "whois",
        both:            bool = False,
        fallback:        bool = True,
        rdap_pool=None,
        whois_pool=None,
        required_fields: list | None = None,
    ) -> None:
        self.rdap_options    = rdap_options  or {}
        self.whois_options   = whois_options or {}
        self.first_method    = first_method.lower()
        self.both            = both
        self.fallback        = fallback
        self._rdap_pool      = rdap_pool
        self._whois_pool     = whois_pool
        self.required_fields = required_fields or []

    # ── lazy pool ────────────────────────────────────────────────────────────

    def _get_rdap_pool(self):
        if self._rdap_pool is None:
            self._rdap_pool = whoisit.create_rdap_pool()
        return self._rdap_pool

    # ── WHOIS helpers ─────────────────────────────────────────────────────────

    def _whois_domain_sync(self, domain_name: str) -> tuple[dict | None, str | None]:
        """Returns (raw_result, error_str)."""
        opts = {
            "follow_whois_registrar": True,
            "include_whois_registry": True,
            **self.whois_options,
        }
        try:
            return whoisitlegacy.domain(domain_name, **opts), None
        except Exception as exc:
            return None, str(exc)

    async def _whois_domain_async(self, domain_name: str) -> tuple[dict | None, str | None]:
        opts = {
            "follow_whois_registrar": True,
            "include_whois_registry": True,
            **self.whois_options,
        }
        try:
            return await whoisitlegacy.domain_async(
                domain_name, whois_pool=self._whois_pool, **opts
            ), None
        except Exception as exc:
            return None, str(exc)

    # ── RDAP helpers ──────────────────────────────────────────────────────────

    def _rdap_domain_sync(self, domain_name: str) -> tuple[dict | None, str | None]:
        opts = {
            "follow_rdap_registrar": True,
            "follow_related":        True,
            "return_on_error":       True,
            **self.rdap_options,
        }
        try:
            return whoisit.domain(domain_name, **opts), None
        except Exception as exc:
            return None, str(exc)

    async def _rdap_domain_async(self, domain_name: str) -> tuple[dict | None, str | None]:
        opts = {
            "follow_rdap_registrar": True,
            "follow_related":        True,
            "return_on_error":       True,
            **self.rdap_options,
        }
        try:
            result = await whoisit.domain_async(
                domain_name,
                rdap_pool=self._get_rdap_pool(),
                **opts,
            )
            return result, None
        except Exception as exc:
            return None, str(exc)

    # ── domain (sync) ─────────────────────────────────────────────────────────

    def domain(self, domain_name: str) -> dict:
        """
        Query a domain using WHOIS and/or RDAP.

        Returns the normalised hybrid result dict.
        """
        whois_raw  = _whois_raw_sections(None)
        rdap_raw   = _rdap_raw_sections(None)
        normalized = {}
        sources_used: list[str] = []

        if self.both:
            # Run both sequentially (sync); merge results
            w_res, w_err = self._whois_domain_sync(domain_name)
            r_res, r_err = self._rdap_domain_sync(domain_name)
            whois_raw   = _whois_raw_sections(w_res, w_err)
            rdap_raw    = _rdap_raw_sections(r_res, r_err)
            w_norm = whois_domain_to_normalized(w_res)
            r_norm = rdap_domain_to_normalized(r_res)
            normalized = merge_normalized(w_norm, r_norm)
            sources_used = ["whois", "rdap"]
        else:
            first, second = (
                ("whois", "rdap") if self.first_method == "whois" else ("rdap", "whois")
            )
            # First attempt
            if first == "whois":
                w_res, w_err = self._whois_domain_sync(domain_name)
                whois_raw = _whois_raw_sections(w_res, w_err)
                normalized = whois_domain_to_normalized(w_res)
            else:
                r_res, r_err = self._rdap_domain_sync(domain_name)
                rdap_raw  = _rdap_raw_sections(r_res, r_err)
                normalized = rdap_domain_to_normalized(r_res)
            sources_used = [first]

            # Fallback
            if self.fallback and needs_fallback(normalized, self.required_fields):
                if second == "whois":
                    w_res, w_err = self._whois_domain_sync(domain_name)
                    whois_raw = _whois_raw_sections(w_res, w_err)
                    sec_norm  = whois_domain_to_normalized(w_res)
                else:
                    r_res, r_err = self._rdap_domain_sync(domain_name)
                    rdap_raw  = _rdap_raw_sections(r_res, r_err)
                    sec_norm  = rdap_domain_to_normalized(r_res)
                normalized = merge_normalized(normalized, sec_norm)
                sources_used.append(second)

        return _build_result(normalized, sources_used, whois_raw, rdap_raw)

    # ── domain_async ──────────────────────────────────────────────────────────

    async def domain_async(self, domain_name: str) -> dict:
        """
        Async version of :meth:`domain`.

        When ``both=True`` both sources are queried in parallel via
        ``asyncio.gather``.
        """
        whois_raw  = _whois_raw_sections(None)
        rdap_raw   = _rdap_raw_sections(None)
        sources_used: list[str] = []

        if self.both:
            (w_res, w_err), (r_res, r_err) = await asyncio.gather(
                self._whois_domain_async(domain_name),
                self._rdap_domain_async(domain_name),
            )
            whois_raw   = _whois_raw_sections(w_res, w_err)
            rdap_raw    = _rdap_raw_sections(r_res, r_err)
            w_norm = whois_domain_to_normalized(w_res)
            r_norm = rdap_domain_to_normalized(r_res)
            normalized = merge_normalized(w_norm, r_norm)
            sources_used = ["whois", "rdap"]
        else:
            first, second = (
                ("whois", "rdap") if self.first_method == "whois" else ("rdap", "whois")
            )
            if first == "whois":
                w_res, w_err = await self._whois_domain_async(domain_name)
                whois_raw  = _whois_raw_sections(w_res, w_err)
                normalized = whois_domain_to_normalized(w_res)
            else:
                r_res, r_err = await self._rdap_domain_async(domain_name)
                rdap_raw   = _rdap_raw_sections(r_res, r_err)
                normalized = rdap_domain_to_normalized(r_res)
            sources_used = [first]

            if self.fallback and needs_fallback(normalized, self.required_fields):
                if second == "whois":
                    w_res, w_err = await self._whois_domain_async(domain_name)
                    whois_raw  = _whois_raw_sections(w_res, w_err)
                    sec_norm   = whois_domain_to_normalized(w_res)
                else:
                    r_res, r_err = await self._rdap_domain_async(domain_name)
                    rdap_raw   = _rdap_raw_sections(r_res, r_err)
                    sec_norm   = rdap_domain_to_normalized(r_res)
                normalized = merge_normalized(normalized, sec_norm)
                sources_used.append(second)

        return _build_result(normalized, sources_used, whois_raw, rdap_raw)

    # ── IP — RDAP only ────────────────────────────────────────────────────────

    def ip(self, ip_address: str, rir: str | None = None) -> dict:
        """Query an IP address via RDAP (whoisit only)."""
        try:
            result = whoisit.ip(ip_address, rir=rir, **{
                k: v for k, v in self.rdap_options.items()
                if k in ("raw", "include_raw", "allow_insecure_ssl")
            })
            result["sources_used"] = ["rdap"]
            return result
        except Exception as exc:
            return {"_error": str(exc), "sources_used": ["rdap"]}

    async def ip_async(self, ip_address: str, rir: str | None = None) -> dict:
        """Async version of :meth:`ip`."""
        try:
            result = await whoisit.ip_async(ip_address, rir=rir, **{
                k: v for k, v in self.rdap_options.items()
                if k in ("raw", "include_raw", "allow_insecure_ssl")
            })
            result["sources_used"] = ["rdap"]
            return result
        except Exception as exc:
            return {"_error": str(exc), "sources_used": ["rdap"]}

    # ── ASN — RDAP only ───────────────────────────────────────────────────────

    def asn(self, as_number: int, rir: str | None = None) -> dict:
        """Query an AS number via RDAP (whoisit only)."""
        try:
            result = whoisit.asn(as_number, rir=rir, **{
                k: v for k, v in self.rdap_options.items()
                if k in ("raw", "include_raw", "allow_insecure_ssl")
            })
            result["sources_used"] = ["rdap"]
            return result
        except Exception as exc:
            return {"_error": str(exc), "sources_used": ["rdap"]}

    async def asn_async(self, as_number: int, rir: str | None = None) -> dict:
        """Async version of :meth:`asn`."""
        try:
            result = await whoisit.asn_async(as_number, rir=rir, **{
                k: v for k, v in self.rdap_options.items()
                if k in ("raw", "include_raw", "allow_insecure_ssl")
            })
            result["sources_used"] = ["rdap"]
            return result
        except Exception as exc:
            return {"_error": str(exc), "sources_used": ["rdap"]}

    # ── Entity — RDAP only ────────────────────────────────────────────────────

    def entity(self, entity_handle: str, rir: str | None = None) -> dict:
        """Query an entity via RDAP (whoisit only)."""
        try:
            result = whoisit.entity(entity_handle, rir=rir, **{
                k: v for k, v in self.rdap_options.items()
                if k in ("raw", "include_raw", "allow_insecure_ssl")
            })
            result["sources_used"] = ["rdap"]
            return result
        except Exception as exc:
            return {"_error": str(exc), "sources_used": ["rdap"]}

    async def entity_async(self, entity_handle: str, rir: str | None = None) -> dict:
        """Async version of :meth:`entity`."""
        try:
            result = await whoisit.entity_async(entity_handle, rir=rir, **{
                k: v for k, v in self.rdap_options.items()
                if k in ("raw", "include_raw", "allow_insecure_ssl")
            })
            result["sources_used"] = ["rdap"]
            return result
        except Exception as exc:
            return {"_error": str(exc), "sources_used": ["rdap"]}

    # ── Pool management ───────────────────────────────────────────────────────

    def flush_rdap_status(self) -> None:
        """Flush the RDAP pool's status.json immediately."""
        if self._rdap_pool is not None:
            self._rdap_pool.flush_status()
