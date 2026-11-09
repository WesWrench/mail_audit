"""Unregistered domain checker for SPF includes and CNAME targets.

Uses DomainAvailabilityChecker (bulk) to detect unregistered or potentially
unregistered domains referenced in SPF include chains, and — through the very
same pipeline — the registrable domains of broken CNAME targets found at
DKIM / DMARC / SPF lookup names.
"""
from __future__ import annotations

from typing import Any, Iterable

# ── tldextract (public PyPI package) ─────────────────────────────────────────

try:
    import tldextract as _tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

# ── DomainAvailabilityChecker (lib/domain/ private package) ──────────────────
# Import order matters:
#   1. Importing from ..domain.domain_availability_checker executes checker.py
#      at module level, which does sys.path.insert(0, lib/domain/).
#   2. After that, hybridwhois is findable and already in sys.modules.

_CHECKER_AVAILABLE = False
_CHECKER_IMPORT_ERROR: str = ""
STATUS_AVAILABLE = "available"
STATUS_UNKNOWN = "unknown"
STATUS_UNAVAILABLE = "unavailable"

try:
    from ..domain.domain_availability_checker import (  # type: ignore
        DomainAvailabilityChecker as _DomainAvailabilityChecker,
        STATUS_AVAILABLE,
        STATUS_UNKNOWN,
        STATUS_UNAVAILABLE,
    )
    import hybridwhois as _hybridwhois  # findable after checker.py set sys.path
    _CHECKER_AVAILABLE = True
except Exception as _e:
    _CHECKER_IMPORT_ERROR = f"{type(_e).__name__}: {_e}"


# ── Public helpers ────────────────────────────────────────────────────────────

def extract_registered_domain(include: str) -> str | None:
    """Return the registered (apex) domain for *include*.

    Handles all SPF mechanism types that reference a DNS name:
    - plain domain (from ``include:<domain>``)
    - ``redirect=<domain>``
    - ``a:<domain>``, ``mx:<domain>``, ``ptr:<domain>``, ``exists:<domain>``

    Examples
    --------
    >>> extract_registered_domain('spf.protection.outlook.com')
    'outlook.com'
    >>> extract_registered_domain('a:mail.example.com')
    'example.com'
    >>> extract_registered_domain('redirect=spf.example.net')
    'example.net'

    Returns ``None`` if tldextract is unavailable or cannot determine the domain.
    """
    if not _TLDEXTRACT_AVAILABLE:
        return None
    # Strip SPF mechanism prefix so tldextract receives a plain domain/hostname
    for prefix in ('redirect=', 'a:', 'mx:', 'ptr:', 'exists:'):
        if include.lower().startswith(prefix):
            include = include[len(prefix):]
            break
    ext = _tldextract.extract(include)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def check_domains_availability(registered_domains: list[str]) -> dict[str, dict]:
    """Run a bulk domain availability check on *registered_domains*.

    Sends all domains in a single batch to
    :class:`~lib.domain.domain_availability_checker.DomainAvailabilityChecker`
    to leverage its internal bulk pipeline (DNS → WHOIS → service checker).

    Parameters
    ----------
    registered_domains:
        List of apex domains (deduplicated) — SPF include domains and/or
        registrable domains of CNAME targets.

    Returns
    -------
    dict[str, dict]
        Maps each domain to ``{"status": ..., "reason": ...}`` where status is
        ``'available'`` (unregistered), ``'unavailable'`` (registered), or
        ``'unknown'`` (cannot determine) and reason is the pipeline stage that
        decided (``has_ns``, ``whois_available``, ``service_unknown``...).

        Returns an empty dict if the checker libraries are not installed or
        the input list is empty.
    """
    if not _CHECKER_AVAILABLE or not registered_domains:
        return {}

    _hybridwhois.bootstrap()
    checker = _DomainAvailabilityChecker()
    results = checker.check_domains(registered_domains)
    return {
        domain: {"status": result["status"], "reason": result.get("reason")}
        for domain, result in results.items()
    }


def check_spf_includes_availability(registered_domains: list[str]) -> dict[str, str]:
    """Run a bulk domain availability check on SPF include domains.

    Thin wrapper over :func:`check_domains_availability` kept for backward
    compatibility: maps each domain to its status string only
    (``'available'``, ``'unavailable'`` or ``'unknown'``).
    """
    return {
        domain: result["status"]
        for domain, result in check_domains_availability(registered_domains).items()
    }


# ── SPF includes (end-of-run bulk check, shared by the CLI and mail_audit) ───
# Run once after ALL domains are analysed: registered domains are deduplicated
# across the whole batch so each one is checked a single time (WHOIS / RDAP /
# registrar lookups are slow and rate-limited).

def collect_spf_include_sources(spf_results: Iterable[tuple[str, dict]]) -> dict[str, list]:
    """Map each registered domain referenced by SPF includes to its sources.

    Parameters
    ----------
    spf_results:
        ``(record_id, spf_result_dict)`` pairs (``to_dict()`` output).

    Returns
    -------
    dict[str, list]
        ``{registered_domain: [(record_id, include_str), ...]}``
    """
    domain_sources: dict[str, list] = {}
    for record_id, spf in spf_results:
        if not spf or "error" in spf:
            continue
        for inc_info in spf.get("all_includes", []):
            include = inc_info.get("include", "")
            if not include:
                continue
            reg_domain = extract_registered_domain(include)
            if reg_domain:
                domain_sources.setdefault(reg_domain, []).append((record_id, include))
    return domain_sources


def apply_spf_include_availability(
    spf_by_record: dict[str, dict],
    domain_sources: dict[str, list],
    availability: dict[str, dict],
) -> list[dict]:
    """Add ``spf_domain_unregistered`` / ``spf_domain_potentially_unregistered`` issues.

    Parameters
    ----------
    spf_by_record:
        ``{record_id: spf_result_dict}`` — the dicts are updated in place
        (issue appended, statistics counters incremented).
    domain_sources:
        Output of :func:`collect_spf_include_sources`.
    availability:
        Output of :func:`check_domains_availability`.

    Returns
    -------
    list[dict]
        ``{"record_id", "include", "registered_domain", "status", "severity"}``
        for every issue added (for console output).
    """
    from .issue_definitions import IssueDefinitions

    added: list[dict] = []
    for reg_domain, sources in domain_sources.items():
        status = (availability.get(reg_domain) or {}).get("status")
        if status not in (STATUS_AVAILABLE, STATUS_UNKNOWN):
            continue  # registered (or not checked) — no issue
        for record_id, include in sources:
            spf = spf_by_record.get(record_id)
            if not spf or "error" in spf:
                continue
            if status == STATUS_AVAILABLE:
                issue = IssueDefinitions.create_spf_unregistered_domain(include, reg_domain)
                sev_key = "critical_issues"
            else:
                issue = IssueDefinitions.create_spf_potentially_unregistered_domain(include, reg_domain)
                sev_key = "high_issues"
            # Keep the deciding pipeline stage as evidence (has_ns, whois_available, ...)
            issue.additional_data["registration_reason"] = (availability.get(reg_domain) or {}).get("reason")
            spf.setdefault("issues", []).append(issue.to_dict())
            stats = spf.setdefault("statistics", {})
            stats["total_issues"] = stats.get("total_issues", 0) + 1
            stats[sev_key] = stats.get(sev_key, 0) + 1
            added.append({
                "record_id": record_id,
                "include": include,
                "registered_domain": reg_domain,
                "status": "unregistered" if status == STATUS_AVAILABLE else "potentially unregistered",
                "severity": issue.severity.value,
            })
    return added


# ── CNAME targets ─────────────────────────────────────────────────────────────

# Special-use / reserved names that can never be bought from a registrar
# (RFC 2606, RFC 6761, RFC 6762, RFC 7686, RFC 8375, RFC 9476).
RESERVED_TLDS = frozenset({
    "invalid", "test", "example", "localhost", "local", "onion", "alt", "internal",
})
RESERVED_DOMAINS = frozenset({
    "example.com", "example.net", "example.org", "home.arpa",
})

SUFFIX_ICANN    = "icann"      # registrable under an ICANN public suffix (buyable at a registrar)
SUFFIX_PRIVATE  = "private"    # under a PSL *private* suffix (hosted platform, e.g. github.io)
SUFFIX_RESERVED = "reserved"   # special-use / reserved name
SUFFIX_UNKNOWN  = "unknown"    # no public suffix match (or tldextract missing)


def classify_registrable_domain(name: str) -> dict[str, Any]:
    """Identify the registrable domain of *name* using the Public Suffix List.

    Never takes the last two labels naively: ``a.b.example.co.uk`` gives
    ``example.co.uk``.  Distinguishes ICANN suffixes (registrar-buyable) from
    PSL private suffixes (hosted platforms, where claimability depends on the
    provider) and from reserved / special-use names.

    Returns
    -------
    dict
        ``{"registrable_domain": str | None, "suffix_type": str,
        "private_suffix": str | None}``
    """
    name = name.rstrip(".").lower()
    labels = name.split(".")
    if labels[-1] in RESERVED_TLDS or any(
        name == d or name.endswith("." + d) for d in RESERVED_DOMAINS
    ):
        tld_or_domain = next(
            (d for d in RESERVED_DOMAINS if name == d or name.endswith("." + d)),
            labels[-1],
        )
        return {"registrable_domain": None, "suffix_type": SUFFIX_RESERVED,
                "private_suffix": None, "reserved": tld_or_domain}

    if not _TLDEXTRACT_AVAILABLE:
        return {"registrable_domain": None, "suffix_type": SUFFIX_UNKNOWN, "private_suffix": None}

    icann = extract_registered_domain(name)
    if not icann:
        return {"registrable_domain": None, "suffix_type": SUFFIX_UNKNOWN, "private_suffix": None}

    ext = _tldextract.extract(name, include_psl_private_domains=True)
    if getattr(ext, "is_private", False) and ext.suffix:
        return {"registrable_domain": icann, "suffix_type": SUFFIX_PRIVATE,
                "private_suffix": ext.suffix}
    return {"registrable_domain": icann, "suffix_type": SUFFIX_ICANN, "private_suffix": None}


def _iter_cname_checks(protocol_results: Iterable[dict]):
    for protocol_result in protocol_results:
        if not protocol_result or "error" in protocol_result:
            continue
        for check in protocol_result.get("cname_checks") or []:
            yield protocol_result, check


def collect_cname_registration_candidates(protocol_results: Iterable[dict]) -> set[str]:
    """Registrable domains of CNAME targets still awaiting a registration check.

    *protocol_results* are SPF / DMARC / DKIM result dicts (``to_dict()``
    output) carrying a ``cname_checks`` list.
    """
    return {
        check["registrable_domain"]
        for _, check in _iter_cname_checks(protocol_results)
        if check.get("registrable_domain")
        and (check.get("registration") or {}).get("state") == "not_verified"
    }


def apply_cname_registration_results(
    protocol_results: Iterable[dict],
    availability: dict[str, dict],
) -> list[dict]:
    """Record availability results on CNAME checks and add the matching issues.

    For every ``cname_checks`` entry whose registrable domain is in
    *availability*, sets ``registration`` to ``registered``,
    ``unregistered`` or ``potentially_unregistered`` (with the source stage
    as evidence).  One issue is added per (protocol result, registrable
    domain, state), grouping every alias that points into that domain
    (e.g. several DKIM selectors behind a wildcard).

    Returns a list of ``{"protocol", "names", "registrable_domain", "state",
    "severity"}`` dicts describing the issues added (for console output).
    """
    from .issue_definitions import IssueDefinitions

    state_by_status = {
        STATUS_AVAILABLE: "unregistered",
        STATUS_UNKNOWN: "potentially_unregistered",
        STATUS_UNAVAILABLE: "registered",
    }
    added: list[dict] = []

    grouped: dict[int, tuple[dict, dict[tuple[str, str], list[dict]]]] = {}
    for protocol_result, check in _iter_cname_checks(protocol_results):
        reg = check.get("registrable_domain")
        if (check.get("registration") or {}).get("state") != "not_verified" or reg not in availability:
            continue
        status = availability[reg].get("status")
        reason = availability[reg].get("reason")
        state = state_by_status.get(status)
        if state is None:
            continue
        check["registration"] = {
            "state": state,
            "source": "domain_availability_checker",
            "reason": reason,
        }
        check.setdefault("evidence", []).append(
            f"registration of '{reg}': {state} (domain_availability_checker: {reason})"
        )
        if state == "registered":
            continue
        _, groups = grouped.setdefault(id(protocol_result), (protocol_result, {}))
        groups.setdefault((state, reg), []).append(check)

    for protocol_result, groups in grouped.values():
        for (state, reg), checks in groups.items():
            first = checks[0]
            note = None
            if (first.get("wildcard") or {}).get("status") == "wildcard_probable":
                parent = first["wildcard"].get("parent", "")
                note = (
                    f"Wildcard probable: random names under '{parent}' resolve to the same CNAME "
                    f"chain, so these selector(s) most likely come from a single wildcard record "
                    f"'*.{parent}' — the risk is the same for every selector name."
                )
            issue = IssueDefinitions.create_cname_issue(
                first["protocol"],
                state,
                names=[c["queried_name"] for c in checks],
                chain=first.get("chain", []),
                failing_target=first.get("failing_target"),
                registrable_domain=reg,
                registration_reason=first["registration"].get("reason"),
                note=note,
                additional_data={
                    "selectors": [c["selector"] for c in checks if c.get("selector")],
                    "wildcard": first.get("wildcard", {}).get("status"),
                } if first["protocol"] == "DKIM" else None,
            )
            protocol_result.setdefault("issues", []).append(issue.to_dict())
            stats = protocol_result.setdefault("statistics", {})
            stats["total_issues"] = stats.get("total_issues", 0) + 1
            sev_key = f"{issue.severity.value}_issues"  # critical / high
            stats[sev_key] = stats.get(sev_key, 0) + 1
            added.append({
                "protocol": first["protocol"],
                "names": [c["queried_name"] for c in checks],
                "registrable_domain": reg,
                "state": state,
                "severity": issue.severity.value,
            })
    return added
