"""Organizational-domain helpers (RFC 7489 §3.2 / Public Suffix List).

DMARC is evaluated against the **From header** domain. For a subdomain with no
own ``_dmarc`` record, the lookup jumps **directly to the organizational
(registrable) domain** — it does NOT walk the tree label by label
(RFC 7489 §6.6.3). So ``a.b.sub.example.co.uk`` falls back straight to
``example.co.uk``, never to ``b.sub.example.co.uk`` or ``sub.example.co.uk``.

Because DMARC alignment defaults to **relaxed** (``aspf``/``adkim`` absent = ``r``),
an SPF pass or a DKIM signature on *any* name sharing the organizational domain
satisfies DMARC for a ``From:`` on that organizational domain (and on any of its
siblings). A weak subdomain can therefore be leveraged to spoof the parent.

These helpers derive the organizational domain and, from a list of audit
targets, the set of organizational parents that are not already in the list —
so the caller can additionally fetch the parent's DMARC policy (the one that
actually governs a ``From:`` on the parent).
"""

from typing import Iterable, List


def organizational_domain(domain: str) -> str:
    """Organizational (registrable) domain of *domain* via the Public Suffix List.

    Falls back to the last two labels when ``tldextract`` is unavailable.
    """
    domain = (domain or "").strip().rstrip(".").lower()
    if not domain:
        return domain
    try:
        import tldextract
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except ImportError:
        pass
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def is_subdomain(domain: str) -> bool:
    """True when *domain* is a strict subdomain of its organizational domain."""
    domain = (domain or "").strip().rstrip(".").lower()
    org = organizational_domain(domain)
    return bool(org) and org != domain


def derive_org_parents(domains: Iterable[str]) -> List[str]:
    """Organizational parents of *domains* that are not already in *domains*.

    For every input that is a strict subdomain, its organizational domain is a
    parent whose DMARC policy governs a spoof of that parent. The result keeps
    the first-seen order and excludes any organizational domain already present
    in the input (so it is never audited twice).

    Example
    -------
    >>> derive_org_parents(["alwaysdata.spoofin.fr", "a.b.cef.fr", "spoofin.fr"])
    ['cef.fr']
    # spoofin.fr is already listed, so it is not returned; cef.fr is the only
    # missing organizational parent.
    """
    present = set()
    cleaned = []
    for d in domains:
        d = (d or "").strip().rstrip(".").lower()
        if d:
            cleaned.append(d)
            present.add(d)
    parents: List[str] = []
    seen = set()
    for d in cleaned:
        org = organizational_domain(d)
        if org and org != d and org not in present and org not in seen:
            parents.append(org)
            seen.add(org)
    return parents
