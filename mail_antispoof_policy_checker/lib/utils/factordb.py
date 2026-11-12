"""factordb.com lookup of RSA moduli (known factorizations).

factordb (https://factordb.com) is a public database of factorizations. If a DKIM RSA
modulus ``n`` has a known factor there, the private key can be rebuilt by anyone
(``q = n / p``, ``d = e^-1 mod (p-1)(q-1)``) and DKIM signatures for the domain forged.

Why the HTML page and not the JSON API: the API is heavily throttled; the search page
(``/index.php?query=<n>``) answers the same question. Reading a number there never
stores it ("Reading never stores anything", factordb search page), so an audit does not
add the audited keys to the database.

The client follows the site's rules for automated requests
(https://factordb.com/limits.php): its own User-Agent, one request at a time with a
minimum interval, and it stops querying for the rest of the run after an HTTP 429.

Every factor reported by factordb is re-checked locally (``n % p == 0``) before being
returned: a parsing change on the site can only produce a miss, never a false finding.
"""
from __future__ import annotations

import html
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

import requests

FACTORDB_URL = "https://factordb.com"
DEFAULT_USER_AGENT = "mail-antispoof-policy-checker (DKIM RSA modulus check)"

# factordb status codes (badge class "b-<code>")
STATUS_FULLY_FACTORED = "FF"   # all prime factors known
STATUS_FACTOR_KNOWN = "CF"     # composite, at least one factor known
STATUS_COMPOSITE = "C"         # composite, no factor known
STATUS_PRIME = "P"             # proven prime
STATUS_PROBABLE_PRIME = "PRP"  # probable prime
STATUS_UNKNOWN = "U"           # status unknown

_BADGE_RE = re.compile(r'class="badge b-([A-Za-z]+)"')
# Factors link to their record: "/?id=<id>" (stored numbers) or "/?query=<n>" (small ones)
_FACTOR_RE = re.compile(r'<a class="factor" href="/\?(?:id|query)=(\d+)"[^>]*>(.*?)</a>', re.S)
_FBASE_RE = re.compile(r'<span class="fbase">(.*?)</span>', re.S)
_VALUE_RE = re.compile(r'<div class="value"[^>]*>(.*?)</div>', re.S)
_SUB_RE = re.compile(r"<sub\b.*?</sub>", re.S)
_TAG_RE = re.compile(r"<[^>]+>")
# Information box of the record, e.g. "<b>Interesting number.</b> 768-bit Oakley Group 1 ..."
_NOTICE_RE = re.compile(r'<div class="notice"[^>]*>.*?<div>(.*?)</div>', re.S)


class FactorDBRateLimited(Exception):
    """factordb answered HTTP 429: stop querying for this run."""


@dataclass
class FactorDBResult:
    """Outcome of a factordb lookup for one number."""

    status: str                      # factordb status code, or "error" / "skipped"
    url: str                         # page that was read
    factors: List[int] = field(default_factory=list)   # non-trivial factors, verified locally
    notes: List[str] = field(default_factory=list)     # factordb information box(es)
    error: Optional[str] = None

    @property
    def factor_known(self) -> bool:
        """True when at least one non-trivial factor of the number is known and verified."""
        return bool(self.factors)

    @property
    def is_prime(self) -> bool:
        return self.status in (STATUS_PRIME, STATUS_PROBABLE_PRIME)

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {"status": self.status, "url": self.url}
        if self.factors:
            data["factor_digits"] = [len(str(f)) for f in self.factors]
        if self.notes:
            data["notes"] = list(self.notes)
        if self.error:
            data["error"] = self.error
        return data


def _text(fragment: str) -> str:
    """Visible digits of an HTML fragment: drops the ``<sub>`` digit-count suffix and tags."""
    return html.unescape(_TAG_RE.sub("", _SUB_RE.sub("", fragment))).strip()


def parse_status(page: str) -> Optional[str]:
    """factordb status code of the record shown on *page* (``FF``, ``CF``, ``C``...)."""
    match = _BADGE_RE.search(page)
    return match.group(1).upper() if match else None


def parse_notes(page: str) -> List[str]:
    """Text of the information boxes on *page*, e.g. ``"Interesting number. 768-bit Oakley
    Group 1 (RFC 2409, 1998): ..."`` (well-known published numbers: RSA challenges, DH
    primes, example keys...)."""
    notes = []
    for fragment in _NOTICE_RE.findall(page):
        text = re.sub(r"\s+", " ", html.unescape(_TAG_RE.sub("", fragment))).strip()
        if text:
            notes.append(text)
    return notes


def parse_factors(page: str) -> List[tuple]:
    """``[(factor_ref, digits_or_None), ...]`` listed on *page*.

    ``digits`` is None when factordb abbreviates a long factor (``1234…89``); the full
    value is then read from the factor's own page (:func:`parse_value`).
    """
    factors = []
    for factor_id, inner in _FACTOR_RE.findall(page):
        base = _FBASE_RE.search(inner)
        digits = _text(base.group(1) if base else inner)
        factors.append((factor_id, digits if digits.isdigit() else None))
    return factors


def parse_value(page: str) -> Optional[int]:
    """Full value of the record shown on *page* (requested with ``full=1``)."""
    match = _VALUE_RE.search(page)
    if not match:
        return None
    digits = re.sub(r"\s", "", _text(match.group(1)))
    return int(digits) if digits.isdigit() else None


class FactorDBClient:
    """Thread-safe, rate-limited factordb.com reader with an in-memory cache.

    Args:
        timeout: HTTP timeout per request, in seconds.
        min_interval: Minimum delay between two requests, in seconds (requests are
            serialised: never more than one in flight).
        user_agent: User-Agent header (factordb refuses browser look-alikes).
        base_url: factordb root URL.
        fetch: Optional ``fetch(url) -> (status_code, text)`` replacing HTTP (tests).
    """

    def __init__(
        self,
        timeout: float = 15.0,
        min_interval: float = 0.5,
        user_agent: str = DEFAULT_USER_AGENT,
        base_url: str = FACTORDB_URL,
        fetch: Optional[Callable[[str], tuple]] = None,
    ) -> None:
        self.timeout = timeout
        self.min_interval = min_interval
        self.user_agent = user_agent
        self.base_url = base_url.rstrip("/")
        self._fetch = fetch or self._http_get
        self._lock = threading.Lock()
        self._last_request = 0.0
        self._cache: Dict[int, FactorDBResult] = {}
        self._session: Optional[requests.Session] = None
        self.disabled_reason: Optional[str] = None   # set after HTTP 429

    # ------------------------------------------------------------------ HTTP

    def _http_get(self, url: str) -> tuple:
        if self._session is None:
            self._session = requests.Session()
            self._session.headers["User-Agent"] = self.user_agent
        response = self._session.get(url, timeout=self.timeout)
        return response.status_code, response.text

    def _get(self, url: str) -> str:
        """Rate-limited GET (caller holds ``self._lock``)."""
        wait = self._last_request + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            status, text = self._fetch(url)
        finally:
            self._last_request = time.monotonic()
        if status == 429:
            raise FactorDBRateLimited("HTTP 429 (factordb rate limit)")
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        return text

    def query_url(self, number: int) -> str:
        return f"{self.base_url}/index.php?query={number}"

    # ---------------------------------------------------------------- lookup

    def lookup(self, number: int) -> FactorDBResult:
        """Look *number* up and return its status and locally verified factors.

        Never raises: network errors give ``status="error"``; after an HTTP 429 every
        further lookup gives ``status="skipped"``.
        """
        url = self.query_url(number)
        with self._lock:
            if number in self._cache:
                return self._cache[number]
            if self.disabled_reason:
                return FactorDBResult(status="skipped", url=url, error=self.disabled_reason)
            try:
                result = self._lookup_locked(number, url)
            except FactorDBRateLimited as exc:
                self.disabled_reason = str(exc)
                return FactorDBResult(status="skipped", url=url, error=self.disabled_reason)
            except Exception as exc:   # network / HTTP error: not cached, no finding
                return FactorDBResult(status="error", url=url, error=f"{type(exc).__name__}: {exc}")
            self._cache[number] = result
            return result

    def _lookup_locked(self, number: int, url: str) -> FactorDBResult:
        page = self._get(url)
        status = parse_status(page) or STATUS_UNKNOWN
        factors: List[int] = []
        if status in (STATUS_FULLY_FACTORED, STATUS_FACTOR_KNOWN):
            for factor_id, digits in parse_factors(page):
                if digits is None:
                    value = parse_value(self._get(f"{self.base_url}/index.php?id={factor_id}&full=1"))
                else:
                    value = int(digits)
                if value and 1 < value < number and number % value == 0 and value not in factors:
                    factors.append(value)
        return FactorDBResult(status=status, url=url, factors=factors, notes=parse_notes(page))
