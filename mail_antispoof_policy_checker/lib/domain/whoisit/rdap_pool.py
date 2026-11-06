"""
Per-hostname RDAP rate limiter.

Features:
  - Wildcard hostname matching (``*.rdap.tucows.com`` pools all subdomains together)
  - Endpoint blacklisting (never query blacklisted hosts)
  - Smart 429 handling:
      1. Retry immediately once (covers defective rate-limiters like synergywholesale)
      2. On second 429: sleep from response headers (retry-after / x-ratelimit-reset /
         ratelimit-policy), or fall back to the configured file delay
      3. On third 429: disable the endpoint for the rest of the session
  - ``max_sleep_by_endpoint``: skip endpoints whose computed delay exceeds this
  - Status persistence: last-request wall-clock timestamps are stored in
    ``data/status.json`` via a dedicated background writer thread, so inter-request
    delays survive process restarts.

Usage::

    import whoisit
    pool = whoisit.create_rdap_pool(max_requests_per_hostname=1)

    result = await whoisit.domain_async("example.com", rdap_pool=pool)

    # Or process many domains, streaming results via callback:
    results = await whoisit.check_domains_async(
        ["example.com", "test.org"],
        callback=lambda domain, result: print(domain, result),
        rdap_pool=pool,
    )
"""

import asyncio
import json
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .logger import get_logger

log = get_logger("rdap_pool")

_DATA_DIR = Path(__file__).parent / "data"
_STATUS_FILE = _DATA_DIR / "status.json"


# ---------------------------------------------------------------------------
# 429 header parsing
# ---------------------------------------------------------------------------

def _parse_429_sleep(headers: dict) -> float | None:
    """
    Parse rate-limit response headers and return a suggested sleep time (seconds).

    Priority order:
      1. ``retry-after``         – plain seconds (or timestamp → modulo 3600)
      2. ``x-ratelimit-reset``   – seconds or timestamp (→ modulo 3600)
      3. ``ratelimit-policy``    – ``"limit;w=window"`` → window / limit

    Returns ``None`` if no useful header is present.
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}

    # 1. retry-after
    val = h.get("retry-after")
    if val:
        try:
            v = float(val)
            if v > 3600:
                v = v % 3600
            return max(v, 0.0)
        except (ValueError, TypeError):
            pass

    # 2. x-ratelimit-reset
    val = h.get("x-ratelimit-reset")
    if val:
        try:
            v = float(val)
            if v > 3600:
                v = v % 3600
            return max(v, 0.0)
        except (ValueError, TypeError):
            pass

    # 3. ratelimit-policy  e.g. "100;w=900"  or  "10; w=60"
    val = h.get("ratelimit-policy")
    if val:
        try:
            parts = val.split(";")
            limit = int(parts[0].strip())
            for p in parts[1:]:
                p = p.strip()
                if p.lower().startswith("w="):
                    window = int(p[2:].strip())
                    if limit > 0:
                        return float(window) / float(limit)
        except (ValueError, TypeError, IndexError):
            pass

    return None


# ---------------------------------------------------------------------------
# Wildcard hostname resolution
# ---------------------------------------------------------------------------

def _resolve_pool_key(hostname: str, delay_map: dict) -> str:
    """
    Return the canonical pool key for *hostname*.

    Checks wildcard patterns of the form ``*.parent.tld``.  For example,
    ``dreamhost.rdap.tucows.com`` resolves to ``*.rdap.tucows.com`` if that
    key exists in *delay_map*.  Falls back to the bare hostname.
    """
    if hostname in delay_map:
        return hostname
    # Try progressively shorter wildcard suffixes
    parts = hostname.split(".")
    for i in range(1, len(parts)):
        candidate = "*." + ".".join(parts[i:])
        if candidate in delay_map:
            return candidate
    return hostname


# ---------------------------------------------------------------------------
# Status persistence (background writer thread)
# ---------------------------------------------------------------------------

class _StatusWriter:
    """
    Background thread that serialises writes to ``status.json``.

    Stores ``{pool_key: last_request_wall_timestamp}`` so that inter-request
    delays survive process restarts.  All updates are funnelled through this
    single thread to avoid concurrent-write races.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data: dict[str, float] = {}
        self._dirty = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="rdap-status-writer"
        )
        # Load existing data
        try:
            if path.exists():
                with open(path, encoding="utf-8") as fh:
                    self._data = json.load(fh)
                log.debug(f"Loaded status.json ({len(self._data)} entries)")
        except Exception as exc:
            log.warning(f"Failed to load status.json: {exc}")
            self._data = {}

    def start(self) -> None:
        self._thread.start()

    def update(self, pool_key: str, wall_time: float) -> None:
        """Record a completed request for *pool_key* at *wall_time*."""
        with self._lock:
            self._data[pool_key] = wall_time
        self._dirty.set()

    def get(self, pool_key: str) -> float | None:
        """Return the stored last-request wall timestamp for *pool_key*, or None."""
        with self._lock:
            return self._data.get(pool_key)

    def flush(self) -> None:
        """Write current data to disk immediately (blocking)."""
        with self._lock:
            data = dict(self._data)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as exc:
            log.warning(f"Failed to write status.json: {exc}")

    def _run(self) -> None:
        while not self._stop.is_set():
            fired = self._dirty.wait(timeout=5.0)
            if fired:
                self._dirty.clear()
                self.flush()
        self.flush()  # final flush on stop

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
        self.flush()


# Module-level singleton – one writer shared across all pools in the process
_status_writer: _StatusWriter | None = None
_status_writer_lock = threading.Lock()


def _get_status_writer() -> _StatusWriter:
    global _status_writer
    with _status_writer_lock:
        if _status_writer is None:
            _status_writer = _StatusWriter(_STATUS_FILE)
            _status_writer.start()
    return _status_writer


def flush_status() -> None:
    """Flush ``status.json`` to disk immediately (call on Ctrl+C / shutdown)."""
    if _status_writer is not None:
        _status_writer.flush()


# ---------------------------------------------------------------------------
# Per-hostname queue
# ---------------------------------------------------------------------------

class RDAPHostQueue:
    """
    Async semaphore + inter-request delay for a single RDAP host (or wildcard pool).

    Handles 429 retries internally:
      1. Immediate retry (covers "dumb" rate limiters that always fire on first hit)
      2. Header-based sleep, then retry
      3. File-delay sleep, then retry
      4. Disable the endpoint permanently for this session
    """

    def __init__(
        self,
        pool_key: str,
        delay: float = 0.0,
        max_concurrent: int = 1,
        status_writer: _StatusWriter | None = None,
        max_sleep: float | None = 90.0,
    ) -> None:
        self.pool_key = pool_key
        self.delay = delay
        self.max_sleep = max_sleep
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._disabled = False
        self._status_writer = status_writer

        # Initialise last_request_time from persisted status so we respect
        # delays across process restarts.
        self._last_request_time: float = 0.0
        if status_writer:
            saved = status_writer.get(pool_key)
            if saved is not None:
                elapsed = time.time() - saved
                self._last_request_time = time.monotonic() - elapsed
                log.debug(
                    f"[{pool_key}] restored last-request time "
                    f"({elapsed:.1f}s ago)"
                )

    @property
    def is_disabled(self) -> bool:
        return self._disabled

    async def execute(self, request_fn):
        """
        Execute *request_fn()* under the per-host semaphore.

        *request_fn* is a zero-argument **callable** (not a coroutine object)
        so it can be called multiple times for retries.
        """
        from .errors import RateLimitedError

        if self._disabled:
            raise RateLimitedError(
                f"RDAP endpoint {self.pool_key} is disabled for this session "
                f"(repeated 429)",
                status_code=429,
            )

        async with self._semaphore:
            # ── inter-request delay ────────────────────────────────────────
            elapsed = time.monotonic() - self._last_request_time
            if self.delay > 0 and elapsed < self.delay:
                wait = self.delay - elapsed
                log.debug(f"[{self.pool_key}] waiting {wait:.2f}s before request")
                await asyncio.sleep(wait)

            # ── attempt 1 ─────────────────────────────────────────────────
            result, is_429, sleep_hint = await self._attempt(request_fn)
            if not is_429:
                return result

            # ── attempt 2: immediate retry (handles dumb rate limiters) ───
            log.debug(f"[{self.pool_key}] 429 on attempt 1, retrying immediately")
            result, is_429, sleep_hint = await self._attempt(request_fn)
            if not is_429:
                return result

            # ── compute sleep from headers or file delay ───────────────────
            if sleep_hint is not None:
                sleep_time = sleep_hint
                log.debug(
                    f"[{self.pool_key}] 429 on attempt 2, "
                    f"sleeping {sleep_time:.1f}s (from headers)"
                )
            else:
                sleep_time = self.delay
                log.debug(
                    f"[{self.pool_key}] 429 on attempt 2, "
                    f"sleeping {sleep_time:.1f}s (from file delay)"
                )

            if sleep_time > 0:
                if self.max_sleep is not None and sleep_time > self.max_sleep:
                    log.warning(
                        f"[{self.pool_key}] required sleep {sleep_time:.1f}s exceeds "
                        f"max_sleep {self.max_sleep:.1f}s — disabling endpoint"
                    )
                    self._disabled = True
                    raise RateLimitedError(
                        f"RDAP endpoint {self.pool_key} disabled: sleep "
                        f"{sleep_time:.1f}s > max_sleep {self.max_sleep:.1f}s",
                        status_code=429,
                    )
                await asyncio.sleep(sleep_time)

            # ── attempt 3: after sleep ─────────────────────────────────────
            result, is_429, _ = await self._attempt(request_fn)
            if not is_429:
                return result

            # ── give up: disable endpoint ──────────────────────────────────
            log.warning(
                f"[{self.pool_key}] 429 persists after sleep — disabling endpoint"
            )
            self._disabled = True
            raise RateLimitedError(
                f"RDAP endpoint {self.pool_key} disabled after repeated 429",
                status_code=429,
            )

    async def _attempt(
        self, request_fn
    ) -> tuple[dict | None, bool, float | None]:
        """
        Make one HTTP attempt.

        Returns ``(result, is_429, sleep_hint)`` where *sleep_hint* is a
        suggested sleep duration parsed from response headers (may be None).
        """
        from .errors import RateLimitedError

        try:
            result = await request_fn()
            self._record_request()
            return result, False, None
        except RateLimitedError as exc:
            self._record_request()
            return None, True, _parse_429_sleep(exc.headers)

    def _record_request(self) -> None:
        """Update last-request time and persist to status.json."""
        now_mono = time.monotonic()
        now_wall = time.time()
        self._last_request_time = now_mono
        if self._status_writer:
            self._status_writer.update(self.pool_key, now_wall)


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------

class RDAPPool:
    """
    Registry of per-hostname ``RDAPHostQueue`` objects.

    Pass an instance to ``whoisit.domain_async()`` or ``whoisit.check_domains_async()``
    so that every HTTP request (primary registry + optional registrar follow-up)
    is routed through per-hostname queuing and rate-limit logic.

    Parameters
    ----------
    host_delays:
        ``{hostname_or_wildcard: delay_seconds}`` mapping loaded from
        ``rdap_host_delay.json`` and ``rdap_registrar_host_delay.json``.
    blacklist:
        Set of hostnames that must never be queried.
    max_requests_per_hostname:
        Maximum simultaneous requests to any single hostname.
    max_sleep_by_endpoint:
        If the computed sleep required for a 429 exceeds this value the
        endpoint is disabled rather than waited on.  ``None`` = no limit.
    use_status:
        Whether to load/save ``status.json`` for cross-restart delay awareness.
    """

    def __init__(
        self,
        host_delays: dict[str, float] | None = None,
        blacklist: set[str] | None = None,
        max_requests_per_hostname: int = 1,
        max_sleep_by_endpoint: float | None = 90.0,
        use_status: bool = True,
        max_total_concurrent: int | None = None,
    ) -> None:
        self._host_delays: dict[str, float] = dict(host_delays or {})
        self._blacklist: set[str] = set(blacklist or set())
        self._max_concurrent = max_requests_per_hostname
        self._max_sleep = max_sleep_by_endpoint
        self._queues: dict[str, RDAPHostQueue] = {}
        self._lock = asyncio.Lock()
        self._status_writer: _StatusWriter | None = (
            _get_status_writer() if use_status else None
        )
        self._global_semaphore: asyncio.Semaphore | None = (
            asyncio.Semaphore(max_total_concurrent) if max_total_concurrent else None
        )
        self._start_wall: float = time.time()

    # ── public helpers ──────────────────────────────────────────────────────

    def elapsed(self) -> float:
        """Seconds since this pool was created."""
        return time.time() - self._start_wall

    def is_blacklisted(self, hostname: str) -> bool:
        return hostname in self._blacklist

    def flush_status(self) -> None:
        """Flush status.json immediately (e.g. on shutdown / Ctrl+C)."""
        if self._status_writer:
            self._status_writer.flush()

    # ── core execute ────────────────────────────────────────────────────────

    async def execute(self, url: str, request_fn):
        """
        Execute *request_fn()* through the per-hostname queue for *url*.

        *request_fn* must be a **callable** (zero-argument) that returns a
        coroutine each time it is called (i.e. pass ``q.request``, not
        ``q.request()``).
        """
        from .errors import RateLimitedError

        hostname = urlsplit(url).hostname or "unknown"
        if self.is_blacklisted(hostname):
            raise RateLimitedError(
                f"RDAP endpoint {hostname} is blacklisted",
                status_code=429,
            )
        queue = await self._get_queue(hostname)
        if self._global_semaphore is not None:
            async with self._global_semaphore:
                return await queue.execute(request_fn)
        return await queue.execute(request_fn)

    async def _get_queue(self, hostname: str) -> RDAPHostQueue:
        pool_key = _resolve_pool_key(hostname, self._host_delays)
        async with self._lock:
            if pool_key not in self._queues:
                delay = self._host_delays.get(pool_key, 0.0)
                self._queues[pool_key] = RDAPHostQueue(
                    pool_key,
                    delay,
                    self._max_concurrent,
                    self._status_writer,
                    self._max_sleep,
                )
                if delay > 0:
                    log.debug(
                        f"Created RDAP queue for {pool_key} "
                        f"(delay={delay}s, max_concurrent={self._max_concurrent})"
                    )
            return self._queues[pool_key]
