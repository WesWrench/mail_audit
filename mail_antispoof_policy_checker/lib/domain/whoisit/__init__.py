import asyncio
import time
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
import httpx
import requests
from .bootstrap import _BootstrapWrapper
from .errors import ArgumentError, ParseError, QueryError, RateLimitedError
from .parser import parse
from .query import Query, QueryAsync, QueryBuilder
from .rdap_pool import RDAPPool, flush_status
from .utils import (
    get_async_client,
    get_session,
    recursive_merge,
    clear_session as clear_session,
    set_proxy as set_proxy,
    get_proxy as get_proxy,
    clear_proxy as clear_proxy,
)
from .version import version as version


# Private methods

_bootstrap = _BootstrapWrapper()
_query_builder = QueryBuilder(_bootstrap)


# Expose class methods as the public API

bootstrap = _bootstrap.bootstrap
bootstrap_async = _bootstrap.bootstrap_async
is_bootstrapped = _bootstrap.is_bootstrapped
clear_bootstrapping = _bootstrap.clear_bootstrapping
save_bootstrap_data = _bootstrap.save_bootstrap_data
load_bootstrap_data = _bootstrap.load_bootstrap_data
bootstrap_is_older_than = _bootstrap.bootstrap_is_older_than
build_query = _query_builder.build


# RDAP pool factory

def create_rdap_pool(
    max_requests_per_hostname: int = 1,
    max_sleep_by_endpoint: float | None = 90.0,
    use_status: bool = True,
    max_total_concurrent: int | None = None,
) -> RDAPPool:
    """
    Create an :class:`RDAPPool` pre-loaded with per-hostname delays and the
    endpoint blacklist from bootstrap data.

    Parameters
    ----------
    max_requests_per_hostname:
        Maximum simultaneous RDAP requests to any single hostname.
    max_sleep_by_endpoint:
        Skip endpoints whose required 429-recovery sleep exceeds this value
        (seconds).  ``None`` disables the limit.
    use_status:
        Persist last-request timestamps in ``data/status.json`` so delays
        are respected across process restarts.
    max_total_concurrent:
        Global cap on the total number of in-flight RDAP requests across
        **all** endpoints combined.  ``None`` (default) means no global limit
        — each endpoint is only constrained by its own per-hostname semaphore.
        Useful when querying many distinct endpoints at once to avoid opening
        hundreds of simultaneous connections (e.g. ``max_total_concurrent=50``).
    """
    return RDAPPool(
        host_delays=_bootstrap.get_rdap_host_delays(),
        blacklist=_bootstrap.get_rdap_blacklist(),
        max_requests_per_hostname=max_requests_per_hostname,
        max_sleep_by_endpoint=max_sleep_by_endpoint,
        use_status=use_status,
        max_total_concurrent=max_total_concurrent,
    )


def get_rdap_host_delays() -> dict[str, float]:
    """Return the per-hostname RDAP delay map loaded at bootstrap time."""
    return _bootstrap.get_rdap_host_delays()


def get_registrar_info(iana_id: int | str) -> "dict | None":
    """
    Return a dict of RDAP registrar information for the given IANA registrar ID,
    or ``None`` if not found in the bootstrap data.

    The returned dict contains:
        ``iana_id`` (int), ``name`` (str), ``rdap_url`` (str | None).

    ``rdap_url`` is the base RDAP URL of the registrar's RDAP server, or ``None``
    if the registrar does not have a known RDAP endpoint.

    This is useful in hybrid clients that need to bridge from a WHOIS-derived
    IANA ID to the corresponding registrar RDAP endpoint.

    Example::

        import whoisit
        info = whoisit.get_registrar_info(146)
        print(info["rdap_url"])  # "https://rdap.godaddy.com/"
    """
    try:
        iana_id_int = int(iana_id)
    except (TypeError, ValueError):
        return None
    rdap_url = _bootstrap.get_registrar_rdap_url(str(iana_id_int))
    return {
        "iana_id":  iana_id_int,
        "rdap_url": rdap_url,
    }


def get_registrar_rdap_url(iana_id: str) -> str | None:
    """Return the RDAP base URL for a registrar given its IANA ID."""
    return _bootstrap.get_registrar_rdap_url(iana_id)


# Helpers

def _extract_registrar_iana_id(response: dict) -> str | None:
    """
    Extract the registrar IANA ID from an RDAP response.

    Searches entities for role "registrar", then looks for a ``publicIds``
    entry of type "IANA Registrar ID".  Falls back to the entity ``handle``
    if it looks numeric.
    """
    for entity in response.get("entities", []):
        roles = [r.lower() for r in entity.get("roles", [])]
        if "registrar" not in roles:
            continue
        # Try publicIds first
        for pid in entity.get("publicIds", []):
            if pid.get("type", "").lower() == "iana registrar id":
                identifier = str(pid.get("identifier", "")).strip()
                if identifier:
                    return identifier
        # Fallback: numeric handle
        handle = str(entity.get("handle", "")).strip()
        if handle.isdigit():
            return handle
    return None


# Query helpers


def _asn(
    as_number: int,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    session: requests.Session | None = None,
    async_client: httpx.AsyncClient | None = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    method, url, _ = build_query(query_type="asn", query_value=as_number, rir=rir)
    if isinstance(async_client, httpx.AsyncClient):
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield (
        response
        if raw
        else parse(_bootstrap, "autnum", as_number, response, include_raw)
    )


def asn(
    as_number: int,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    session: requests.Session | None = None,
) -> dict:
    session = get_session(session, allow_insecure_ssl)
    gen = _asn(as_number, rir, raw, include_raw, session=session)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def asn_async(
    as_number: int,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    async_client: httpx.AsyncClient | None = None,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _asn(as_number, rir, raw, include_raw, async_client=async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp


def _domain(
    domain_name: str,
    raw: bool = False,
    include_raw: bool = False,
    follow_related: bool = True,
    return_on_error: bool = False,
    follow_rdap_registrar: bool = True,
    session: requests.Session | None = None,
    async_client: httpx.AsyncClient | None = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    is_async = isinstance(async_client, httpx.AsyncClient)
    method, url, _ = build_query(query_type="domain", query_value=domain_name)
    if is_async:
        q = QueryAsync(async_client, method, url, return_on_error=return_on_error)
    else:
        q = Query(session, method, url, return_on_error=return_on_error)
    response = yield q
    # Inject source metadata into the primary response
    if isinstance(response, dict):
        response["_rdap_source"] = {
            "url": url,
            "domain": domain_name,
            "status_code": response.get("_rdap_error", {}).get("status_code", 200),
        }
    # Short-circuit: return raw response immediately only when no follow-ups needed
    if raw and not follow_related and not follow_rdap_registrar:
        yield response
        return
    if follow_related:
        # Attempt to follow the 'related' or 'registration' links if the TLD has
        # an upstream RDAP endpoint that may have more information
        relresponse = None
        for link in response.get("links", []):
            rel = link.get("rel", "")
            if rel in ("related", "registration"):
                relhref = link.get("href", "")
                reltype = link.get("type", "")
                # Exclude related links with type set to HTML content types to avoid parsing web pages as JSON
                if relhref and not reltype.startswith("text/html"):
                    if is_async:
                        relq = QueryAsync(async_client, method, relhref, return_on_error=return_on_error)
                    else:
                        relq = Query(session, method, relhref, return_on_error=return_on_error)
                    yield
                    relresponse = yield relq
                    break
        if relresponse and not relresponse.get("_rdap_error"):
            # Overlay the related response over the original response
            # (skip merge if the follow-up itself returned an error)
            recursive_merge(response, relresponse)
    if follow_rdap_registrar:
        # Build registry result first
        if raw:
            registry_result = response
        else:
            try:
                registry_result = parse(_bootstrap, "domain", domain_name, response, include_raw)
            except ParseError:
                # Error responses (e.g., 404 blocked/reserved domains) may lack
                # objectClassName so the parser cannot identify the type.
                # Fall back to the raw response so that notices and _rdap_error
                # are preserved for downstream availability detection.
                registry_result = response
        # Attempt the registrar RDAP query
        registrar_result = None
        iana_id = _extract_registrar_iana_id(response)
        if iana_id:
            registrar_base_url = _bootstrap.get_registrar_rdap_url(iana_id)
            if registrar_base_url:
                if not registrar_base_url.endswith("/"):
                    registrar_base_url += "/"
                registrar_url = registrar_base_url + "domain/" + domain_name
                if is_async:
                    regq = QueryAsync(async_client, method, registrar_url, return_on_error=True)
                else:
                    regq = Query(session, method, registrar_url, return_on_error=True)
                yield  # signal
                reg_response = yield regq
                if reg_response is not None:
                    # Inject source metadata into registrar response
                    if isinstance(reg_response, dict):
                        reg_response["_rdap_source"] = {
                            "url": registrar_url,
                            "domain": domain_name,
                            "status_code": reg_response.get("_rdap_error", {}).get("status_code", 200),
                        }
                    if raw:
                        registrar_result = reg_response
                    elif reg_response.get("_rdap_error"):
                        registrar_result = reg_response
                    else:
                        registrar_result = parse(
                            _bootstrap, "domain", domain_name, reg_response, include_raw
                        )
        yield {"registry": registry_result, "registrar": registrar_result}
        return
    # follow_rdap_registrar=False: original flat response
    if raw:
        yield response
    else:
        try:
            yield parse(_bootstrap, "domain", domain_name, response, include_raw)
        except ParseError:
            yield response


def domain(
    domain_name: str,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    allow_invalid_certificate: bool = False,
    session: requests.Session | None = None,
    follow_related: bool = True,
    return_on_error: bool = False,
    follow_rdap_registrar: bool = True,
) -> dict:
    session = get_session(session, allow_insecure_ssl, allow_invalid_certificate)
    gen = _domain(
        domain_name, raw, include_raw, follow_related,
        return_on_error, follow_rdap_registrar, session, None,
    )
    resp: dict | None = None
    q: Query
    for q in gen:
        req_resp: dict = q.request()
        resp = gen.send(req_resp)
        if resp is req_resp:
            gen.close()
            break
    return resp


async def domain_async(
    domain_name: str,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    allow_invalid_certificate: bool = False,
    async_client: httpx.AsyncClient | None = None,
    follow_related: bool = True,
    return_on_error: bool = False,
    follow_rdap_registrar: bool = True,
    rdap_pool: RDAPPool | None = None,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl, allow_invalid_certificate)
    gen = _domain(
        domain_name, raw, include_raw, follow_related,
        return_on_error, follow_rdap_registrar, None, async_client,
    )
    resp: dict | None = None
    q: QueryAsync
    for q in gen:
        if rdap_pool and hasattr(q, "url"):
            try:
                # Pass q.request (callable) so the pool can retry on 429
                req_resp: dict = await rdap_pool.execute(q.url, q.request)
            except (RateLimitedError, QueryError) as exc:
                if q.return_on_error:
                    req_resp = {
                        "_rdap_error": {
                            "status_code": getattr(exc, "status_code", 0),
                            "error_type": type(exc).__name__,
                            "message": str(exc),
                        }
                    }
                else:
                    raise
        else:
            req_resp: dict = await q.request()
        resp = gen.send(req_resp)
        # happens when raw=true
        if resp is req_resp:
            gen.close()
            break
    return resp


def _ip(
    ip_address_or_network: str | IPv4Address | IPv4Network | IPv6Address | IPv6Network,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    session: requests.Session | None = None,
    async_client: bool = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    method, url, _ = build_query(
        query_type="ip", query_value=ip_address_or_network, rir=rir
    )
    if isinstance(async_client, httpx.AsyncClient):
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield (
        response
        if raw
        else parse(_bootstrap, "ip", ip_address_or_network, response, include_raw)
    )


def ip(
    ip_address_or_network: str | IPv4Address | IPv4Network | IPv6Address | IPv6Network,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    session: requests.Session | None = None,
) -> dict:
    session = get_session(session, allow_insecure_ssl)
    gen = _ip(ip_address_or_network, rir, raw, include_raw, session, None)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def ip_async(
    ip_address_or_network: str | IPv4Address | IPv4Network | IPv6Address | IPv6Network,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    async_client: httpx.AsyncClient | None = None,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _ip(ip_address_or_network, rir, raw, include_raw, None, async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp


def _entity(
    entity_handle: str,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    session: requests.Session | None = None,
    async_client: httpx.AsyncClient | None = None,
) -> Iterator:
    if raw and include_raw:
        raise ArgumentError("You cannot set both raw=True and include_raw=True")
    method, url, _ = build_query(
        query_type="entity", query_value=entity_handle, rir=rir
    )
    if isinstance(async_client, httpx.AsyncClient):
        q = QueryAsync(async_client, method, url)
    else:
        q = Query(session, method, url)
    response = yield q
    yield (
        response
        if raw
        else parse(_bootstrap, "entity", entity_handle, response, include_raw)
    )


def entity(
    entity_handle: str,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    session: requests.Session | None = None,
) -> dict:
    session = get_session(session, allow_insecure_ssl)
    gen = _entity(entity_handle, rir, raw, include_raw, session, None)
    q: Query = next(gen)
    resp: dict = gen.send(q.request())
    gen.close()
    return resp


async def entity_async(
    entity_handle,
    rir: str | None = None,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    async_client: httpx.AsyncClient | None = None,
) -> dict:
    async_client = get_async_client(async_client, allow_insecure_ssl)
    gen = _entity(entity_handle, rir, raw, include_raw, None, async_client)
    q: QueryAsync = next(gen)
    resp: dict = gen.send(await q.request())
    gen.close()
    return resp


# ---------------------------------------------------------------------------
# check_domains / check_domains_async
# ---------------------------------------------------------------------------

async def check_domains_async(
    domains: list[str],
    callback=None,
    max_total_time: float | None = 86400.0,
    max_sleep_by_endpoint: float | None = 90.0,
    follow_rdap_registrar: bool = True,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    allow_invalid_certificate: bool = False,
    rdap_pool: RDAPPool | None = None,
) -> dict[str, dict]:
    """
    Query RDAP for a list of domain names concurrently and return all results.

    Parameters
    ----------
    domains:
        List of domain names to query.
    callback:
        Optional ``callable(domain: str, result: dict)`` invoked as each
        domain result becomes available (streaming).
    max_total_time:
        Stop scheduling new queries and mark pending ones as
        ``{"_rdap_error": {"message": "max_total_time exceeded"}}`` after
        this many seconds.  ``None`` = no limit.
    max_sleep_by_endpoint:
        Passed to ``create_rdap_pool()`` when no pool is provided.
        Endpoints whose 429-recovery delay exceeds this are skipped.
    follow_rdap_registrar:
        Also query the registrar's own RDAP endpoint for richer data.
    raw / include_raw / allow_insecure_ssl / allow_invalid_certificate:
        Same as ``domain_async()``.
    rdap_pool:
        Use an existing :class:`RDAPPool`.  If ``None``, one is created
        automatically with ``create_rdap_pool(max_sleep_by_endpoint=...)``.

    Returns
    -------
    dict mapping domain → result dict (or ``_rdap_error`` dict on failure).
    """
    pool = rdap_pool or create_rdap_pool(
        max_sleep_by_endpoint=max_sleep_by_endpoint,
    )
    results: dict[str, dict] = {}
    start = time.monotonic()

    async def _process(domain_name: str) -> tuple[str, dict]:
        try:
            result = await domain_async(
                domain_name,
                raw=raw,
                include_raw=include_raw,
                allow_insecure_ssl=allow_insecure_ssl,
                allow_invalid_certificate=allow_invalid_certificate,
                follow_related=True,
                return_on_error=True,
                follow_rdap_registrar=follow_rdap_registrar,
                rdap_pool=pool,
            )
        except Exception as exc:
            result = {
                "_rdap_error": {
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            }
        return domain_name, result

    # Create all tasks up-front
    task_map: dict[asyncio.Task, str] = {}
    for d in domains:
        task = asyncio.create_task(_process(d))
        task_map[task] = d

    pending = set(task_map.keys())
    try:
        while pending:
            # Check global time budget
            if max_total_time is not None and (time.monotonic() - start) > max_total_time:
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for t in pending:
                    d = task_map[t]
                    if d not in results:
                        results[d] = {
                            "_rdap_error": {"message": "max_total_time exceeded"}
                        }
                        if callback:
                            callback(d, results[d])
                break

            done, pending = await asyncio.wait(
                pending, timeout=0.5, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                try:
                    domain_name, result = task.result()
                except asyncio.CancelledError:
                    continue
                except Exception as exc:
                    domain_name = task_map[task]
                    result = {
                        "_rdap_error": {
                            "error_type": type(exc).__name__,
                            "message": str(exc),
                        }
                    }
                results[domain_name] = result
                if callback:
                    callback(domain_name, result)
    finally:
        pool.flush_status()

    return results


def check_domains(
    domains: list[str],
    callback=None,
    max_total_time: float | None = 86400.0,
    max_sleep_by_endpoint: float | None = 90.0,
    follow_rdap_registrar: bool = True,
    raw: bool = False,
    include_raw: bool = False,
    allow_insecure_ssl: bool = False,
    allow_invalid_certificate: bool = False,
    rdap_pool: RDAPPool | None = None,
) -> dict[str, dict]:
    """
    Synchronous wrapper around :func:`check_domains_async`.

    Runs an asyncio event loop to process *domains* concurrently and returns
    once all results are collected (or *max_total_time* is exceeded).

    See :func:`check_domains_async` for parameter documentation.
    """
    try:
        return asyncio.run(
            check_domains_async(
                domains,
                callback=callback,
                max_total_time=max_total_time,
                max_sleep_by_endpoint=max_sleep_by_endpoint,
                follow_rdap_registrar=follow_rdap_registrar,
                raw=raw,
                include_raw=include_raw,
                allow_insecure_ssl=allow_insecure_ssl,
                allow_invalid_certificate=allow_invalid_certificate,
                rdap_pool=rdap_pool,
            )
        )
    except KeyboardInterrupt:
        flush_status()
        raise
