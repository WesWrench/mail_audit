"""
Bootstrap module for loading TLD WHOIS servers with async support and caching.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, Optional, List
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .connection import query_rir, async_whois_query
from .exceptions import WhoisError


# Global cache for TLD WHOIS servers
# Changed to Dict[str, List[str]] to support multiple servers with fallback
_TLD_WHOIS_SERVERS: Dict[str, List[str]] = {}
_TLD_WORKING_SERVERS: Dict[str, str] = {}  # Cache of servers that work for each TLD
_BOOTSTRAP_LOCK = threading.Lock()
_BOOTSTRAP_COMPLETE = False


def get_data_file_path(filename: str) -> Path:
    """Get the path to a data file."""
    package_dir = Path(__file__).parent
    data_dir = package_dir / "data"
    if data_dir.exists():
        return data_dir / filename
    parent_data_dir = package_dir.parent / "data"
    if parent_data_dir.exists():
        return parent_data_dir / filename
    raise FileNotFoundError(f"Data directory not found. Looking for: {filename}")


def load_tld_list_from_cache() -> Optional[List[str]]:
    """Load cached TLD list from disk."""
    try:
        cache_file = get_data_file_path("iana_tlds_cache.json")
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('tlds', [])
    except Exception:
        pass
    return None


def save_tld_list_to_cache(tlds: List[str]) -> None:
    """Save TLD list to disk cache."""
    try:
        cache_file = get_data_file_path("iana_tlds_cache.json")
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({'tlds': tlds}, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Warning: Could not save TLD cache: {e}")


def load_tld_list(use_cache: bool = False, timeout: float = 10.0) -> List[str]:
    """
    Load list of TLDs by scraping IANA website.

    Args:
        use_cache: If True, try to load from cache first
        timeout: Request timeout for web scraping

    Returns:
        List of TLDs
    """
    # Try cache first if requested
    if use_cache:
        cached = load_tld_list_from_cache()
        if cached:
            return cached

    # Scrape from IANA website
    from .iana import extract_tlds_from_iana_web
    tlds = extract_tlds_from_iana_web(timeout=timeout)

    return tlds


def query_tld_whois_server(tld: str, timeout: float = 3.0, try_fallback: bool = True) -> Optional[str]:
    """
    Query IANA for the WHOIS server of a specific TLD.

    Args:
        tld: TLD without leading dot
        timeout: Query timeout
        try_fallback: If True, try whois.nic.<tld> if IANA doesn't provide server

    Returns:
        WHOIS server or None
    """
    try:
        response = query_rir("iana", tld, timeout=timeout)
        for line in response.split('\n'):
            line = line.strip()
            if line.startswith('whois:'):
                whois_server = line.split('whois:')[1].strip()
                if whois_server:
                    return whois_server

        # Fallback: try standard convention whois.nic.<tld>
        if try_fallback:
            fallback_server = f"whois.nic.{tld}"
            try:
                # Quick test if fallback server responds
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((fallback_server, 43))
                sock.close()
                return fallback_server
            except:
                pass

        return None
    except Exception:
        return None


def load_bootstrap_cache() -> Optional[Dict[str, List[str]]]:
    """Load cached bootstrap results from disk.

    Returns:
        Dictionary mapping TLD -> List of WHOIS servers
        (Backward compatible: converts old Dict[str, str] format to Dict[str, List[str]])
    """
    try:
        cache_file = get_data_file_path("bootstrap_cache.json")
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

                # Check if it's the old format (Dict[str, str]) or new format (Dict[str, List[str]])
                if data:
                    first_value = next(iter(data.values()))

                    # Old format: convert str -> List[str]
                    if isinstance(first_value, str):
                        return {tld: [server] for tld, server in data.items()}

                    # New format: already List[str]
                    return data

                return data
    except Exception:
        pass
    return None


def save_bootstrap_cache(cache: Dict[str, List[str]]) -> None:
    """Save bootstrap results to disk cache in new format.

    Args:
        cache: Dictionary mapping TLD -> List of WHOIS servers
    """
    try:
        cache_file = get_data_file_path("bootstrap_cache.json")
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2, ensure_ascii=False, sort_keys=True)
    except Exception as e:
        print(f"Warning: Could not save bootstrap cache: {e}")


def bootstrap(
    force: bool = False,
    timeout: float = 3.0,
    max_tlds: Optional[int] = None,
    verbose: bool = False,
    max_workers: int = 40,
    tlds_iana_cache: bool = False,
    whois_server_cache: bool = False,
    use_ruby_whois: bool = True
) -> None:
    """
    Bootstrap TLD WHOIS servers using parallel queries with multiple sources.

    Data is loaded in this order (each source enriches the previous):
    1. Ruby WHOIS library (base layer — 1,317+ TLDs)
    2. Other curated sources (enrichment — 1,258+ additional TLDs)
    3. IANA live queries (fill remaining gaps)

    Parallel queries via ``ThreadPoolExecutor`` are used for the IANA phase
    because querying each TLD individually over TCP/43 would take ~45 minutes
    sequentially.  With 40 workers the full bootstrap completes in ~1–2 minutes.

    Each TLD can have multiple WHOIS servers for automatic fallback.
    The results are always saved to disk after a live bootstrap.

    Args:
        force: Re-bootstrap even if the in-memory cache already exists.
        timeout: Per-TLD query timeout in seconds (default: 3).
        max_tlds: Limit the number of TLDs processed — useful for testing.
        verbose: Print progress information to stdout.
        max_workers: Number of parallel IANA query workers (default: 40).
        tlds_iana_cache: If True, use the cached TLD list instead of
                         re-scraping IANA (faster restarts).
        whois_server_cache: If True, load the WHOIS server map from the on-disk
                            cache instead of performing live queries (fastest).
                            The disk cache is always written after a live run.
        use_ruby_whois: If True (default), use the Ruby WHOIS library data as
                        the base layer of TLD coverage.

    Returns:
        None.  Use :func:`get_bootstrap_stats` to inspect the loaded cache
        programmatically, or pass ``verbose=True`` to print progress.

    Example:
        >>> import whoisitlegacy
        >>> whoisitlegacy.bootstrap()                          # silent, live
        >>> whoisitlegacy.bootstrap(verbose=True)              # with progress
        >>> whoisitlegacy.bootstrap(whois_server_cache=True)  # fast from cache
    """
    global _TLD_WHOIS_SERVERS, _BOOTSTRAP_COMPLETE

    # Check if already bootstrapped in memory
    if _BOOTSTRAP_COMPLETE and not force:
        if verbose:
            stats = get_bootstrap_stats()
            print(f"Already bootstrapped: {stats['tlds_cached']} TLDs in memory")
        return

    with _BOOTSTRAP_LOCK:
        # Double-check after acquiring lock
        if _BOOTSTRAP_COMPLETE and not force:
            return

        # Try to load from disk cache first (only if whois_server_cache=True)
        if whois_server_cache and not force:
            cached = load_bootstrap_cache()
            if cached:
                _TLD_WHOIS_SERVERS.clear()
                _TLD_WHOIS_SERVERS.update(cached)
                _BOOTSTRAP_COMPLETE = True
                if verbose:
                    total = sum(len(v) for v in cached.values())
                    print(f"Bootstrap loaded from cache: {len(cached)} TLDs, {total} servers")
                return

        if verbose:
            print("Starting parallel bootstrap of TLD WHOIS servers...")

        # Load Ruby WHOIS data as fallback source
        ruby_servers = {}
        if use_ruby_whois:
            try:
                from .iana import load_ruby_whois_servers
                ruby_servers = load_ruby_whois_servers(check_update=True, timeout=timeout, verbose=verbose)
                if verbose:
                    print(f"Loaded {len(ruby_servers)} WHOIS servers from Ruby WHOIS library")
            except Exception as e:
                if verbose:
                    print(f"Warning: Could not load Ruby WHOIS data: {e}")

        # Load additional WHOIS servers from other sources
        other_servers = {}
        try:
            from pathlib import Path
            import json
            other_file = Path(__file__).parent / "data" / "other_whois_servers.json"
            if other_file.exists():
                with open(other_file, "r", encoding="utf-8") as f:
                    other_servers = json.load(f)
                if verbose:
                    print(f"Enriched with {len(other_servers)} additional WHOIS servers from other sources")
        except Exception as e:
            if verbose:
                print(f"Warning: Could not load other WHOIS servers: {e}")

        # Load TLD list (scrape IANA unless tlds_iana_cache=True)
        try:
            tlds = load_tld_list(use_cache=tlds_iana_cache, timeout=timeout)

            # Save TLD cache if requested
            if tlds_iana_cache:
                save_tld_list_to_cache(tlds)

        except Exception as e:
            raise WhoisError(f"Failed to load TLD list: {e}")

        if max_tlds:
            tlds = tlds[:max_tlds]

        if verbose:
            print(f"Querying IANA for {len(tlds)} TLDs using {max_workers} parallel workers...")

        # Store results as Dict[str, List[str]] for multiple servers per TLD
        results: Dict[str, List[str]] = {}

        # Initialize results with Ruby WHOIS servers
        for tld, server in ruby_servers.items():
            if tld not in results:
                results[tld] = []
            if server not in results[tld]:
                results[tld].append(server)

        # Add servers from other sources (merge, don't overwrite)
        for tld, server in other_servers.items():
            if tld not in results:
                results[tld] = []
            if server not in results[tld]:
                results[tld].append(server)

        completed = 0

        # Query in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_tld = {
                executor.submit(query_tld_whois_server, tld, timeout): tld
                for tld in tlds
            }

            # Process results as they complete
            for future in as_completed(future_to_tld):
                tld = future_to_tld[future]
                completed += 1

                try:
                    whois_server = future.result()
                    if whois_server:
                        # Add IANA server to the list
                        if tld not in results:
                            results[tld] = []
                        if whois_server not in results[tld]:
                            results[tld].append(whois_server)

                    if verbose and completed % 100 == 0:
                        total_servers = sum(len(servers) for servers in results.values())
                        print(f"  Progress: {completed}/{len(tlds)} ({completed/len(tlds)*100:.1f}%) - {len(results)} TLDs, {total_servers} total servers")

                except Exception as e:
                    if verbose and completed % 100 == 0:
                        print(f"  Error querying {tld}: {e}")

        # Update global cache
        _TLD_WHOIS_SERVERS.clear()
        _TLD_WHOIS_SERVERS.update(results)
        _BOOTSTRAP_COMPLETE = True

        # Always save to disk cache after bootstrap (even if whois_server_cache=False)
        # The whois_server_cache flag only controls whether we LOAD from cache on startup
        save_bootstrap_cache(results)

        if verbose:
            total_servers = sum(len(servers) for servers in results.values())
            print(f"\nBootstrap complete: {len(results)} TLDs, {total_servers} servers")


async def _async_query_tld_whois_server(tld: str, timeout: float, semaphore: asyncio.Semaphore) -> tuple:
    """Query IANA for the WHOIS server of a TLD (async, semaphore-limited)."""
    async with semaphore:
        try:
            response = await async_whois_query("whois.iana.org", 43, tld, timeout=timeout, max_retries=1)
            for line in response.split('\n'):
                line = line.strip()
                if line.startswith('whois:'):
                    whois_server = line.split('whois:')[1].strip()
                    if whois_server:
                        return tld, whois_server
        except Exception:
            pass
        return tld, None


async def bootstrap_async(
    force: bool = False,
    timeout: float = 3.0,
    max_tlds: Optional[int] = None,
    verbose: bool = False,
    max_workers: int = 40,
    tlds_iana_cache: bool = False,
    whois_server_cache: bool = False,
    use_ruby_whois: bool = True,
) -> None:
    """
    Async version of :func:`bootstrap` — uses ``asyncio.gather`` with a semaphore
    instead of ``ThreadPoolExecutor`` for non-blocking concurrent IANA queries.

    Args:
        force: Re-bootstrap even if the in-memory cache already exists.
        timeout: Per-TLD query timeout in seconds (default: 3).
        max_tlds: Limit the number of TLDs processed — useful for testing.
        verbose: Print progress information to stdout.
        max_workers: Maximum concurrent IANA queries (default: 40).
        tlds_iana_cache: If True, use the cached TLD list instead of re-scraping IANA.
        whois_server_cache: If True, load the WHOIS server map from the on-disk cache.
        use_ruby_whois: If True (default), use the Ruby WHOIS library data as base layer.

    Returns:
        None.

    Example:
        >>> import asyncio, whoisitlegacy
        >>> asyncio.run(whoisitlegacy.bootstrap_async())
        >>> asyncio.run(whoisitlegacy.bootstrap_async(whois_server_cache=True))
    """
    global _TLD_WHOIS_SERVERS, _BOOTSTRAP_COMPLETE

    if _BOOTSTRAP_COMPLETE and not force:
        if verbose:
            stats = get_bootstrap_stats()
            print(f"Already bootstrapped: {stats['tlds_cached']} TLDs in memory")
        return

    # Try to load from disk cache first (only if whois_server_cache=True)
    if whois_server_cache and not force:
        cached = load_bootstrap_cache()
        if cached:
            with _BOOTSTRAP_LOCK:
                _TLD_WHOIS_SERVERS.clear()
                _TLD_WHOIS_SERVERS.update(cached)
                _BOOTSTRAP_COMPLETE = True
            if verbose:
                total = sum(len(v) for v in cached.values())
                print(f"Bootstrap loaded from cache: {len(cached)} TLDs, {total} servers")
            return

    if verbose:
        print("Starting async bootstrap of TLD WHOIS servers...")

    # Load Ruby WHOIS data as base source (blocking I/O — run in executor)
    ruby_servers = {}
    if use_ruby_whois:
        try:
            from .iana import load_ruby_whois_servers
            ruby_servers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: load_ruby_whois_servers(check_update=True, timeout=timeout, verbose=verbose)
            )
            if verbose:
                print(f"Loaded {len(ruby_servers)} WHOIS servers from Ruby WHOIS library")
        except Exception as e:
            if verbose:
                print(f"Warning: Could not load Ruby WHOIS data: {e}")

    # Load additional WHOIS servers from other sources
    other_servers = {}
    try:
        other_file = Path(__file__).parent / "data" / "other_whois_servers.json"
        if other_file.exists():
            with open(other_file, "r", encoding="utf-8") as f:
                other_servers = json.load(f)
            if verbose:
                print(f"Enriched with {len(other_servers)} additional WHOIS servers from other sources")
    except Exception as e:
        if verbose:
            print(f"Warning: Could not load other WHOIS servers: {e}")

    # Load TLD list (blocking HTTP scrape — run in executor)
    try:
        tlds = await asyncio.get_event_loop().run_in_executor(
            None, lambda: load_tld_list(use_cache=tlds_iana_cache, timeout=timeout)
        )
        if tlds_iana_cache:
            save_tld_list_to_cache(tlds)
    except Exception as e:
        raise WhoisError(f"Failed to load TLD list: {e}")

    if max_tlds:
        tlds = tlds[:max_tlds]

    if verbose:
        print(f"Querying IANA for {len(tlds)} TLDs with concurrency={max_workers}...")

    # Initialise results from static sources
    results: Dict[str, List[str]] = {}
    for tld, server in ruby_servers.items():
        if tld not in results:
            results[tld] = []
        if server not in results[tld]:
            results[tld].append(server)
    for tld, server in other_servers.items():
        if tld not in results:
            results[tld] = []
        if server not in results[tld]:
            results[tld].append(server)

    # Async parallel IANA queries using a semaphore
    semaphore = asyncio.Semaphore(max_workers)
    tasks = [_async_query_tld_whois_server(tld, timeout, semaphore) for tld in tlds]

    completed = 0
    for coro in asyncio.as_completed(tasks):
        tld, whois_server = await coro
        completed += 1
        if whois_server:
            if tld not in results:
                results[tld] = []
            if whois_server not in results[tld]:
                results[tld].append(whois_server)
        if verbose and completed % 100 == 0:
            total_servers = sum(len(s) for s in results.values())
            print(f"  Progress: {completed}/{len(tlds)} ({completed/len(tlds)*100:.1f}%) - {len(results)} TLDs, {total_servers} total servers")

    with _BOOTSTRAP_LOCK:
        _TLD_WHOIS_SERVERS.clear()
        _TLD_WHOIS_SERVERS.update(results)
        _BOOTSTRAP_COMPLETE = True

    save_bootstrap_cache(results)

    if verbose:
        total_servers = sum(len(s) for s in results.values())
        print(f"\nAsync bootstrap complete: {len(results)} TLDs, {total_servers} servers")


def get_cached_whois_server(tld: str) -> Optional[str]:
    """
    Get cached WHOIS server for a TLD.
    Returns the first working server if known, otherwise the first available server.
    """
    tld = tld.lower()

    # Check if we have a known working server
    if tld in _TLD_WORKING_SERVERS:
        return _TLD_WORKING_SERVERS[tld]

    # Otherwise return the first server from the list
    servers = _TLD_WHOIS_SERVERS.get(tld)
    if servers and len(servers) > 0:
        return servers[0]

    return None


def get_all_whois_servers(tld: str) -> List[str]:
    """Get all available WHOIS servers for a TLD (for fallback)."""
    return _TLD_WHOIS_SERVERS.get(tld.lower(), [])


def mark_working_server(tld: str, server: str):
    """Mark a server as working for a TLD (cache it)."""
    _TLD_WORKING_SERVERS[tld.lower()] = server


def is_bootstrapped() -> bool:
    """Check if bootstrap has been completed."""
    return _BOOTSTRAP_COMPLETE


def get_bootstrap_stats() -> Dict[str, int]:
    """Get bootstrap statistics."""
    return {
        "tlds_cached": len(_TLD_WHOIS_SERVERS),
        "is_complete": _BOOTSTRAP_COMPLETE
    }


def clear_cache():
    """Clear the TLD WHOIS server cache."""
    global _TLD_WHOIS_SERVERS, _BOOTSTRAP_COMPLETE
    with _BOOTSTRAP_LOCK:
        _TLD_WHOIS_SERVERS.clear()
        _BOOTSTRAP_COMPLETE = False
