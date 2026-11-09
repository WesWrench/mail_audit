"""
IANA TLD extraction and WHOIS server discovery.
Scrapes https://www.iana.org/domains/root/db for up-to-date TLD list.
"""

import re
from typing import List, Optional, Dict
from pathlib import Path
import json


def extract_tlds_from_iana_web(timeout: float = 10.0) -> List[str]:
    """
    Extract TLD list from IANA website and convert IDN TLDs to ASCII (Punycode).

    Args:
        timeout: Request timeout

    Returns:
        List of TLDs in ASCII format (without leading dot)
    """
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        raise ImportError("requests and beautifulsoup4 required: pip install requests beautifulsoup4")

    url = "https://www.iana.org/domains/root/db"

    response = requests.get(url, timeout=timeout)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')

    # Find the TLD table first (more precise)
    tld_table = soup.find('table', id='tld-table')

    tlds = []
    if tld_table:
        # Find all TLD spans within the table
        for span in tld_table.find_all('span', class_='domain'):
            tld_text = span.get_text().strip()

            # Remove Unicode control characters (RTL/LTR marks, zero-width chars, etc.)
            tld_cleaned = ''.join(c for c in tld_text if ord(c) >= 32 and ord(c) not in [0x200E, 0x200F, 0x200B, 0x200C, 0x200D, 0xFEFF])

            # Remove leading dot if present
            tld = tld_cleaned.lstrip('.')

            if tld:
                # Convert IDN TLDs to ASCII (Punycode)
                try:
                    tld_ascii = tld.encode('idna').decode('ascii').lower()
                    tlds.append(tld_ascii)
                except Exception:
                    # If conversion fails, use original (already ASCII)
                    tlds.append(tld.lower())
    else:
        # Fallback: search all spans (less precise)
        for span in soup.find_all('span', class_='domain'):
            tld_text = span.get_text().strip()

            # Remove Unicode control characters (RTL/LTR marks, zero-width chars, etc.)
            tld_cleaned = ''.join(c for c in tld_text if ord(c) >= 32 and ord(c) not in [0x200E, 0x200F, 0x200B, 0x200C, 0x200D, 0xFEFF])

            # Remove leading dot if present
            tld = tld_cleaned.lstrip('.')

            if tld:
                # Convert IDN TLDs to ASCII (Punycode)
                try:
                    tld_ascii = tld.encode('idna').decode('ascii').lower()
                    tlds.append(tld_ascii)
                except Exception:
                    # If conversion fails, use original (already ASCII)
                    tlds.append(tld.lower())

    return sorted(set(tlds))


def get_whois_server_from_iana(tld: str, timeout: float = 5.0, try_whois_query: bool = True) -> Optional[str]:
    """
    Get WHOIS server for a TLD from IANA detail page with WHOIS query fallback.

    Args:
        tld: TLD without leading dot
        timeout: Request timeout
        try_whois_query: Try querying IANA WHOIS server directly if not found on web

    Returns:
        WHOIS server or None
    """
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        raise ImportError("requests and beautifulsoup4 required: pip install requests beautifulsoup4")

    # Strategy 1: Scrape IANA HTML page
    url = f"https://www.iana.org/domains/root/db/{tld}.html"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        # Find "WHOIS Server:" in the page
        for b_tag in soup.find_all('b'):
            if 'WHOIS Server:' in b_tag.get_text():
                # WHOIS server is usually in next sibling or parent
                parent = b_tag.parent
                text = parent.get_text()

                # Extract server after "WHOIS Server:"
                match = re.search(r'WHOIS Server:\s*(\S+)', text)
                if match:
                    server = match.group(1).strip()
                    if server:
                        return server

    except Exception:
        pass

    # Strategy 2: Query IANA WHOIS server directly (most reliable)
    if try_whois_query:
        try:
            from . import connection

            response = connection.query_rir("iana", tld, timeout=timeout)

            # Look for "whois:" field in response
            for line in response.split('\n'):
                line_stripped = line.strip()
                if line_stripped.startswith('whois:'):
                    whois_server = line_stripped.split('whois:')[1].strip()
                    if whois_server:
                        return whois_server
        except Exception as e:
            # Silently fail, return None
            pass

    return None


def _test_whois_server(server: str, timeout: float = 2.0) -> bool:
    """
    Test if a WHOIS server responds on port 43.

    Args:
        server: WHOIS server hostname
        timeout: Connection timeout

    Returns:
        True if server responds, False otherwise
    """
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.close()
        return True
    except:
        return False


def build_tld_whois_map_from_web(
    use_cached_tlds: bool = True,
    save_cache: bool = True,
    timeout: float = 5.0,
    max_workers: int = 20,
    verbose: bool = False
) -> Dict[str, str]:
    """
    Build complete TLD -> WHOIS server mapping from IANA web.

    Args:
        use_cached_tlds: Use cached TLD list if available
        save_cache: Save result to cache file
        timeout: Request timeout
        max_workers: Parallel workers for WHOIS queries
        verbose: Print progress

    Returns:
        Dict mapping TLD -> WHOIS server
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Get TLD list
    if verbose:
        print("Fetching TLD list from IANA website...")

    tlds = extract_tlds_from_iana_web(timeout=timeout)

    if verbose:
        print(f"Found {len(tlds)} TLDs")
        print(f"Querying WHOIS servers using {max_workers} parallel workers...")

    results = {}
    completed = 0

    # Query WHOIS servers in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_tld = {
            executor.submit(get_whois_server_from_iana, tld, timeout): tld
            for tld in tlds
        }

        for future in as_completed(future_to_tld):
            tld = future_to_tld[future]
            completed += 1

            try:
                whois_server = future.result()
                if whois_server:
                    results[tld] = whois_server

                if verbose and completed % 100 == 0:
                    print(f"  Progress: {completed}/{len(tlds)} ({completed/len(tlds)*100:.1f}%) - {len(results)} servers found")

            except Exception as e:
                if verbose:
                    print(f"  Error querying {tld}: {e}")

    if verbose:
        print(f"\nComplete: {len(results)} WHOIS servers found")

    # Save to cache if requested
    if save_cache:
        try:
            from .bootstrap import get_data_file_path
            cache_file = get_data_file_path("iana_web_cache.json")
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'tlds': tlds,
                    'whois_servers': results
                }, f, indent=2, ensure_ascii=False)

            if verbose:
                print(f"Cached to: {cache_file}")
        except Exception as e:
            if verbose:
                print(f"Warning: Could not save cache: {e}")

    return results


def load_iana_web_cache() -> Optional[Dict]:
    """Load cached IANA web data."""
    try:
        from .bootstrap import get_data_file_path
        cache_file = get_data_file_path("iana_web_cache.json")
        if cache_file.exists():
            with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return None


def load_ruby_whois_servers(check_update: bool = True, timeout: float = 5.0, verbose: bool = False) -> Dict[str, str]:
    """
    Load WHOIS servers from the Ruby WHOIS library data.

    This provides an additional source of WHOIS servers to complement IANA data.
    Source: https://github.com/weppos/whois

    Args:
        check_update: If True, check if remote file has been updated using ETag
        timeout: Request timeout
        verbose: Print update information

    Returns:
        Dict mapping TLD -> WHOIS server
    """
    try:
        import requests
    except ImportError:
        raise ImportError("requests required: pip install requests")

    from .bootstrap import get_data_file_path

    local_file = get_data_file_path("tld_whois_ruby.json")
    url = "https://raw.githubusercontent.com/weppos/whois/refs/heads/main/data/tld.json"

    # Check if we need to update the file
    if check_update and local_file.exists():
        try:
            # Load current ETag from metadata file
            etag_file = local_file.with_suffix('.etag')
            current_etag = None
            if etag_file.exists():
                with open(etag_file, 'r') as f:
                    current_etag = f.read().strip()

            # Check remote ETag with HEAD request
            head_response = requests.head(url, timeout=timeout)
            remote_etag = head_response.headers.get('ETag', '').strip('"')

            if remote_etag and current_etag == remote_etag:
                if verbose:
                    print("Ruby WHOIS data is up to date (ETag match)")
            else:
                # Download updated file
                if verbose:
                    print(f"Downloading updated Ruby WHOIS data (ETag: {remote_etag})...")

                response = requests.get(url, timeout=timeout)
                response.raise_for_status()

                with open(local_file, 'wb') as f:
                    f.write(response.content)

                # Save ETag
                with open(etag_file, 'w') as f:
                    f.write(remote_etag)

                if verbose:
                    print("Ruby WHOIS data updated successfully")

        except Exception as e:
            if verbose:
                print(f"Warning: Could not check for updates: {e}")

    # Load and parse the file
    if not local_file.exists():
        if verbose:
            print("Ruby WHOIS data file not found, downloading...")

        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        with open(local_file, 'wb') as f:
            f.write(response.content)

        # Save ETag
        remote_etag = response.headers.get('ETag', '').strip('"')
        if remote_etag:
            etag_file = local_file.with_suffix('.etag')
            with open(etag_file, 'w') as f:
                f.write(remote_etag)

    # Parse JSON and extract WHOIS servers
    with open(local_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    whois_servers = {}
    for tld, info in data.items():
        # Skip metadata entry
        if tld == '_':
            continue

        # Extract host if present and adapter is not "none"
        if isinstance(info, dict):
            host = info.get('host')
            adapter = info.get('adapter')

            # Only include if host is specified and adapter is not "none"
            if host and adapter != 'none':
                whois_servers[tld.lower()] = host

    return whois_servers
