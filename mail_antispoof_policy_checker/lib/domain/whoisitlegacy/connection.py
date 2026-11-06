"""
Low-level TCP/43 WHOIS connection handler.

This module handles the raw socket connection to WHOIS servers,
with both synchronous and asynchronous implementations.
"""

import asyncio
import socket
import time
from typing import Optional
from .exceptions import WhoisConnectionError


# WHOIS servers for each RIR
RIR_SERVERS = {
    "arin": ("whois.arin.net", 43),
    "ripe": ("whois.ripe.net", 43),
    "ripencc": ("whois.ripe.net", 43),  # Alias
    "afrinic": ("whois.afrinic.net", 43),
    "apnic": ("whois.apnic.net", 43),
    "lacnic": ("whois.lacnic.net", 43),
    "iana": ("whois.iana.org", 43),  # IANA for RIR delegation lookup
}


def whois_query(
    host: str,
    port: int,
    query: str,
    timeout: float = 10.0,
    encoding: str = "utf-8",
    max_retries: int = 5,
    retry_delay: float = 1.0
) -> str:
    """
    Execute a raw WHOIS query over TCP/43 with retry logic.

    Args:
        host: WHOIS server hostname
        port: WHOIS server port (usually 43)
        query: Query string to send
        timeout: Socket timeout in seconds
        encoding: Character encoding (default: utf-8, fallback to latin-1)
        max_retries: Maximum number of connection retry attempts (default: 5)
        retry_delay: Delay in seconds between retry attempts (default: 1.0)

    Returns:
        Raw WHOIS response as string

    Raises:
        WhoisConnectionError: If connection fails after all retries
    """
    last_error = None

    for attempt in range(max_retries):
        sock = None
        try:
            # Prepare query with CRLF termination
            payload = (query.strip() + "\r\n").encode(encoding, errors="replace")

            # Create socket connection manually for better control
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send query
            sock.sendall(payload)

            # Receive response
            chunks = []
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                except socket.error as recv_error:
                    # Some servers close connection abruptly after sending data
                    # If we already received some data, that's fine
                    if chunks:
                        break
                    raise recv_error

            # Decode response
            raw = b"".join(chunks)
            try:
                response = raw.decode(encoding)
            except UnicodeDecodeError:
                # Fallback to latin-1 if UTF-8 fails
                response = raw.decode("latin-1", errors="replace")

            return response

        except socket.timeout as e:
            last_error = WhoisConnectionError(f"Connection to {host}:{port} timed out: {e}")
        except socket.error as e:
            last_error = WhoisConnectionError(f"Connection to {host}:{port} failed: {e}")
        except Exception as e:
            last_error = WhoisConnectionError(f"Unexpected error querying {host}:{port}: {e}")
        finally:
            # Always close the socket if it was created
            if sock is not None:
                try:
                    sock.close()
                except:
                    pass

        # If we got an error and have retries left, wait and try again
        if attempt < max_retries - 1:
            time.sleep(retry_delay)

    # If we exhausted all retries, raise the last error
    raise last_error


async def async_whois_query(
    host: str,
    port: int,
    query: str,
    timeout: float = 10.0,
    encoding: str = "utf-8",
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> str:
    """
    Execute a raw WHOIS query over TCP/43 using asyncio (non-blocking).

    Args:
        host: WHOIS server hostname
        port: WHOIS server port (usually 43)
        query: Query string to send
        timeout: Connection + read timeout in seconds
        encoding: Character encoding (default: utf-8, fallback to latin-1)
        max_retries: Maximum number of connection retry attempts (default: 3)
        retry_delay: Delay in seconds between retry attempts (default: 1.0)

    Returns:
        Raw WHOIS response as string

    Raises:
        WhoisConnectionError: If connection fails after all retries
    """
    payload = (query.strip() + "\r\n").encode(encoding, errors="replace")
    last_error = None

    for attempt in range(max_retries):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            try:
                writer.write(payload)
                await writer.drain()

                chunks = []
                while True:
                    try:
                        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                        if not data:
                            break
                        chunks.append(data)
                    except asyncio.TimeoutError:
                        break

                raw = b"".join(chunks)
                try:
                    return raw.decode(encoding)
                except UnicodeDecodeError:
                    return raw.decode("latin-1", errors="replace")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        except asyncio.TimeoutError as e:
            last_error = WhoisConnectionError(f"Connection to {host}:{port} timed out: {e}")
        except OSError as e:
            last_error = WhoisConnectionError(f"Connection to {host}:{port} failed: {e}")
        except Exception as e:
            last_error = WhoisConnectionError(f"Unexpected error querying {host}:{port}: {e}")

        if attempt < max_retries - 1:
            await asyncio.sleep(retry_delay)

    raise last_error


async def async_query_rir(
    rir: str,
    query: str,
    timeout: float = 10.0,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> str:
    """
    Async version of :func:`query_rir`.

    Args:
        rir: RIR name (arin, ripe, afrinic, apnic, lacnic)
        query: Query string
        timeout: Socket timeout in seconds
        max_retries: Maximum number of connection retry attempts (default: 3)
        retry_delay: Delay in seconds between retry attempts (default: 1.0)

    Returns:
        Raw WHOIS response

    Raises:
        WhoisConnectionError: If RIR is unknown or connection fails after all retries
    """
    rir_lower = rir.lower()

    if rir_lower not in RIR_SERVERS:
        raise WhoisConnectionError(f"Unknown RIR: {rir}. Valid RIRs: {', '.join(RIR_SERVERS.keys())}")

    host, port = RIR_SERVERS[rir_lower]
    return await async_whois_query(host, port, query, timeout=timeout,
                                   max_retries=max_retries, retry_delay=retry_delay)


def query_rir(
    rir: str,
    query: str,
    timeout: float = 10.0,
    max_retries: int = 5,
    retry_delay: float = 1.0
) -> str:
    """
    Query a specific RIR's WHOIS server with retry logic.

    Args:
        rir: RIR name (arin, ripe, afrinic, apnic, lacnic)
        query: Query string
        timeout: Socket timeout in seconds
        max_retries: Maximum number of connection retry attempts (default: 5)
        retry_delay: Delay in seconds between retry attempts (default: 1.0)

    Returns:
        Raw WHOIS response

    Raises:
        WhoisConnectionError: If RIR is unknown or connection fails after all retries
    """
    rir_lower = rir.lower()

    if rir_lower not in RIR_SERVERS:
        raise WhoisConnectionError(f"Unknown RIR: {rir}. Valid RIRs: {', '.join(RIR_SERVERS.keys())}")

    host, port = RIR_SERVERS[rir_lower]
    return whois_query(host, port, query, timeout=timeout, max_retries=max_retries, retry_delay=retry_delay)
