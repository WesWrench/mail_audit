import asyncio
import smtplib
import socket
import time
import re
import ipaddress
from typing import Any, Dict, List, Optional, Union

from .exceptions import SMTPConnectionError
from .config import DEFAULT_OPTIONS, validate_options


class SMTPChecker:
    """
    SMTP configuration checker using a single SMTP session.

    - Uses one TCP connection for all tests.
    - Can be initialized with a hostname or IP.
    - Open relay test sender/recipient are configurable.
    - Returns a dict with all tests + a global SMTP-only session transcript.
    - Supports selective test execution via options parameter.
    """

    def __init__(
        self,
        target: Union[str, List[str]],
        port: int = 25,
        timeout: float = 10.0,
        open_relay_sender: Optional[str] = None,
        open_relay_recipient: Optional[str] = None,
        open_relay_mode: str = "rcpt",
        options: Optional[Dict[str, bool]] = None,
    ) -> None:
        """
        :param target: SMTP server hostname or IP address, **or a list of
                       hostnames/IPs** for batch scanning.
                       - Single string → ``run_all_tests()`` returns a dict.
                       - List of strings → ``run_all_tests()`` returns a list
                         of dicts (one per target, sequential);
                         ``run_all_tests_async()`` scans them concurrently.
        :param port:   TCP port (default 25).
        :param timeout: Connection timeout in seconds.
        :param open_relay_sender: Sender address used for open relay test.
        :param open_relay_recipient: Recipient address used for open relay test.
        :param open_relay_mode: How far the open relay test goes:
            ``"rcpt"`` (default) stops after RCPT TO (like MXToolbox);
            ``"data"`` also sends DATA and checks for 354, then drops the
            connection without sending any content (like Nessus) — nothing is relayed.
        :param options: Dictionary specifying which tests to run (default: all enabled except timing tests).
        """
        if isinstance(target, list):
            self._target_list: Optional[List[str]] = target
            self.target = target[0] if target else ""
        else:
            self._target_list = None
            self.target = target
        self.port = port
        self.timeout = timeout

        # Open relay test configuration
        self.open_relay_sender = open_relay_sender
        self.open_relay_recipient = open_relay_recipient
        if open_relay_mode not in ("rcpt", "data"):
            raise ValueError("open_relay_mode must be 'rcpt' or 'data'")
        self.open_relay_mode = open_relay_mode

        # Test options
        if options is None:
            self.options = DEFAULT_OPTIONS.copy()
        else:
            self.options = validate_options(options)

        # SMTP session
        self.smtp: Optional[smtplib.SMTP] = None
        self.session_transcript: list[str] = []

        # Cached info
        self.connection_time: Optional[float] = None
        self.transaction_time: Optional[float] = None
        self.banner: Optional[str] = None
        self.banner_hostname: Optional[str] = None
        self.peer_ip: Optional[str] = None
        self.reverse_dns_host: Optional[str] = None

        # Internal state
        self.dns_resolution_error: Optional[str] = None
        self.connection_error: Optional[str] = None
        self.ehlo_done: bool = False

        # TLS certificate captured during test_smtp_starttls_cert (if enabled)
        self.tls_cert_der: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Logging / helpers
    # ------------------------------------------------------------------
    def _log(self, direction: str, message: str) -> None:
        """
        Append a line to the global session transcript (SMTP-visible bits only).

        :param direction: "C" for client, "S" for server, "I" for info.
        :param message:   Message to log.
        """
        line = f"[{direction}] {message}"
        self.session_transcript.append(line)

    def _connect_if_needed(self) -> bool:
        """
        Ensure that the SMTP session is connected and the banner is read.

        Only logs what would appear in an SMTP transcript:
        - Connecting line
        - 220 banner

        :raises SMTPConnectionError: If connection fails.
        :return: True if connected successfully, False otherwise.
        """
        if self.smtp is not None:
            return True

        try:
            self._log("I", f"Connecting to {self.target}:{self.port}")

            smtp = smtplib.SMTP(timeout=self.timeout)

            start = time.time()
            code, msg = smtp.connect(self.target, self.port)
            end = time.time()

            self.connection_time = end - start
            decoded_msg = msg.decode(errors="replace") if isinstance(msg, (bytes, bytearray)) else str(msg)
            self.banner = decoded_msg
            self._log("S", f"{code} {decoded_msg}")

            # Extract banner hostname (first token)
            parts = decoded_msg.split()
            if parts:
                self.banner_hostname = parts[0]

            # Get peer IP from the socket (not logged in transcript)
            try:
                peer = smtp.sock.getpeername()
                self.peer_ip = peer[0]
            except Exception:
                pass

            self.smtp = smtp
            return True

        except socket.gaierror as exc:
            self.dns_resolution_error = str(exc)
            error_msg = f"DNS resolution failed for {self.target}: {exc}"
            raise SMTPConnectionError(error_msg, exc)
        except (socket.timeout, OSError, smtplib.SMTPConnectError) as exc:
            self.connection_error = str(exc)
            error_msg = f"Failed to connect to {self.target}:{self.port}: {exc}"
            raise SMTPConnectionError(error_msg, exc)

    def _ehlo_if_needed(self) -> None:
        """
        Send EHLO once per session.

        Logged in transcript as:
        [C] EHLO <client-hostname>
        [S] 250-...
        """
        if self.smtp is None or self.ehlo_done:
            return

        try:
            self._log("C", "EHLO")
            code, msg = self.smtp.ehlo()
            decoded_msg = msg.decode(errors="replace") if isinstance(msg, (bytes, bytearray)) else str(msg)

            for line in decoded_msg.splitlines():
                self._log("S", line if line.startswith("250") else f"250-{line}")

            self.ehlo_done = True
        except smtplib.SMTPHeloError:
            pass

    def _perform_reverse_dns(self) -> Optional[str]:
        """
        Perform PTR lookup on server IP (reverse DNS).

        Uses dns.resolver with Google DNS (8.8.8.8) as default resolver
        for more reliable results than system DNS.

        NOTE: No logging here – DNS is not part of the visible SMTP transcript.
        """
        if self.peer_ip is None:
            return None

        if self.reverse_dns_host is not None:
            return self.reverse_dns_host

        # Try with dnspython first (more reliable)
        try:
            import dns.resolver
            import dns.reversename

            # Create resolver with Google DNS
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google DNS + Cloudflare DNS
            resolver.timeout = 5
            resolver.lifetime = 5

            # Get reverse DNS name (e.g., "18.201.254.51.in-addr.arpa")
            rev_name = dns.reversename.from_address(self.peer_ip)

            # Perform PTR query
            answers = resolver.resolve(rev_name, 'PTR')
            if answers:
                # Get first PTR record
                self.reverse_dns_host = str(answers[0].target).rstrip(".")
                return self.reverse_dns_host
        except ImportError:
            # dnspython not installed, fallback to socket
            pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            # No PTR record found
            self.reverse_dns_host = None
            return None
        except Exception:
            # Other DNS errors, try fallback
            pass

        # Fallback to socket.gethostbyaddr (uses system DNS)
        try:
            host, _aliases, _addrs = socket.gethostbyaddr(self.peer_ip)
            self.reverse_dns_host = host.rstrip(".")
        except (socket.herror, socket.gaierror):
            self.reverse_dns_host = None

        return self.reverse_dns_host

    @staticmethod
    def _resolve_hostname(hostname: str) -> Optional[set]:
        """
        Resolve hostname to IP addresses using dns.resolver with fallback to socket.

        Uses Google DNS (8.8.8.8) and Cloudflare DNS (1.1.1.1) for more reliable results.

        :param hostname: Hostname to resolve.
        :return: Set of IP addresses or None if resolution fails.
        """
        ips = set()

        # Try with dnspython first (more reliable)
        try:
            import dns.resolver

            # Create resolver with Google DNS
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            resolver.timeout = 5
            resolver.lifetime = 5

            # Try A records (IPv4)
            try:
                answers = resolver.resolve(hostname, 'A')
                for rdata in answers:
                    ips.add(str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            # Try AAAA records (IPv6)
            try:
                answers = resolver.resolve(hostname, 'AAAA')
                for rdata in answers:
                    ips.add(str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            if ips:
                return ips

        except ImportError:
            # dnspython not installed, use fallback
            pass
        except Exception:
            # Other DNS errors, try fallback
            pass

        # Fallback to socket.getaddrinfo (uses system DNS)
        try:
            infos = socket.getaddrinfo(hostname, None)
            for info in infos:
                ips.add(info[4][0])
            return ips if ips else None
        except socket.gaierror:
            return None

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        """
        Return True if `value` looks like an IPv4 or IPv6 address.
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """
        Simple syntactic validation for a DNS hostname.
        """
        if len(hostname) > 253:
            return False

        if hostname.endswith("."):
            hostname = hostname[:-1]

        labels = hostname.split(".")
        if not labels:
            return False

        label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
        return all(label_re.match(label) for label in labels)

    def _domain_has_mx(self, domain: str) -> Optional[bool]:
        """
        Check if the given domain has at least one MX record.

        NOTE: No logging in transcript – DNS is not part of SMTP transcript.

        :param domain: Domain part after '@'.
        :return:
          - True  -> at least one MX record found
          - False -> no MX record
          - None  -> could not check (e.g. dnspython not installed)
        """
        try:
            import dns.resolver
        except ImportError:
            return None

        try:
            answers = dns.resolver.resolve(domain, "MX")
            count = len(list(answers))
            return count > 0
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            return False

    def close(self) -> None:
        """
        Gracefully close the SMTP session.

        QUIT is not logged (MXToolbox does not show it).
        """
        if self.smtp is not None:
            try:
                self.smtp.quit()
            except Exception:
                pass
            finally:
                self.smtp = None

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------
    def test_smtp_banner_check(self) -> Dict[str, Any]:
        """
        Test 1: SMTP Banner Check / Reverse Banner Check.
        Compare banner hostname and reverse DNS hostname.
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Banner Check",
                    "status": "PROBLEM",
                    "ok": False,
                    "details": "Unable to connect to SMTP server; banner not available.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Banner Check",
                "status": "PROBLEM",
                "ok": False,
                "details": str(exc),
            }

        ptr_host = self._perform_reverse_dns()
        result: Dict[str, Any] = {
            "title": "SMTP Banner Check",
            "ok": True,
            "status": "OK",
            "banner": self.banner,
            "banner_hostname": self.banner_hostname,
            "reverse_dns_host": ptr_host,
            "details": "Banner hostname matches reverse DNS hostname.",
        }

        if not self.banner_hostname:
            result.update(
                ok=False,
                status="WARNING",
                details="Could not determine banner hostname from greeting.",
            )
            return result

        if not ptr_host:
            result.update(
                ok=False,
                status="WARNING",
                details="Reverse DNS not available; cannot compare with banner hostname.",
            )
            return result

        if self.banner_hostname.rstrip(".").lower() != ptr_host.rstrip(".").lower():
            result.update(
                ok=False,
                status="WARNING",
                details="SMTP banner hostname does not match reverse DNS hostname.",
            )

        return result

    def test_smtp_connect(self) -> Dict[str, Any]:
        """
        Test 2: SMTP Connect.
        Verifies we can establish a TCP connection and read the banner.
        """
        try:
            if not self._connect_if_needed():
                issue = "Unable to connect to SMTP host."
                if self.dns_resolution_error:
                    issue = f"DNS resolution failed: {self.dns_resolution_error}"
                elif self.connection_error:
                    issue = f"Connection error: {self.connection_error}"

                return {
                    "title": "SMTP Connect",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": issue,
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Connect",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        return {
            "title": "SMTP Connect",
            "ok": True,
            "status": "OK",
            "details": "Successfully connected to SMTP server and received banner.",
        }

    def test_smtp_connection_time(self, warning_threshold: float = 5.0) -> Dict[str, Any]:
        """
        Test 3: SMTP Connection Time.
        Uses the measured time during connect().
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Connection Time",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; connection time not available.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Connection Time",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        assert self.connection_time is not None
        result: Dict[str, Any] = {
            "title": "SMTP Connection Time",
            "ok": True,
            "status": "OK",
            "connection_time_seconds": self.connection_time,
            "details": f"Connection time: {self.connection_time:.3f}s.",
        }

        if self.connection_time > warning_threshold:
            result.update(
                ok=False,
                status="WARNING",
                details=f"Slow connection time: {self.connection_time:.3f}s (threshold {warning_threshold:.1f}s).",
            )

        return result

    def test_smtp_dns_resolution(self) -> Dict[str, Any]:
        """
        Test 4: SMTP DNS Resolution.
        Only meaningful when target is a hostname.
        """
        if self._looks_like_ip(self.target):
            return {
                "title": "SMTP DNS Resolution",
                "ok": True,
                "status": "SKIPPED",
                "details": "Target appears to be an IP address; DNS A/AAAA resolution is not applicable.",
            }

        try:
            self._connect_if_needed()
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP DNS Resolution",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        if self.dns_resolution_error is not None:
            return {
                "title": "SMTP DNS Resolution",
                "ok": False,
                "status": "PROBLEM",
                "details": f"DNS resolution failed while connecting: {self.dns_resolution_error}",
            }

        return {
            "title": "SMTP DNS Resolution",
            "ok": True,
            "status": "OK",
            "details": "Hostname resolved successfully when attempting SMTP connection.",
        }

    def test_smtp_open_relay(self) -> Dict[str, Any]:
        """
        Test 5: SMTP Open Relay.

        - Uses configured sender and recipient.
        - Performs MX lookup on sender domain; if no MX, test is refused.
        - Marks 'WARNING' only if RCPT TO for external recipient is accepted.
        - Mode ``"data"``: after an accepted RCPT TO, also sends DATA; a 354 reply
          confirms the server is ready to take the message. The connection is
          then dropped WITHOUT sending any content or the final '.', so nothing
          is relayed (the server discards the incomplete transaction).
        - Measures transaction time (EHLO + MAIL + RCPT [+ DATA]).
        """
        data_aborted = False
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Open Relay",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect to SMTP server; cannot test for open relay.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Open Relay",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        if self.smtp is None:
            return {
                "title": "SMTP Open Relay",
                "ok": False,
                "status": "PROBLEM",
                "details": "SMTP object not available.",
            }

        if not self.open_relay_sender or not self.open_relay_recipient:
            return {
                "title": "SMTP Open Relay",
                "ok": False,
                "status": "SKIPPED",
                "details": "Open relay sender/recipient not configured.",
            }

        if "@" not in self.open_relay_sender:
            return {
                "title": "SMTP Open Relay",
                "ok": False,
                "status": "SKIPPED",
                "details": "Open relay sender address is invalid; cannot perform test.",
            }

        sender_domain = self.open_relay_sender.split("@", 1)[1]
        has_mx = self._domain_has_mx(sender_domain)
        if has_mx is False:
            return {
                "title": "SMTP Open Relay",
                "ok": False,
                "status": "SKIPPED",
                "details": f"Domain {sender_domain} has no MX; refusing open relay test (nullMX-like case).",
            }

        try:
            start = time.time()

            self._ehlo_if_needed()

            self._log("C", f"MAIL FROM:<{self.open_relay_sender}>")
            code_from, msg_from = self.smtp.mail(self.open_relay_sender)
            decoded_from = msg_from.decode(errors="replace") if isinstance(msg_from, (bytes, bytearray)) else str(msg_from)
            self._log("S", f"{code_from} {decoded_from}")

            if code_from >= 400:
                end = time.time()
                self.transaction_time = end - start
                return {
                    "title": "SMTP Open Relay",
                    "ok": False,
                    "status": "SKIPPED",
                    "details": f"MAIL FROM rejected by server ({code_from}); cannot reliably test for open relay.",
                    "mail_from_code": code_from,
                }

            self._log("C", f"RCPT TO:<{self.open_relay_recipient}>")
            code_rcpt, msg_rcpt = self.smtp.rcpt(self.open_relay_recipient)
            decoded_rcpt = msg_rcpt.decode(errors="replace") if isinstance(msg_rcpt, (bytes, bytearray)) else str(msg_rcpt)
            self._log("S", f"{code_rcpt} {decoded_rcpt}")

            is_open_relay = 200 <= code_rcpt < 300

            code_data: Optional[int] = None
            if is_open_relay and self.open_relay_mode == "data":
                self._log("C", "DATA")
                code_data, msg_data = self.smtp.docmd("DATA")
                decoded_data = msg_data.decode(errors="replace") if isinstance(msg_data, (bytes, bytearray)) else str(msg_data)
                self._log("S", f"{code_data} {decoded_data}")
                if code_data == 354:
                    # Abort before any content: drop the connection (no '.', nothing relayed)
                    self._log("I", "Closing connection without sending message content (DATA aborted)")
                    self._drop_connection()
                    data_aborted = True

            end = time.time()
            self.transaction_time = end - start

            if is_open_relay and code_data is not None and code_data != 354:
                status = "OK"
                ok = True
                details = (
                    f"Server accepted RCPT TO for external recipient but refused DATA ({code_data}); "
                    "relay not confirmed."
                )
            elif is_open_relay:
                status = "WARNING"
                ok = False
                if code_data == 354:
                    details = (
                        "Server accepted RCPT TO for external recipient without authentication and "
                        "answered 354 to DATA (ready to take the message): open relay confirmed up to "
                        "DATA. Connection dropped before sending any content."
                    )
                else:
                    details = (
                        "Server accepted RCPT TO for external recipient without authentication; "
                        "may be an open relay."
                    )
            else:
                status = "OK"
                ok = True
                details = "Server did not accept RCPT TO for external recipient; relay access denied."

            result = {
                "title": "SMTP Open Relay",
                "ok": ok,
                "status": status,
                "details": details,
                "mode": self.open_relay_mode,
                "mail_from_code": code_from,
                "rcpt_to_code": code_rcpt,
                "transaction_time_seconds": self.transaction_time,
            }
            if code_data is not None:
                result["data_code"] = code_data
            return result

        except smtplib.SMTPServerDisconnected:
            return {
                "title": "SMTP Open Relay",
                "ok": True,
                "status": "OK",
                "details": (
                    "Server terminated the connection during the relay test. "
                    "This is a common defensive behaviour — the server refused the "
                    "relay attempt by dropping the session rather than responding with "
                    "a 5xx code. No open relay confirmed."
                ),
            }
        finally:
            if self.smtp is not None and not data_aborted:
                try:
                    self.smtp.rset()
                except Exception:
                    pass

    def _drop_connection(self) -> None:
        """Close the socket without QUIT (used to abort a transaction in DATA state).

        The next test reconnects through ``_connect_if_needed()``.
        """
        if self.smtp is None:
            return
        try:
            self.smtp.close()
        except Exception:
            pass
        self.smtp = None

    def test_smtp_reverse_dns_mismatch(self) -> Dict[str, Any]:
        """
        Test 6: SMTP Reverse DNS Mismatch.
        Forward DNS of banner hostname vs server IP.
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Reverse DNS Mismatch",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; cannot evaluate reverse DNS mismatch.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Reverse DNS Mismatch",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        if not self.banner_hostname or not self.peer_ip:
            return {
                "title": "SMTP Reverse DNS Mismatch",
                "ok": False,
                "status": "WARNING",
                "details": "Banner hostname or peer IP not available.",
            }

        # Resolve banner hostname to IPs
        ips = self._resolve_hostname(self.banner_hostname)
        if ips is None:
            return {
                "title": "SMTP Reverse DNS Mismatch",
                "ok": False,
                "status": "PROBLEM",
                "details": f"Failed to resolve banner hostname {self.banner_hostname}",
            }

        match = self.peer_ip in ips
        return {
            "title": "SMTP Reverse DNS Mismatch",
            "ok": match,
            "status": "OK" if match else "WARNING",
            "details": "Forward DNS of banner hostname matches server IP."
            if match
            else "Forward DNS of banner hostname does not include server IP.",
            "banner_hostname": self.banner_hostname,
            "banner_ips": sorted(ips),
            "server_ip": self.peer_ip,
        }

    def test_smtp_valid_hostname(self) -> Dict[str, Any]:
        """
        Test 7: SMTP Valid Hostname.
        Check that the PTR hostname is a syntactically valid DNS name.
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Valid Hostname",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; cannot determine reverse DNS hostname.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Valid Hostname",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        ptr_host = self._perform_reverse_dns()
        if not ptr_host:
            return {
                "title": "SMTP Valid Hostname",
                "ok": False,
                "status": "WARNING",
                "details": "No reverse DNS hostname available for server IP.",
            }

        is_valid = self._is_valid_hostname(ptr_host)
        return {
            "title": "SMTP Valid Hostname",
            "ok": is_valid,
            "status": "OK" if is_valid else "WARNING",
            "reverse_dns_host": ptr_host,
            "details": "Reverse DNS hostname is syntactically valid."
            if is_valid
            else "Reverse DNS hostname is not syntactically valid.",
        }

    def test_smtp_reverse_dns_resolution(self) -> Dict[str, Any]:
        """
        Test 8: SMTP Reverse DNS Resolution.
        Just checks PTR existence.
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Reverse DNS Resolution",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; cannot perform reverse DNS resolution.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Reverse DNS Resolution",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        ptr_host = self._perform_reverse_dns()
        if not ptr_host:
            return {
                "title": "SMTP Reverse DNS Resolution",
                "ok": False,
                "status": "WARNING",
                "details": "No PTR record found for server IP.",
            }

        return {
            "title": "SMTP Reverse DNS Resolution",
            "ok": True,
            "status": "OK",
            "reverse_dns_host": ptr_host,
            "details": "PTR record found for server IP.",
        }

    def test_smtp_server_disconnected(self) -> Dict[str, Any]:
        """
        Test 9: SMTP Server Disconnected.

        Internally issues a NOOP to see if the server is still connected.
        NOOP is *not* logged in transcript (MXToolbox does not show it).
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Server Disconnected",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; cannot test for disconnection.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Server Disconnected",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        if self.smtp is None:
            return {
                "title": "SMTP Server Disconnected",
                "ok": False,
                "status": "PROBLEM",
                "details": "SMTP object not available.",
            }

        try:
            self.smtp.noop()
            return {
                "title": "SMTP Server Disconnected",
                "ok": True,
                "status": "OK",
                "details": "Server remained connected during NOOP check.",
            }
        except smtplib.SMTPServerDisconnected:
            return {
                "title": "SMTP Server Disconnected",
                "ok": False,
                "status": "WARNING",
                "details": "Server disconnected unexpectedly during NOOP.",
            }

    def test_smtp_tls(self) -> Dict[str, Any]:
        """
        Test 10: SMTP TLS.
        Checks whether server advertises STARTTLS.
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP TLS",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; cannot test for TLS support.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP TLS",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        if self.smtp is None:
            return {
                "title": "SMTP TLS",
                "ok": False,
                "status": "PROBLEM",
                "details": "SMTP object not available.",
            }

        self._ehlo_if_needed()
        esmtp_features = getattr(self.smtp, "esmtp_features", {}) or {}
        supports_tls = "starttls" in (name.lower() for name in esmtp_features.keys())

        return {
            "title": "SMTP TLS",
            "ok": supports_tls,
            "status": "OK" if supports_tls else "WARNING",
            "details": "Server advertises STARTTLS support."
            if supports_tls
            else "Server does not advertise STARTTLS support.",
            "esmtp_features": dict(esmtp_features),
        }

    def test_smtp_transaction_time(self, warning_threshold: float = 5.0) -> Dict[str, Any]:
        """
        Test 11: SMTP Transaction Time.

        The transaction time is measured during the Open Relay test
        (EHLO + MAIL + RCPT). This method only *reports* that value and
        does not start a new SMTP transaction to keep the transcript
        as close as possible to MXToolbox.
        """
        if self.transaction_time is None:
            return {
                "title": "SMTP Transaction Time",
                "ok": False,
                "status": "SKIPPED",
                "details": "Transaction time not measured (open relay test may have been skipped or failed early).",
            }

        ok = True
        status = "OK"
        details = f"Transaction time: {self.transaction_time:.3f}s."

        if self.transaction_time > warning_threshold:
            ok = False
            status = "WARNING"
            details = f"Long transaction time: {self.transaction_time:.3f}s (threshold {warning_threshold:.1f}s)."

        return {
            "title": "SMTP Transaction Time",
            "ok": ok,
            "status": status,
            "transaction_time_seconds": self.transaction_time,
            "details": details,
        }

    def test_smtp_reverse_lookup(self) -> Dict[str, Any]:
        """
        Test 12: SMTP Reverse Lookup.

        - PTR exists for server IP.
        - PTR hostname resolves back to the same IP (or one of them).
        """
        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP Reverse Lookup",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; cannot perform reverse lookup.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP Reverse Lookup",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        if not self.peer_ip:
            return {
                "title": "SMTP Reverse Lookup",
                "ok": False,
                "status": "PROBLEM",
                "details": "Server IP not available.",
            }

        ptr_host = self._perform_reverse_dns()
        if not ptr_host:
            return {
                "title": "SMTP Reverse Lookup",
                "ok": False,
                "status": "PROBLEM",
                "details": "No PTR record found for server IP.",
            }

        # Resolve PTR hostname back to IPs
        ips = self._resolve_hostname(ptr_host)
        if ips is None:
            return {
                "title": "SMTP Reverse Lookup",
                "ok": False,
                "status": "PROBLEM",
                "details": f"Forward DNS lookup on PTR hostname failed",
                "reverse_dns_host": ptr_host,
            }

        match = self.peer_ip in ips
        return {
            "title": "SMTP Reverse Lookup",
            "ok": match,
            "status": "OK" if match else "WARNING",
            "reverse_dns_host": ptr_host,
            "forward_ips_from_ptr": sorted(ips),
            "server_ip": self.peer_ip,
            "details": "PTR hostname resolves back to server IP."
            if match
            else "PTR hostname does not resolve back to server IP.",
        }

    def test_smtp_starttls_cert(self) -> Dict[str, Any]:
        """
        Test 13: SMTP STARTTLS Certificate Capture.

        Performs actual STARTTLS negotiation on the existing connection,
        captures the server's DER-encoded certificate (with CERT_NONE so
        self-signed certs are accepted), and stores it in self.tls_cert_der
        for use by DomainChecker's DANE verification.

        This test must run LAST to avoid disrupting prior plain-text tests
        (open relay, NOOP, etc.) with the TLS upgrade.
        """
        import ssl as _ssl

        try:
            if not self._connect_if_needed():
                return {
                    "title": "SMTP STARTTLS Cert",
                    "ok": False,
                    "status": "PROBLEM",
                    "details": "Unable to connect; cannot perform STARTTLS.",
                }
        except SMTPConnectionError as exc:
            return {
                "title": "SMTP STARTTLS Cert",
                "ok": False,
                "status": "PROBLEM",
                "details": str(exc),
            }

        if self.smtp is None:
            return {
                "title": "SMTP STARTTLS Cert",
                "ok": False,
                "status": "PROBLEM",
                "details": "SMTP object not available.",
            }

        self._ehlo_if_needed()
        esmtp_features = getattr(self.smtp, "esmtp_features", {}) or {}
        if "starttls" not in (k.lower() for k in esmtp_features.keys()):
            return {
                "title": "SMTP STARTTLS Cert",
                "ok": False,
                "status": "SKIPPED",
                "details": "Server does not advertise STARTTLS; cannot capture certificate.",
            }

        try:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE

            # smtplib created the SMTP object without a host in its constructor
            # (checker uses smtp.connect() separately for timing), so _host may
            # be None — ssl.wrap_socket requires a server_hostname when the ssl
            # context is built with PROTOCOL_TLS_CLIENT.  Patch it defensively.
            if not getattr(self.smtp, "_host", None):
                self.smtp._host = self.target

            self.smtp.starttls(context=ctx)
            # Re-EHLO required after STARTTLS (RFC 3207 §4.2)
            # Use a direct call — do not reset self.ehlo_done so other
            # helpers remain coherent.
            self.smtp.ehlo()

            cert_der = self.smtp.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
            if cert_der:
                self.tls_cert_der = cert_der
                return {
                    "title": "SMTP STARTTLS Cert",
                    "ok": True,
                    "status": "OK",
                    "details": "STARTTLS succeeded; certificate captured for DANE verification.",
                }
            else:
                return {
                    "title": "SMTP STARTTLS Cert",
                    "ok": False,
                    "status": "WARNING",
                    "details": "STARTTLS succeeded but server returned no certificate.",
                }

        except Exception as exc:
            return {
                "title": "SMTP STARTTLS Cert",
                "ok": False,
                "status": "PROBLEM",
                "details": f"STARTTLS failed: {exc}",
            }

    def test_smtp_tls_cert_check(self) -> Dict[str, Any]:
        """
        Test 14: SMTP TLS Certificate Check.

        Analyses the server TLS certificate:
        - Hostname match: checks SANs (dNSName + IP) with wildcard support,
          falls back to CN. Reports all SANs present in the certificate.
        - Self-signed detection: issuer DN == subject DN AND the certificate
          signature is cryptographically valid against its own public key
          (supports RSA PKCS1v15 and ECDSA; uses verify_directly_issued_by()
          on cryptography >= 42, manual fallback for older versions).
        - Expiry: PROBLEM if already expired or < 14 days remaining;
          WARNING if < 30 days.
        - AIA issuer URL: extracted from the Authority Information Access
          extension; surfaced in error messages to aid chain diagnosis.
        - CA chain: opens one additional STARTTLS connection with strict
          hostname + chain validation using the certifi CA bundle (Mozilla
          root store). Detects incomplete chains, untrusted roots, and
          expired certificates. Raw SSL errors are translated to actionable
          messages (incomplete_chain, self_signed, expired, hostname_mismatch,
          untrusted_ca).

        Reuses self.tls_cert_der if already captured by test_smtp_starttls_cert
        (no extra SMTP connection needed for static analysis).
        CA validation always opens one additional connection.
        """
        import ssl as _ssl
        from datetime import datetime, timezone as _tz

        from cryptography import x509 as _x509

        result: Dict[str, Any] = {
            "title": "SMTP TLS Certificate",
            "ok": False,
            "status": "PROBLEM",
            "details": "",
            "cert_subject": None,
            "cert_issuer": None,
            "cert_not_after": None,
            "cert_days_remaining": None,
            "cert_self_signed": None,
            "cert_hostname_match": None,
            "cert_san_names": [],
            "cert_ca_valid": None,
            "cert_ca_error": None,
        }

        # ---- Obtain cert DER ----
        cert_der = self.tls_cert_der
        if cert_der is None:
            # smtp_starttls_cert may not have run or may have been disabled;
            # check if STARTTLS is at least advertised before trying.
            self._ehlo_if_needed()
            features = getattr(self.smtp, "esmtp_features", {}) or {}
            if "starttls" not in (k.lower() for k in features.keys()):
                result["status"] = "SKIPPED"
                result["details"] = (
                    "STARTTLS not advertised and no certificate pre-captured; "
                    "cannot perform certificate check."
                )
                return result
            try:
                from .dane import fetch_smtp_cert_der as _fetch_cert
                cert_der = _fetch_cert(self.target, port=self.port, timeout=self.timeout, verify=False)
            except Exception as exc:
                result["details"] = f"Cannot retrieve certificate: {exc}"
                return result

        # ---- Parse cert ----
        try:
            cert = _x509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            result["details"] = f"Cannot parse certificate DER: {exc}"
            return result

        # Subject / Issuer (best-effort CN extraction)
        def _cn(name: Any) -> str:
            try:
                return name.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)[0].value
            except (IndexError, Exception):
                return str(name)

        result["cert_subject"] = _cn(cert.subject)
        result["cert_issuer"] = _cn(cert.issuer)

        # Self-signed: issuer == subject AND signature verifiable with own public key.
        # issuer == subject alone is not sufficient (intermediate CAs can share names).
        def _is_self_signed(c: Any) -> bool:
            if c.subject != c.issuer:
                return False
            try:
                # cryptography >= 42 provides a direct method
                c.verify_directly_issued_by(c)
                return True
            except AttributeError:
                pass
            except Exception:
                return False
            # Fallback for cryptography < 42: verify signature manually
            from cryptography.hazmat.primitives import hashes as _hashes
            from cryptography.hazmat.primitives.asymmetric import ec as _ec, rsa as _rsa, padding as _padding
            pub = c.public_key()
            try:
                if isinstance(pub, _rsa.RSAPublicKey):
                    pub.verify(c.signature, c.tbs_certificate_bytes,
                               _padding.PKCS1v15(), c.signature_hash_algorithm)
                elif isinstance(pub, _ec.EllipticCurvePublicKey):
                    pub.verify(c.signature, c.tbs_certificate_bytes,
                               _ec.ECDSA(c.signature_hash_algorithm))
                else:
                    return False
                return True
            except Exception:
                return False

        result["cert_self_signed"] = _is_self_signed(cert)

        # Expiry — handle both cryptography <42 (naive) and >=42 (aware)
        try:
            not_after = cert.not_valid_after_utc  # cryptography >= 42
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=_tz.utc)
        now = datetime.now(_tz.utc)
        days_remaining = (not_after - now).days
        result["cert_not_after"] = not_after.isoformat()
        result["cert_days_remaining"] = days_remaining

        # SANs
        san_names: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            for entry in san_ext.value:
                if isinstance(entry, (_x509.DNSName, _x509.IPAddress)):
                    san_names.append(str(entry.value))
        except _x509.ExtensionNotFound:
            pass
        result["cert_san_names"] = san_names

        # AIA — issuer URL (useful to diagnose missing intermediate)
        issuer_url: Optional[str] = None
        try:
            aia = cert.extensions.get_extension_for_class(_x509.AuthorityInformationAccess)
            for access in aia.value:
                if access.access_method == _x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    issuer_url = access.access_location.value
                    break
        except (_x509.ExtensionNotFound, Exception):
            pass
        result["cert_issuer_url"] = issuer_url

        # Hostname match (SAN first, then CN fallback)
        target_lower = self.target.lower().rstrip(".")

        def _matches(name: str) -> bool:
            name = name.lower().rstrip(".")
            if name.startswith("*."):
                # Wildcard covers one level: *.example.com → mail.example.com
                suffix = name[2:]
                parts = target_lower.split(".")
                return len(parts) >= 2 and ".".join(parts[1:]) == suffix
            return name == target_lower

        if san_names:
            hostname_match = any(_matches(n) for n in san_names)
        else:
            hostname_match = _matches(result["cert_subject"] or "")
        result["cert_hostname_match"] = hostname_match

        # ---- CA chain validation (fresh connection, OS trust-store) ----
        def _translate_ssl_error(exc: Exception) -> tuple[str, str]:
            """
            Return (human_message, error_type) for a SSL verification error.
            error_type: "incomplete_chain" | "self_signed" | "expired" |
                        "hostname_mismatch" | "untrusted_ca" | "unknown"
            """
            msg = str(exc).lower()
            if "unable to get local issuer certificate" in msg or "unable to get issuer cert" in msg:
                hint = f" (fetch from {issuer_url})" if issuer_url else ""
                return (
                    f"Server did not send full certificate chain "
                    f"(missing intermediate CA: {result['cert_issuer']}{hint})",
                    "incomplete_chain",
                )
            if "self signed" in msg or "self-signed" in msg:
                return "Self-signed certificate", "self_signed"
            if "certificate has expired" in msg or "certificate expired" in msg:
                return "Certificate expired (verified by CA layer)", "expired"
            if "hostname mismatch" in msg or "doesn't match" in msg or "does not match" in msg:
                return "Hostname mismatch (detected by SSL layer)", "hostname_mismatch"
            if "certificate verify failed" in msg:
                return f"Certificate not trusted by OS CA store: {str(exc).split(':')[-1].strip()}", "untrusted_ca"
            return str(exc), "unknown"

        try:
            from .dane import fetch_smtp_cert_der as _fetch_cert
            _fetch_cert(self.target, port=self.port, timeout=self.timeout, verify=True)
            result["cert_ca_valid"] = True
            result["cert_ca_error"] = None
            result["cert_ca_error_type"] = None
        except (_ssl.SSLCertVerificationError, _ssl.SSLError) as exc:
            human_msg, err_type = _translate_ssl_error(exc)
            result["cert_ca_valid"] = False
            result["cert_ca_error"] = human_msg
            result["cert_ca_error_type"] = err_type
        except Exception as exc:
            result["cert_ca_valid"] = None
            result["cert_ca_error"] = f"Unable to verify chain: {exc}"
            result["cert_ca_error_type"] = "unknown"

        # ---- Determine status ----
        problems: list[str] = []
        warnings: list[str] = []

        if days_remaining < 0:
            problems.append(f"expired {abs(days_remaining)} day(s) ago")
        elif days_remaining < 14:
            problems.append(f"expires in {days_remaining} day(s)")
        elif days_remaining < 30:
            warnings.append(f"expires in {days_remaining} day(s)")

        if not hostname_match:
            problems.append(f"hostname '{self.target}' not in certificate")

        if result["cert_self_signed"]:
            warnings.append("self-signed certificate")
        elif result["cert_ca_valid"] is False:
            err_type = result.get("cert_ca_error_type", "unknown")
            ca_err = result["cert_ca_error"] or ""
            # Incomplete chain is a server config issue → WARNING
            # Untrusted / unknown CA → WARNING too (could be internal PKI)
            warnings.append(ca_err)

        if problems:
            result["ok"] = False
            result["status"] = "PROBLEM"
            result["details"] = "; ".join(problems)
        elif warnings:
            result["ok"] = False
            result["status"] = "WARNING"
            result["details"] = "; ".join(warnings)
        else:
            result["ok"] = True
            result["status"] = "OK"
            result["details"] = (
                f"Valid CA-signed cert for '{self.target}', "
                f"expires in {days_remaining} day(s)."
            )

        return result

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------
    def _clone(self, target: str) -> "SMTPChecker":
        """Return a fresh SMTPChecker for *target* with the same configuration."""
        return SMTPChecker(
            target,
            port=self.port,
            timeout=self.timeout,
            open_relay_sender=self.open_relay_sender,
            open_relay_recipient=self.open_relay_recipient,
            open_relay_mode=self.open_relay_mode,
            options=dict(self.options),
        )

    def run_all_tests(self) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Run all enabled tests.

        - **Single target** (default): returns a dict with keys ``tests``,
          ``session_transcript``, ``options``.
        - **List of targets**: returns a list of such dicts, one per target,
          scanned sequentially.  Use ``run_all_tests_async()`` for concurrent
          execution.

        Raises:
            SMTPConnectionError: If initial connection to the server fails
                                 (single-target mode only).
        """
        if self._target_list is not None:
            return [self._clone(t).run_all_tests() for t in self._target_list]
        results: Dict[str, Any] = {
            "target": self.target,
            "port": self.port,
            "options": self.options,
            "tests": {},
        }

        # Try to connect first - if this fails, raise exception immediately
        # instead of running all tests with PROBLEM status
        try:
            self._connect_if_needed()
        except SMTPConnectionError:
            self.close()
            raise

        test_methods = {
            "smtp_banner_check": self.test_smtp_banner_check,
            "smtp_connect": self.test_smtp_connect,
            "smtp_connection_time": self.test_smtp_connection_time,
            "smtp_dns_resolution": self.test_smtp_dns_resolution,
            "smtp_open_relay": self.test_smtp_open_relay,
            "smtp_reverse_dns_mismatch": self.test_smtp_reverse_dns_mismatch,
            "smtp_valid_hostname": self.test_smtp_valid_hostname,
            "smtp_reverse_dns_resolution": self.test_smtp_reverse_dns_resolution,
            "smtp_server_disconnected": self.test_smtp_server_disconnected,
            "smtp_tls": self.test_smtp_tls,
            "smtp_transaction_time": self.test_smtp_transaction_time,
            "smtp_reverse_lookup": self.test_smtp_reverse_lookup,
            "smtp_starttls_cert": self.test_smtp_starttls_cert,
            "smtp_tls_cert_check": self.test_smtp_tls_cert_check,
        }

        try:
            for test_name, test_method in test_methods.items():
                if self.options.get(test_name, False):
                    results["tests"][test_name] = test_method()
        finally:
            self.close()

        results["session_transcript"] = "\n".join(self.session_transcript)
        return results

    async def run_all_tests_async(
        self,
        *,
        max_smtp: int = 10,
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Async version of ``run_all_tests()``.

        - **Single target**: runs in a thread pool via ``asyncio.to_thread``
          and returns a dict.
        - **List of targets**: scans all targets concurrently (capped at
          *max_smtp* simultaneous connections) and returns a list of dicts
          in the same order as the input list.

        :param max_smtp: Maximum number of concurrent SMTP connections when
                         scanning a list.  ``0`` means no limit.
        """
        if self._target_list is not None:
            smtp_sem = asyncio.Semaphore(max_smtp) if max_smtp > 0 else None

            async def _guarded(t: str) -> Dict[str, Any]:
                if smtp_sem:
                    async with smtp_sem:
                        return await asyncio.to_thread(self._clone(t).run_all_tests)
                return await asyncio.to_thread(self._clone(t).run_all_tests)

            return list(await asyncio.gather(*[_guarded(t) for t in self._target_list]))
        return await asyncio.to_thread(self.run_all_tests)
