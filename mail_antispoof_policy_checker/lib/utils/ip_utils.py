"""IP address and range utilities"""

import ipaddress
from typing import Union, Optional, Tuple, Dict


class IPUtils:
    """Utilities for IP address and range operations"""

    @staticmethod
    def is_ip_in_range(ip: str, ip_range: str) -> bool:
        """
        Check if an IP address is within a given IP range.

        Args:
            ip: IP address to check
            ip_range: IP range in CIDR notation (e.g., '192.168.1.0/24')

        Returns:
            True if the IP is within the range, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            network_obj = ipaddress.ip_network(ip_range, strict=False)
            return ip_obj in network_obj
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_range_in_range(inner_range: str, outer_range: str) -> bool:
        """
        Check if one IP range is a subnet of another IP range.

        Args:
            inner_range: Inner IP range in CIDR notation
            outer_range: Outer IP range in CIDR notation

        Returns:
            True if inner_range is a subnet of outer_range, False otherwise
        """
        try:
            inner_network = ipaddress.ip_network(inner_range, strict=False)
            outer_network = ipaddress.ip_network(outer_range, strict=False)
            return inner_network.subnet_of(outer_network)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def get_first_ip_in_range(ip_range: str) -> Optional[str]:
        """
        Get the first IP address in a given IP range.

        Args:
            ip_range: IP range in CIDR notation

        Returns:
            First IP address in the range as a string, or None if invalid
        """
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return str(next(network.hosts())) if network.num_addresses > 2 else str(network.network_address)
        except (ValueError, TypeError, StopIteration):
            try:
                # Try returning network address if it's a single IP or /31 or /32
                network = ipaddress.ip_network(ip_range, strict=False)
                return str(network.network_address)
            except Exception:
                return None

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Check if a string is a valid IP address.

        Args:
            ip: String to check

        Returns:
            True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_ip_range(ip_range: str) -> bool:
        """
        Check if a string is a valid IP range in CIDR notation.

        Args:
            ip_range: String to check

        Returns:
            True if valid IP range, False otherwise
        """
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def normalize_ip_range(ip_range: str) -> Optional[str]:
        """
        Normalize an IP range to CIDR notation.

        Args:
            ip_range: IP range to normalize

        Returns:
            Normalized IP range or None if invalid
        """
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return str(network)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def get_range_overlap(range1: str, range2: str) -> Optional[Dict[str, str]]:
        """
        Calculate the overlap between two IP ranges.

        Args:
            range1: First IP range in CIDR notation
            range2: Second IP range in CIDR notation

        Returns:
            Dict with 'ip_start', 'ip_end', 'count' if overlap exists, None otherwise

        Example:
            >>> get_range_overlap('192.168.1.0/24', '192.168.0.0/23')
            {'ip_start': '192.168.1.0', 'ip_end': '192.168.1.255', 'count': 256}
        """
        try:
            net1 = ipaddress.ip_network(range1, strict=False)
            net2 = ipaddress.ip_network(range2, strict=False)

            # Check if ranges overlap
            if not net1.overlaps(net2):
                return None

            # Calculate the intersection
            # Get the maximum starting address
            start_ip = max(net1.network_address, net2.network_address)
            # Get the minimum ending address
            end_ip = min(net1.broadcast_address, net2.broadcast_address)

            # Count IPs in overlap
            count = int(end_ip) - int(start_ip) + 1

            return {
                'ip_start': str(start_ip),
                'ip_end': str(end_ip),
                'count': count
            }
        except (ValueError, TypeError):
            return None

    @staticmethod
    def ranges_overlap(range1: str, range2: str) -> bool:
        """
        Check if two IP ranges overlap.

        Args:
            range1: First IP range in CIDR notation
            range2: Second IP range in CIDR notation

        Returns:
            True if ranges overlap, False otherwise
        """
        try:
            net1 = ipaddress.ip_network(range1, strict=False)
            net2 = ipaddress.ip_network(range2, strict=False)
            return net1.overlaps(net2)
        except (ValueError, TypeError):
            return False
