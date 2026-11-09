"""
ARIN Summary/List format parser.

When querying an IP directly, ARIN returns a summary format like:
    Cogent Communications, LLC COGENT-154-41-16 (NET-154-41-0-0-1) 154.41.0.0 - 154.41.255.255
    GIE SIHM NET-154-41-69-0-1 (NET-154-41-69-0-1) 154.41.69.0 - 154.41.69.255

This parser extracts the handles and network information from this format.
"""

import re
from typing import List, Dict, Any, Optional


class ARINSummaryParser:
    """Parser for ARIN summary/list format."""

    # Pattern for summary line:
    # Name HANDLE (HANDLE) range1 - range2
    SUMMARY_PATTERN = re.compile(
        r'^(.+?)\s+'  # Name (greedy, everything before the handle)
        r'([A-Z0-9\-]+)\s+'  # First handle (short form)
        r'\(([A-Z0-9\-]+)\)\s+'  # Second handle in parentheses (full NET- form)
        r'([\d\.\:]+)\s+-\s+'  # Start IP
        r'([\d\.\:]+)'  # End IP
    )

    @classmethod
    def is_summary_format(cls, response: str) -> bool:
        """
        Check if response is in summary/list format.

        Args:
            response: WHOIS response text

        Returns:
            True if summary format detected
        """
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Check if it matches summary pattern
                if cls.SUMMARY_PATTERN.match(line):
                    return True
        return False

    @classmethod
    def parse(cls, response: str) -> Dict[str, Any]:
        """
        Parse ARIN summary format into structured data.

        Args:
            response: ARIN summary response

        Returns:
            Dictionary with list of network summaries:
            {
                "format": "summary",
                "networks": [
                    {
                        "name": "GIE SIHM",
                        "handle": "NET-154-41-69-0-1",
                        "netRange": "154.41.69.0 - 154.41.69.255"
                    },
                    ...
                ]
            }
        """
        networks = []
        lines = response.split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            match = cls.SUMMARY_PATTERN.match(line)
            if match:
                name = match.group(1).strip()
                short_handle = match.group(2).strip()
                full_handle = match.group(3).strip()
                start_ip = match.group(4).strip()
                end_ip = match.group(5).strip()

                networks.append({
                    "name": name,
                    "shortHandle": short_handle,
                    "handle": full_handle,  # Use the NET-xxx form
                    "netRange": f"{start_ip} - {end_ip}",
                    "objectType": "net"
                })

        return {
            "format": "summary",
            "networks": networks
        }

    @classmethod
    def get_most_specific_handle(cls, response: str) -> Optional[str]:
        """
        Get the handle of the most specific network from summary.

        The most specific network is usually the last one in the list.

        Args:
            response: ARIN summary response

        Returns:
            Handle of most specific network, or None
        """
        result = cls.parse(response)
        networks = result.get("networks", [])

        if networks:
            # Return last network (most specific)
            return networks[-1]["handle"]

        return None
