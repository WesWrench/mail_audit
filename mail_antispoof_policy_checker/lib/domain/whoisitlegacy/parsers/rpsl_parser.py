"""
RPSL (Routing Policy Specification Language) parser for RIPE, AfriNIC, APNIC, LACNIC.

This parser handles the RPSL format used by most RIRs (except ARIN).
It converts raw WHOIS responses into structured JSON format compatible with RIPE Stat API.

RPSL format example:
    inetnum:        80.124.169.0 - 80.124.169.7
    netname:        DELUBAC
    descr:          BANQUE DELUBAC & CIE
    country:        FR
    admin-c:        DR5299-RIPE
    tech-c:         DR5299-RIPE
    status:         ASSIGNED PA
    mnt-by:         DELUBAC-MNT
    created:        2013-09-25T13:00:41Z
    last-modified:  2013-09-25T13:00:41Z
    source:         RIPE
"""

import re
from typing import Dict, List, Any, Optional
from ..exceptions import WhoisParseError


class RPSLParser:
    """Parser for RPSL-formatted WHOIS responses."""

    # RPSL object types
    RPSL_OBJECT_TYPES = {
        "inetnum", "inet6num", "route", "route6",
        "aut-num", "as-block", "as-set",
        "person", "role", "organisation",
        "mntner", "irt",
        "domain", "key-cert",
        "poem", "poetic-form",
        "route-set", "rtr-set", "filter-set", "peering-set"
    }

    # Primary key field for each object type
    PRIMARY_KEYS = {
        "inetnum": "inetnum",
        "inet6num": "inet6num",
        "route": "route",
        "route6": "route6",
        "aut-num": "aut-num",
        "as-block": "as-block",
        "as-set": "as-set",
        "person": "nic-hdl",
        "role": "nic-hdl",
        "organisation": "organisation",
        "mntner": "mntner",
        "irt": "irt",
        "domain": "domain",
        "key-cert": "key-cert",
        "poem": "poem",
        "poetic-form": "poetic-form",
        "route-set": "route-set",
        "rtr-set": "rtr-set",
        "filter-set": "filter-set",
        "peering-set": "peering-set"
    }

    @staticmethod
    def _is_comment(line: str) -> bool:
        """Check if line is a comment (starts with % or #)."""
        stripped = line.strip()
        return stripped.startswith("%") or stripped.startswith("#") or not stripped

    @staticmethod
    def _parse_field_line(line: str) -> Optional[tuple[str, str]]:
        """
        Parse a single RPSL field line.

        Args:
            line: Raw line from WHOIS response

        Returns:
            Tuple of (field_name, field_value) or None if not a valid field
        """
        # Check for field pattern: "field-name:  value"
        match = re.match(r'^([a-zA-Z0-9\-]+):\s*(.*)$', line)
        if match:
            field_name = match.group(1).lower()
            field_value = match.group(2).strip()
            return field_name, field_value
        return None

    @classmethod
    def _parse_single_object(cls, lines: List[str]) -> Dict[str, Any]:
        """
        Parse a single RPSL object from lines.

        Args:
            lines: List of lines for one object

        Returns:
            Dictionary with parsed fields
        """
        obj = {}
        current_field = None
        current_value = []

        for line in lines:
            # Skip comments and empty lines
            if cls._is_comment(line):
                continue

            # Check for continuation line (starts with whitespace)
            if line and line[0] in (' ', '\t'):
                # Continuation of previous field
                if current_field:
                    current_value.append(line.strip())
                continue

            # Parse field line
            parsed = cls._parse_field_line(line)
            if parsed:
                # Save previous field if exists
                if current_field:
                    value = ' '.join(current_value)
                    if current_field in obj:
                        # Convert to list if multiple values
                        if isinstance(obj[current_field], list):
                            obj[current_field].append(value)
                        else:
                            obj[current_field] = [obj[current_field], value]
                    else:
                        obj[current_field] = value

                # Start new field
                current_field, first_value = parsed
                current_value = [first_value] if first_value else []

        # Save last field
        if current_field:
            value = ' '.join(current_value)
            if current_field in obj:
                if isinstance(obj[current_field], list):
                    obj[current_field].append(value)
                else:
                    obj[current_field] = [obj[current_field], value]
            else:
                obj[current_field] = value

        return obj

    @classmethod
    def _detect_object_type(cls, obj: Dict[str, Any]) -> Optional[str]:
        """
        Detect RPSL object type from parsed fields.

        Args:
            obj: Parsed object dictionary

        Returns:
            Object type string or None
        """
        # Check for primary keys - but also check for characteristic fields
        # First, check for primary keys that are always unique
        if "inetnum" in obj:
            return "inetnum"
        if "inet6num" in obj:
            return "inet6num"
        if "route" in obj:
            return "route"
        if "route6" in obj:
            return "route6"
        if "aut-num" in obj:
            return "aut-num"
        if "as-block" in obj:
            return "as-block"
        if "as-set" in obj:
            return "as-set"
        if "organisation" in obj:
            return "organisation"
        if "mntner" in obj:
            return "mntner"
        if "irt" in obj:
            return "irt"
        if "domain" in obj:
            return "domain"
        if "key-cert" in obj:
            return "key-cert"
        if "poem" in obj:
            return "poem"
        if "poetic-form" in obj:
            return "poetic-form"
        if "route-set" in obj:
            return "route-set"
        if "rtr-set" in obj:
            return "rtr-set"
        if "filter-set" in obj:
            return "filter-set"
        if "peering-set" in obj:
            return "peering-set"

        # For person/role, check nic-hdl + person or role field
        if "nic-hdl" in obj:
            if "person" in obj:
                return "person"
            if "role" in obj:
                return "role"

        return None

    @classmethod
    def _normalize_field_values(cls, obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize field values (convert single-item lists, ensure arrays for multi-value fields).

        Args:
            obj: Parsed object

        Returns:
            Normalized object
        """
        # Fields that should always be arrays
        ARRAY_FIELDS = {
            "descr", "remarks", "notify", "abuse-mailbox",
            "address", "phone", "fax-no", "e-mail",
            "admin-c", "tech-c", "zone-c", "abuse-c",
            "mnt-by", "mnt-ref", "mnt-routes", "mnt-domains", "mnt-lower",
            "org", "members", "mp-members",
            "import", "export", "default", "mp-import", "mp-export", "mp-default"
        }

        result = {}
        for key, value in obj.items():
            if key in ARRAY_FIELDS:
                # Ensure it's a list
                if isinstance(value, list):
                    result[key] = value
                else:
                    result[key] = [value] if value else []
            else:
                # Keep single values as strings
                if isinstance(value, list) and len(value) == 1:
                    result[key] = value[0]
                else:
                    result[key] = value

        return result

    @classmethod
    def parse(cls, whois_response: str) -> Dict[str, Any]:
        """
        Parse RPSL WHOIS response into structured JSON format.

        Args:
            whois_response: Raw WHOIS response text

        Returns:
            Dictionary with structure:
            {
                "objects": [
                    {
                        "objectType": "inetnum",
                        "inetnum": "80.124.169.0 - 80.124.169.7",
                        "netname": "DELUBAC",
                        ...
                    },
                    ...
                ]
            }

        Raises:
            WhoisParseError: If parsing fails
        """
        try:
            lines = whois_response.split('\n')

            # Split into individual objects (separated by blank lines)
            objects = []
            current_object_lines = []

            for line in lines:
                if not line.strip():
                    # Blank line - end of object
                    if current_object_lines:
                        obj = cls._parse_single_object(current_object_lines)
                        if obj:  # Only add non-empty objects
                            objects.append(obj)
                        current_object_lines = []
                else:
                    current_object_lines.append(line)

            # Handle last object if no trailing blank line
            if current_object_lines:
                obj = cls._parse_single_object(current_object_lines)
                if obj:
                    objects.append(obj)

            # Add object type and normalize
            result_objects = []
            for obj in objects:
                obj_type = cls._detect_object_type(obj)
                if obj_type:
                    normalized = cls._normalize_field_values(obj)
                    normalized["objectType"] = obj_type
                    result_objects.append(normalized)

            return {
                "objects": result_objects
            }

        except Exception as e:
            raise WhoisParseError(f"Failed to parse RPSL response: {e}")

    @classmethod
    def parse_single_object(cls, whois_response: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single RPSL object (convenience method).

        Args:
            whois_response: Raw WHOIS response

        Returns:
            Single object dictionary or None if no objects found
        """
        result = cls.parse(whois_response)
        objects = result.get("objects", [])
        return objects[0] if objects else None
