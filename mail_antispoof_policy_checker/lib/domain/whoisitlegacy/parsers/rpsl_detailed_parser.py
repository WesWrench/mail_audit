"""
RPSL Detailed parser - Returns RIPE Stat API compatible format.

Converts RPSL WHOIS response into {"records": [[{...}], [{...}]]} format
like RIPE Stat API.
"""

import re
from typing import List, Dict, Any, Optional


class RPSLDetailedParser:
    """Parser that returns RPSL data in RIPE Stat API format."""

    # RPSL object start fields (primary keys)
    OBJECT_START_FIELDS = [
        "inetnum",
        "inet6num",
        "route",
        "route6",
        "aut-num",
        "as-block",
        "as-set",
        "person",
        "role",
        "organisation",
        "mntner",
        "irt",
        "domain",
        "key-cert",
        "poem",
        "poetic-form",
        "route-set",
        "rtr-set",
        "filter-set",
        "peering-set"
    ]

    @staticmethod
    def _is_comment(line: str) -> bool:
        """Check if line is a comment."""
        stripped = line.strip()
        return stripped.startswith("%") or stripped.startswith("#") or not stripped

    @staticmethod
    def _parse_field_line(line: str) -> Optional[tuple[str, str]]:
        """Parse a single RPSL field line."""
        match = re.match(r'^([a-zA-Z0-9\-]+):\s*(.*)$', line)
        if match:
            field_name = match.group(1).lower()
            field_value = match.group(2).strip()
            return field_name, field_value
        return None

    @classmethod
    def _extract_all_fields(cls, response: str) -> List[Dict[str, Any]]:
        """
        Extract all field key-value pairs from RPSL response.

        Returns list of {"key": "...", "value": "...", "details_link": null} dictionaries.
        """
        lines = response.split('\n')
        fields = []
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
                    if value:  # Only add non-empty values
                        fields.append({
                            "key": current_field,
                            "value": value,
                            "details_link": None
                        })

                # Start new field
                current_field, first_value = parsed
                current_value = [first_value] if first_value else []

        # Save last field
        if current_field:
            value = ' '.join(current_value)
            if value:
                fields.append({
                    "key": current_field,
                    "value": value,
                    "details_link": None
                })

        return fields

    @classmethod
    def _group_into_objects(cls, fields: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """
        Group fields into separate objects.

        An object starts when we encounter an object start field.
        """
        objects = []
        current_object = []

        for field in fields:
            key = field["key"]

            # Check if this field starts a new object
            if key in cls.OBJECT_START_FIELDS:
                # Save previous object if it exists
                if current_object:
                    objects.append(current_object)

                # Start new object
                current_object = [field]
            else:
                # Continue current object
                current_object.append(field)

        # Save last object
        if current_object:
            objects.append(current_object)

        return objects

    @classmethod
    def _detect_object_type(cls, fields: List[Dict[str, Any]]) -> str:
        """
        Detect object type from fields.

        Args:
            fields: List of field dictionaries

        Returns:
            Object type string (matches RPSL object types)
        """
        if not fields:
            return "unknown"

        first_key = fields[0]["key"]

        # RPSL object types are determined by their primary key
        # The primary key IS the object type
        if first_key in cls.OBJECT_START_FIELDS:
            return first_key

        return "unknown"

    @classmethod
    def _fields_to_dict(cls, fields: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Convert list of field dictionaries to a single dictionary.

        Args:
            fields: List of {"key": "...", "value": "...", "details_link": ...}

        Returns:
            Dictionary with keys as field names and values as field values
        """
        result = {}
        for field in fields:
            key = field["key"]
            value = field["value"]

            # Handle multiple values for same key (e.g., multiple "remarks" fields)
            if key in result:
                # Convert to list if not already
                if not isinstance(result[key], list):
                    result[key] = [result[key]]
                result[key].append(value)
            else:
                result[key] = value

        return result

    @classmethod
    def parse(cls, whois_response: str) -> Dict[str, Any]:
        """
        Parse RPSL WHOIS response into dictionary-based structure.

        Args:
            whois_response: Raw RPSL WHOIS response

        Returns:
            Dictionary with structure:
            {
                "records": [
                    {
                        "ObjectType": "inetnum",
                        "inetnum": "...",
                        "netname": "...",
                        "source": "RIPE",
                        "Handle": "..."
                    },
                    {
                        "ObjectType": "person",
                        "person": "...",
                        "address": ["...", "..."],
                        "source": "RIPE",
                        "Handle": "..."
                    },
                    ...
                ]
            }
        """
        # Extract all fields
        all_fields = cls._extract_all_fields(whois_response)

        # Group into objects
        objects = cls._group_into_objects(all_fields)

        # Convert to dictionary format with object_type
        records = []
        for obj in objects:
            # Convert fields list to dictionary
            obj_dict = cls._fields_to_dict(obj)

            # Add object type (use capital letters to match ARIN format)
            obj_type = cls._detect_object_type(obj)
            obj_dict["ObjectType"] = obj_type

            # Normalize handle field for person/role objects (use capital letters)
            if obj_type in ["person", "role"] and "nic-hdl" in obj_dict:
                obj_dict["Handle"] = obj_dict["nic-hdl"]

            # For organisation objects, use "organisation" field as handle
            if obj_type == "organisation" and "organisation" in obj_dict:
                obj_dict["Handle"] = obj_dict["organisation"]

            # For mntner objects, use "mntner" field as handle
            if obj_type == "mntner" and "mntner" in obj_dict:
                obj_dict["Handle"] = obj_dict["mntner"]

            records.append(obj_dict)

        return {
            "records": records
        }
