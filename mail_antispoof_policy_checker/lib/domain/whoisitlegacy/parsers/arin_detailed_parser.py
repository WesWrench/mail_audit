"""
ARIN Detailed parser - Segments WHOIS response into multiple objects.

ARIN WHOIS responses contain multiple sections (networks, organizations, POCs).
This parser segments them into separate objects like RIPE Stat API does.

Example ARIN response structure:
    - Customer section (CustName, Address, City, etc.)
    - Network sections (NetRange, NetHandle, etc.)
    - Organization sections (OrgName, OrgId, etc.)
    - POC sections (OrgAbuseHandle, OrgTechHandle, etc.)
    - Other sections (ReferralServer, etc.)
"""

import re
from typing import List, Dict, Any, Optional


class ARINDetailedParser:
    """Parser that segments ARIN WHOIS into multiple objects like RIPE Stat API."""

    # Signature fields that start a new object (in priority order)
    # Only the FIRST occurrence of these starts a new object
    OBJECT_START_FIELDS = [
        "CustName",       # Customer object
        "ASNumber",       # Autonomous System object (ASN queries)
        "NetRange",       # Network object
        "OrgName",        # Organization object
        "OrgAbuseHandle", # POC Abuse object
        "OrgTechHandle",  # POC Tech object
        "OrgNOCHandle",   # POC NOC object
        "ReferralServer", # Referral object
    ]

    @staticmethod
    def _is_comment(line: str) -> bool:
        """Check if line is a comment."""
        stripped = line.strip()
        return stripped.startswith("#") or not stripped

    @staticmethod
    def _parse_field_line(line: str) -> Optional[tuple[str, str]]:
        """Parse a single field line."""
        match = re.match(r'^([a-zA-Z0-9\-]+):\s*(.*)$', line)
        if match:
            field_name = match.group(1)
            field_value = match.group(2).strip()
            return field_name, field_value
        return None

    @classmethod
    def _extract_all_fields(cls, response: str) -> List[Dict[str, Any]]:
        """
        Extract all field key-value pairs from WHOIS response.

        Returns list of {"key": "...", "value": "..."} dictionaries.
        """
        lines = response.split('\n')
        fields = []

        for line in lines:
            if cls._is_comment(line):
                continue

            parsed = cls._parse_field_line(line)
            if parsed:
                key, value = parsed
                if value:  # Only add non-empty values
                    fields.append({"key": key, "value": value, "details_link": None})

        return fields

    @classmethod
    def _group_into_objects(cls, fields: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """
        Group fields into separate objects.

        An object starts when we encounter a start field.
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
                # Continue current object or create first object
                current_object.append(field)

        # Save last object
        if current_object:
            objects.append(current_object)

        return objects

    @classmethod
    def _deduplicate_objects(cls, objects: List[List[Dict[str, Any]]]) -> List[List[Dict[str, Any]]]:
        """
        Remove duplicate objects.

        ARIN sometimes repeats the same contact multiple times.
        """
        seen = set()
        unique_objects = []

        for obj in objects:
            # Create a signature for this object
            signature_parts = []
            for field in obj:
                signature_parts.append(f"{field['key']}:{field['value']}")
            signature = "|".join(sorted(signature_parts))

            if signature not in seen:
                seen.add(signature)
                unique_objects.append(obj)

        return unique_objects

    @classmethod
    def _detect_object_type(cls, fields: List[Dict[str, Any]]) -> str:
        """
        Detect object type from fields.

        Args:
            fields: List of field dictionaries

        Returns:
            Object type string
        """
        if not fields:
            return "unknown"

        first_key = fields[0]["key"]

        # Map start field to object type
        type_mapping = {
            "NetRange": "network",
            "CustName": "customer",
            "OrgName": "organization",
            "OrgAbuseHandle": "poc",
            "OrgTechHandle": "poc",
            "OrgNOCHandle": "poc",
            "ReferralServer": "referral",
            "ASNumber": "autnum",
            "Name": "poc",  # Direct POC query starts with Name
            "Handle": "poc",  # Or Handle
        }

        return type_mapping.get(first_key, "unknown")

    @classmethod
    def _detect_poc_type(cls, fields: List[Dict[str, Any]]) -> Optional[str]:
        """
        Detect POC type (abuse, technical, noc) from fields.

        Args:
            fields: List of field dictionaries

        Returns:
            POC type string or None
        """
        if not fields:
            return None

        first_key = fields[0]["key"]

        poc_type_mapping = {
            "OrgAbuseHandle": "abuse",
            "OrgTechHandle": "technical",
            "OrgNOCHandle": "noc",
        }

        return poc_type_mapping.get(first_key)

    @classmethod
    def _extract_handle_from_ref(cls, ref: str) -> Optional[str]:
        """
        Extract handle from ARIN Ref URL.

        Args:
            ref: URL like "https://rdap.arin.net/registry/entity/C07925304"

        Returns:
            Handle (e.g., "C07925304") or None
        """
        if not ref:
            return None

        # Extract last segment from URL
        parts = ref.rstrip('/').split('/')
        if parts:
            return parts[-1]

        return None

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

            # Handle multiple values for same key (e.g., multiple "address" fields)
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
        Parse ARIN WHOIS response into dictionary-based structure.

        Args:
            whois_response: Raw ARIN WHOIS response

        Returns:
            Dictionary with structure:
            {
                "records": [
                    {
                        "object_type": "network",
                        "NetRange": "...",
                        "CIDR": "...",
                        "source": "ARIN"
                    },
                    {
                        "object_type": "customer",
                        "CustName": "...",
                        "Address": "...",
                        "source": "ARIN"
                    },
                    ...
                ]
            }
        """
        # Extract all fields
        all_fields = cls._extract_all_fields(whois_response)

        # Group into objects
        objects = cls._group_into_objects(all_fields)

        # Deduplicate
        unique_objects = cls._deduplicate_objects(objects)

        # Convert to dictionary format with object_type
        records = []
        for obj in unique_objects:
            # Convert fields list to dictionary
            obj_dict = cls._fields_to_dict(obj)

            # Detect object type
            obj_type = cls._detect_object_type(obj)
            obj_dict["ObjectType"] = obj_type

            # Normalize POC fields
            if obj_type == "poc":
                # Detect POC type (abuse, technical, noc)
                poc_type = cls._detect_poc_type(obj)
                if poc_type:
                    obj_dict["PocType"] = poc_type

                # Normalize POC fields to match direct POC query format (with capital letters)
                field_mapping = {
                    "OrgAbuseHandle": "Handle",
                    "OrgTechHandle": "Handle",
                    "OrgNOCHandle": "Handle",
                    "OrgAbuseName": "Name",
                    "OrgTechName": "Name",
                    "OrgNOCName": "Name",
                    "OrgAbusePhone": "Phone",
                    "OrgTechPhone": "Phone",
                    "OrgNOCPhone": "Phone",
                    "OrgAbuseEmail": "Email",
                    "OrgTechEmail": "Email",
                    "OrgNOCEmail": "Email",
                    "OrgAbuseRef": "Ref",
                    "OrgTechRef": "Ref",
                    "OrgNOCRef": "Ref",
                }

                # Apply normalization and remove original fields
                for orig_key, norm_key in field_mapping.items():
                    if orig_key in obj_dict:
                        obj_dict[norm_key] = obj_dict[orig_key]
                        del obj_dict[orig_key]  # Remove original field

            # Extract Handle from Ref URL for all objects that don't have Handle yet
            if "Ref" in obj_dict and "Handle" not in obj_dict:
                handle = cls._extract_handle_from_ref(obj_dict["Ref"])
                if handle:
                    obj_dict["Handle"] = handle

            # Add Source (with capital letter to match ARIN format)
            obj_dict["Source"] = "ARIN"

            records.append(obj_dict)

        return {
            "records": records
        }
