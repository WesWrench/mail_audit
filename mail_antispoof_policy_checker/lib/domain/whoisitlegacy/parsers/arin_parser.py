"""
ARIN WHOIS parser.

ARIN uses a different format than RPSL. Fields are colon-separated key-value pairs.
This parser handles ARIN-specific object types: POC, Network, Organization, ASN, Customer.

ARIN format example:
    NetRange:       74.125.0.0 - 74.125.255.255
    CIDR:           74.125.0.0/16
    NetName:        GOOGLE
    NetHandle:      NET-74-125-0-0-1
    Parent:         NET74 (NET-74-0-0-0-0)
    NetType:        Direct Allocation
    Organization:   Google LLC (GOGL)
    RegDate:        2007-03-13
    Updated:        2012-02-24
    Ref:            https://whois.arin.net/rest/net/NET-74-125-0-0-1
"""

import re
from typing import Dict, List, Any, Optional
from ..exceptions import WhoisParseError


class ARINParser:
    """Parser for ARIN-formatted WHOIS responses."""

    # ARIN object type detection patterns
    OBJECT_TYPE_PATTERNS = {
        "net": [
            ("NetRange:", "netRange"),
            ("NetHandle:", "handle"),
            ("NetName:", "name")
        ],
        "org": [
            ("OrgName:", "name"),
            ("OrgId:", "handle"),
            ("Organization:", None)  # Can appear in both
        ],
        "poc": [
            ("POCHandle:", "handle"),
            ("Name:", "name"),
            ("Company:", "company")
        ],
        "asn": [
            ("ASNumber:", "number"),
            ("ASHandle:", "handle"),
            ("ASName:", "name")
        ],
        "customer": [
            ("CustName:", "name"),
            ("Customer:", None)
        ]
    }

    # Field mappings for each object type
    FIELD_MAPPINGS = {
        "net": {
            "NetRange": "netRange",
            "CIDR": "cidr",
            "NetName": "name",
            "NetHandle": "handle",
            "Parent": "parent",
            "NetType": "netType",
            "Organization": "organization",
            "Customer": "customer",
            "RegDate": "registrationDate",
            "Updated": "lastUpdated",
            "Ref": "restfulLink",
            "Comment": "comments",
            "OrgTechHandle": "orgTechHandle",
            "OrgTechName": "orgTechName",
            "OrgTechPhone": "orgTechPhone",
            "OrgTechEmail": "orgTechEmail",
            "OrgTechRef": "orgTechRef",
            "OrgAbuseHandle": "orgAbuseHandle",
            "OrgAbuseName": "orgAbuseName",
            "OrgAbusePhone": "orgAbusePhone",
            "OrgAbuseEmail": "orgAbuseEmail",
            "OrgAbuseRef": "orgAbuseRef",
            "OrgNOCHandle": "orgNOCHandle",
            "OrgNOCName": "orgNOCName",
            "OrgNOCPhone": "orgNOCPhone",
            "OrgNOCEmail": "orgNOCEmail",
            "OrgNOCRef": "orgNOCRef",
            "RTechHandle": "rTechHandle",
            "RTechName": "rTechName",
            "RTechPhone": "rTechPhone",
            "RTechEmail": "rTechEmail",
            "RTechRef": "rTechRef",
            "RAbuseHandle": "rAbuseHandle",
            "RAbuseName": "rAbuseName",
            "RAbusePhone": "rAbusePhone",
            "RAbuseEmail": "rAbuseEmail",
            "RAbuseRef": "rAbuseRef",
            "RNOCHandle": "rNOCHandle",
            "RNOCName": "rNOCName",
            "RNOCPhone": "rNOCPhone",
            "RNOCEmail": "rNOCEmail",
            "RNOCRef": "rNOCRef"
        },
        "org": {
            "OrgName": "name",
            "OrgId": "handle",
            "Address": "street",
            "City": "city",
            "StateProv": "state",
            "PostalCode": "postalCode",
            "Country": "country",
            "RegDate": "registrationDate",
            "Updated": "lastUpdated",
            "Ref": "restfulLink",
            "Comment": "comments",
            "OrgTechHandle": "orgTechHandle",
            "OrgTechName": "orgTechName",
            "OrgTechPhone": "orgTechPhone",
            "OrgTechEmail": "orgTechEmail",
            "OrgTechRef": "orgTechRef",
            "OrgAbuseHandle": "orgAbuseHandle",
            "OrgAbuseName": "orgAbuseName",
            "OrgAbusePhone": "orgAbusePhone",
            "OrgAbuseEmail": "orgAbuseEmail",
            "OrgAbuseRef": "orgAbuseRef",
            "OrgNOCHandle": "orgNOCHandle",
            "OrgNOCName": "orgNOCName",
            "OrgNOCPhone": "orgNOCPhone",
            "OrgNOCEmail": "orgNOCEmail",
            "OrgNOCRef": "orgNOCRef"
        },
        "poc": {
            "POCHandle": "handle",
            "Name": "name",
            "Company": "company",
            "Address": "street",
            "City": "city",
            "StateProv": "state",
            "PostalCode": "postalCode",
            "Country": "country",
            "RegDate": "registrationDate",
            "Updated": "lastUpdated",
            "Ref": "restfulLink",
            "Comment": "comments",
            "OfficePhone": "phones",
            "MobilePhone": "phones",
            "FaxPhone": "phones",
            "Email": "emails"
        },
        "asn": {
            "ASNumber": "number",
            "ASName": "name",
            "ASHandle": "handle",
            "OrgId": "organization",
            "RegDate": "registrationDate",
            "Updated": "lastUpdated",
            "Ref": "restfulLink",
            "Comment": "comments",
            "OrgTechHandle": "orgTechHandle",
            "OrgTechName": "orgTechName",
            "OrgTechPhone": "orgTechPhone",
            "OrgTechEmail": "orgTechEmail",
            "OrgAbuseHandle": "orgAbuseHandle",
            "OrgAbuseName": "orgAbuseName",
            "OrgAbusePhone": "orgAbusePhone",
            "OrgAbuseEmail": "orgAbuseEmail",
            "OrgNOCHandle": "orgNOCHandle",
            "OrgNOCName": "orgNOCName",
            "OrgNOCPhone": "orgNOCPhone",
            "OrgNOCEmail": "orgNOCEmail"
        },
        "customer": {
            "CustName": "name",
            "Address": "street",
            "City": "city",
            "StateProv": "state",
            "PostalCode": "postalCode",
            "Country": "country",
            "RegDate": "registrationDate",
            "Updated": "lastUpdated",
            "Ref": "restfulLink",
            "Comment": "comments"
        }
    }

    # Fields that should be arrays
    ARRAY_FIELDS = {
        "cidr", "street", "comments", "phones", "emails"
    }

    @staticmethod
    def _is_comment(line: str) -> bool:
        """Check if line is a comment (starts with #)."""
        stripped = line.strip()
        return stripped.startswith("#") or not stripped

    @staticmethod
    def _parse_field_line(line: str) -> Optional[tuple[str, str]]:
        """
        Parse a single ARIN field line.

        Args:
            line: Raw line from WHOIS response

        Returns:
            Tuple of (field_name, field_value) or None
        """
        # ARIN format: "FieldName:   value"
        match = re.match(r'^([a-zA-Z0-9\-]+):\s*(.*)$', line)
        if match:
            field_name = match.group(1)
            field_value = match.group(2).strip()
            return field_name, field_value
        return None

    @classmethod
    def _detect_object_type(cls, fields: Dict[str, Any]) -> Optional[str]:
        """
        Detect ARIN object type from parsed fields.

        Args:
            fields: Dictionary of parsed fields (with original ARIN field names)

        Returns:
            Object type string (net, org, poc, asn, customer) or None
        """
        # Check for unique signature fields first (most specific first)
        if "NetHandle" in fields or "NetRange" in fields:
            return "net"
        if "POCHandle" in fields:
            return "poc"
        if "ASNumber" in fields or "ASHandle" in fields:
            return "asn"
        if "OrgId" in fields and "OrgName" in fields:
            return "org"
        if "CustName" in fields and "NetHandle" not in fields:
            return "customer"

        return None

    @classmethod
    def _map_fields(cls, obj_type: str, raw_fields: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map ARIN field names to normalized schema field names.

        Args:
            obj_type: Object type
            raw_fields: Dictionary with original ARIN field names

        Returns:
            Dictionary with normalized field names
        """
        mapping = cls.FIELD_MAPPINGS.get(obj_type, {})
        result = {}

        for arin_field, value in raw_fields.items():
            normalized_field = mapping.get(arin_field, arin_field.lower())

            # Handle special cases
            if normalized_field == "phones":
                # Parse phone number with type
                phone_type = "Office"
                if "Mobile" in arin_field:
                    phone_type = "Mobile"
                elif "Fax" in arin_field:
                    phone_type = "Fax"

                if "phones" not in result:
                    result["phones"] = []
                result["phones"].append({
                    "number": value,
                    "type": phone_type
                })
            elif normalized_field == "emails":
                if "emails" not in result:
                    result["emails"] = []
                if isinstance(value, list):
                    result["emails"].extend(value)
                else:
                    result["emails"].append(value)
            elif normalized_field in cls.ARRAY_FIELDS:
                # Ensure array fields are lists
                if normalized_field not in result:
                    result[normalized_field] = []
                if isinstance(value, list):
                    result[normalized_field].extend(value)
                else:
                    result[normalized_field].append(value)
            else:
                # Regular field
                result[normalized_field] = value

        return result

    @classmethod
    def _parse_single_object(cls, lines: List[str]) -> Dict[str, Any]:
        """
        Parse a single ARIN object from lines.

        Args:
            lines: List of lines for one object

        Returns:
            Dictionary with parsed fields (original ARIN field names)
        """
        fields = {}
        current_field = None
        current_value = []

        for line in lines:
            # Skip comments
            if cls._is_comment(line):
                continue

            # Check for continuation line (starts with whitespace)
            if line and line[0] in (' ', '\t'):
                if current_field:
                    current_value.append(line.strip())
                continue

            # Parse field line
            parsed = cls._parse_field_line(line)
            if parsed:
                # Save previous field
                if current_field:
                    value = ' '.join(current_value) if current_value else ''
                    if current_field in fields:
                        # Multiple values - convert to list
                        if isinstance(fields[current_field], list):
                            fields[current_field].append(value)
                        else:
                            fields[current_field] = [fields[current_field], value]
                    else:
                        fields[current_field] = value

                # Start new field
                current_field, first_value = parsed
                current_value = [first_value] if first_value else []

        # Save last field
        if current_field:
            value = ' '.join(current_value) if current_value else ''
            if current_field in fields:
                if isinstance(fields[current_field], list):
                    fields[current_field].append(value)
                else:
                    fields[current_field] = [fields[current_field], value]
            else:
                fields[current_field] = value

        return fields

    @classmethod
    def parse(cls, whois_response: str) -> Dict[str, Any]:
        """
        Parse ARIN WHOIS response into structured JSON format.

        Args:
            whois_response: Raw ARIN WHOIS response

        Returns:
            Dictionary with structure:
            {
                "objects": [
                    {
                        "objectType": "net",
                        "handle": "NET-74-125-0-0-1",
                        "netRange": "74.125.0.0 - 74.125.255.255",
                        ...
                    }
                ]
            }

        Raises:
            WhoisParseError: If parsing fails
        """
        try:
            lines = whois_response.split('\n')

            # ARIN typically returns one object per query
            # But responses can contain multiple sections (network + org references)
            # We'll parse all and let the caller decide

            all_fields = cls._parse_single_object(lines)

            if not all_fields:
                return {"objects": []}

            # Detect object type
            obj_type = cls._detect_object_type(all_fields)
            if not obj_type:
                # If we can't detect type, return raw fields
                return {"objects": [{"objectType": "unknown", **all_fields}]}

            # Map fields to normalized names
            normalized = cls._map_fields(obj_type, all_fields)
            normalized["objectType"] = obj_type

            return {
                "objects": [normalized]
            }

        except Exception as e:
            raise WhoisParseError(f"Failed to parse ARIN response: {e}")

    @classmethod
    def parse_single_object(cls, whois_response: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single ARIN object (convenience method).

        Args:
            whois_response: Raw WHOIS response

        Returns:
            Single object dictionary or None
        """
        result = cls.parse(whois_response)
        objects = result.get("objects", [])
        return objects[0] if objects else None
