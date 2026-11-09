"""
Format parsed WHOIS data into Whoxy-compatible format.
"""

from typing import Dict, Any, Optional
from datetime import datetime

class WhoxyFormatter:
    """Format WHOIS data in Whoxy-compatible structure."""

    @staticmethod
    def format(
        domain_name: str,
        parsed_data: Dict[str, Any],
        registry_entry: Dict[str, Any],
        registrar_entry: Optional[Dict[str, Any]] = None,
        whois_server: Optional[str] = None,
        source: str = 'registry',
        registry_whois_server: Optional[str] = None,
        include_whois_registry: bool = True,
        include_raw_parsed: bool = False,
    ) -> Dict[str, Any]:
        """
        Format parsed WHOIS data into Whoxy-compatible structure.

        Args:
            domain_name: The domain name being queried
            parsed_data: Merged parsed WHOIS data (used for top-level fields)
            registry_entry: Dict with ``whois_endpoint``, ``raw_data``, ``parsed``
                            from the registry WHOIS query.
            registrar_entry: Same structure from the registrar WHOIS query, or None.
            whois_server: Primary WHOIS server used (registry or registrar)
            source: ``"registry"`` or ``"registrar"`` — which server provided
                    the primary parsed data.
            registry_whois_server: The registry WHOIS hostname, present only
                                   when ``source`` is ``"registrar"``.
            include_whois_registry: If False, omit ``whois_registry`` from the result.
            include_raw_parsed: If True, add ``raw_parsed`` dict to each source entry.

        Returns:
            Whoxy-compatible dictionary
        """
        # Determine domain_registered status
        available = parsed_data.get('available')
        if available is False:
            domain_registered = 'yes'
        elif available is True:
            domain_registered = 'no'
        else:
            domain_registered = 'unknown'

        # Base structure
        result = {
            'domain_name': domain_name,
            'query_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source': source,
            'domain_registered': domain_registered,
        }

        # Add WHOIS server if available
        if whois_server:
            result['whois_server'] = whois_server

        # Add registry_whois_server when source is "registrar"
        if registry_whois_server:
            result['registry_whois_server'] = registry_whois_server

        # Add dates if available
        if parsed_data.get('create_date'):
            result['create_date'] = parsed_data['create_date']

        if parsed_data.get('update_date'):
            result['update_date'] = parsed_data['update_date']

        if parsed_data.get('expiry_date'):
            result['expiry_date'] = parsed_data['expiry_date']

        # Add registrar info if available
        registrar = parsed_data.get('registrar', {})
        if registrar:
            result['domain_registrar'] = {}

            if 'iana_id' in registrar:
                result['domain_registrar']['iana_id'] = registrar['iana_id']

            if 'registrar_name' in registrar:
                result['domain_registrar']['registrar_name'] = registrar['registrar_name']

            if 'whois_server' in registrar:
                result['domain_registrar']['whois_server'] = registrar['whois_server']

            if 'website_url' in registrar:
                result['domain_registrar']['website_url'] = registrar['website_url']

            if 'email_address' in registrar:
                result['domain_registrar']['email_address'] = registrar['email_address']

            if 'phone_number' in registrar:
                result['domain_registrar']['phone_number'] = registrar['phone_number']

        # Add contacts if available
        registrant = parsed_data.get('registrant', {})
        if registrant:
            result['registrant_contact'] = WhoxyFormatter._format_contact(registrant)

        admin = parsed_data.get('administrative_contact', {})
        if admin:
            result['administrative_contact'] = WhoxyFormatter._format_contact(admin)

        tech = parsed_data.get('technical_contact', {})
        if tech:
            result['technical_contact'] = WhoxyFormatter._format_contact(tech)

        billing = parsed_data.get('billing_contact', {})
        if billing:
            result['billing_contact'] = WhoxyFormatter._format_contact(billing)

        # Add name servers if available
        name_servers = parsed_data.get('name_servers', [])
        if name_servers:
            result['name_servers'] = name_servers

        # Add domain status if available
        domain_status = parsed_data.get('domain_status', [])
        if domain_status:
            result['domain_status'] = domain_status

        # Add DNSSEC info if available
        dnssec_status = parsed_data.get('dnssec')
        dnssec_keys = parsed_data.get('dnssec_keys', [])
        # Infer "signed" when keys are present but no explicit status field
        if not dnssec_status and dnssec_keys:
            dnssec_status = 'signed'
        if dnssec_status:
            result['dnssec'] = dnssec_status
        if dnssec_keys:
            result['dnssec_keys'] = dnssec_keys

        # Per-source entries: whois_registry and whois_registrar
        if include_whois_registry:
            result['whois_registry'] = WhoxyFormatter._format_source_entry(
                registry_entry, include_raw_parsed=include_raw_parsed
            )

        if registrar_entry:
            result['whois_registrar'] = WhoxyFormatter._format_source_entry(
                registrar_entry, include_raw_parsed=include_raw_parsed
            )

        return result

    @staticmethod
    def _format_source_entry(entry: Dict[str, Any], include_raw_parsed: bool = False) -> Dict[str, Any]:
        """
        Format a per-source entry (registry or registrar) with both raw data
        and the parsed fields from that specific WHOIS server.
        """
        parsed = entry.get("parsed", {})
        result = {
            "whois_endpoint": entry.get("whois_endpoint", ""),
            "raw_data": entry.get("raw_data", ""),
        }

        for date_key in ("create_date", "update_date", "expiry_date"):
            if parsed.get(date_key):
                result[date_key] = parsed[date_key]

        if parsed.get("name_servers"):
            result["name_servers"] = parsed["name_servers"]

        if parsed.get("domain_status"):
            result["domain_status"] = parsed["domain_status"]

        registrar = parsed.get("registrar", {})
        if registrar:
            result["registrar"] = registrar

        for contact_key, out_key in (
            ("registrant", "registrant_contact"),
            ("administrative_contact", "administrative_contact"),
            ("technical_contact", "technical_contact"),
            ("billing_contact", "billing_contact"),
        ):
            contact = parsed.get(contact_key, {})
            if contact:
                result[out_key] = WhoxyFormatter._format_contact(contact)

        if parsed.get("available") is not None:
            result["available"] = parsed["available"]
        if parsed.get("availability_reason"):
            result["availability_reason"] = parsed["availability_reason"]

        # Boolean status flags
        result["domain_status_flags"] = WhoxyFormatter._compute_status_flags(parsed)

        # Add flat key:value line-by-line parsing of the raw data
        if include_raw_parsed:
            result["raw_parsed"] = WhoxyFormatter._parse_raw_flat(entry.get("raw_data", ""))

        return result

    @staticmethod
    def _compute_status_flags(parsed: Dict[str, Any]) -> Dict[str, bool]:
        """Compute boolean domain status flags from parsed WHOIS data."""
        available = parsed.get("available")
        reason = (parsed.get("availability_reason") or "").lower()
        statuses = [s.lower() for s in (parsed.get("domain_status") or [])]

        is_hold = (
            any(kw in s for s in statuses for kw in ("hold", "frozen", "locked", "suspended", "quarantine"))
            or any(kw in reason for kw in ("hold", "frozen", "locked", "suspended"))
        )
        is_grace_period = (
            any(kw in s for s in statuses for kw in ("renewperiod", "autorenewperiod", "grace"))
            or "grace" in reason
        )
        is_pending_delete = (
            any(kw in s for s in statuses for kw in ("pendingdelete", "pending delete"))
            or "pending-delete" in reason
        )
        is_redemption_period = (
            any(kw in s for s in statuses for kw in ("redemptionperiod", "redemption"))
            or "redemption" in reason
        )
        is_reserved = (
            any(kw in s for s in statuses for kw in ("reserved", "blocked", "prohibited", "dpml", "sunrise", "landrush", "premium", "trademark", "withheld"))
            or any(kw in reason for kw in ("reserved", "blocked", "premium", "trademark", "brand protection", "withheld"))
        )
        is_service_error = (
            available is None
            and any(kw in reason for kw in ("service error", "rate limit", "rate-limit", "temporarily unavailable", "access denied", "too many requests", "quota"))
        )
        # Expired: domain was registered but expiry date is past and no clear status
        is_expired = (
            available is None
            and "expired" in reason
            and "redemption" not in reason
            and "pending" not in reason
        )

        return {
            "is_registered": available is False,
            "is_available": available is True,
            "is_hold": is_hold,
            "is_grace_period": is_grace_period,
            "is_pending_delete": is_pending_delete,
            "is_redemption_period": is_redemption_period,
            "is_reserved": is_reserved,
            "is_service_error": is_service_error,
            "is_expired": is_expired,
        }

    @staticmethod
    def _parse_raw_flat(raw_data: str) -> Dict[str, Any]:
        """Parse raw WHOIS text into a flat key:value dict (line-by-line)."""
        result: Dict[str, Any] = {}
        current_key = None
        current_value: list = []

        for line in raw_data.split('\n'):
            stripped = line.strip()
            if not stripped or stripped.startswith('%') or stripped.startswith('#') or stripped.startswith(';'):
                continue
            if ':' in stripped:
                colon_pos = stripped.find(':')
                if 0 < colon_pos < 60:
                    if current_key:
                        value = ' '.join(current_value).strip()
                        if value:
                            if current_key in result:
                                if not isinstance(result[current_key], list):
                                    result[current_key] = [result[current_key]]
                                result[current_key].append(value)
                            else:
                                result[current_key] = value
                    parts = stripped.split(':', 1)
                    current_key = parts[0].strip()
                    current_value = [parts[1].strip()] if len(parts) > 1 and parts[1].strip() else []
                elif current_key:
                    current_value.append(stripped)
            elif current_key:
                current_value.append(stripped)

        if current_key:
            value = ' '.join(current_value).strip()
            if value:
                if current_key in result:
                    if not isinstance(result[current_key], list):
                        result[current_key] = [result[current_key]]
                    result[current_key].append(value)
                else:
                    result[current_key] = value

        return result

    @staticmethod
    def _format_contact(contact: Dict[str, str]) -> Dict[str, str]:
        """Format contact information."""
        formatted = {}

        # Normalize phone/fax fields
        if 'phone' in contact and 'phone_number' not in contact:
            contact['phone_number'] = contact['phone']
        if 'fax' in contact and 'fax_number' not in contact:
            contact['fax_number'] = contact['fax']

        # Map fields - use Whoxy naming convention
        field_mapping = {
            'full_name': 'full_name',
            'company_name': 'company_name',
            'email_address': 'email_address',
            'phone_number': 'phone_number',
            'fax_number': 'fax_number',
            'mailing_address': 'mailing_address',
            'city_name': 'city_name',
            'state_name': 'state_name',
            'zip_code': 'zip_code',
            'country_name': 'country_name',
            'country_code': 'country_code'
        }

        for source_key, target_key in field_mapping.items():
            if source_key in contact:
                formatted[target_key] = contact[source_key]

        return formatted


class RawFormatter:
    """Format WHOIS data in raw key:value format (line-by-line parsing)."""

    @staticmethod
    def format(
        domain_name: str,
        parsed_data: Dict[str, Any],
        registry_entry: Dict[str, Any],
        registrar_entry: Optional[Dict[str, Any]] = None,
        whois_server: Optional[str] = None,
        source: str = 'registry',
        registry_whois_server: Optional[str] = None,
        include_whois_registry: bool = True,
    ) -> Dict[str, Any]:
        """
        Format raw WHOIS into simple key:value dictionary.

        This is the raw line-by-line parsing format without normalization.
        Concatenates registry and registrar raw responses for line-by-line parsing.

        Args:
            domain_name: The domain name being queried
            parsed_data: Parsed WHOIS data from parser (ignored, we parse raw directly)
            registry_entry: Dict with ``whois_endpoint``, ``raw_data``, ``parsed``
            registrar_entry: Same structure from registrar WHOIS query, or None.
            whois_server: WHOIS server used for primary query
            source: ``"registry"`` or ``"registrar"``
            registry_whois_server: Registry WHOIS hostname when source is ``"registrar"``
            include_whois_registry: If False, only include registrar raw data

        Returns:
            Dictionary with raw key:value pairs from WHOIS
        """
        # Concatenate raw responses in order for line-by-line parsing
        parts = []
        if include_whois_registry or not registrar_entry:
            parts.append(registry_entry.get("raw_data", ""))
        if registrar_entry:
            parts.append(registrar_entry.get("raw_data", ""))
        combined = "\n".join(p for p in parts if p)

        result = {}
        current_key = None
        current_value = []

        # Parse line by line
        for line in combined.split('\n'):
            stripped = line.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith('%') or stripped.startswith('#') or stripped.startswith(';'):
                continue

            # Look for key: value format
            if ':' in stripped:
                colon_pos = stripped.find(':')
                if colon_pos > 0 and colon_pos < 60:  # Reasonable position for a key
                    # Save previous field if any
                    if current_key:
                        value = ' '.join(current_value).strip()
                        if value:
                            # Handle multiple values for same key
                            if current_key in result:
                                if not isinstance(result[current_key], list):
                                    result[current_key] = [result[current_key]]
                                result[current_key].append(value)
                            else:
                                result[current_key] = value

                    # Parse new field
                    parts = stripped.split(':', 1)
                    current_key = parts[0].strip()
                    current_value = [parts[1].strip()] if len(parts) > 1 and parts[1].strip() else []
                elif current_key:
                    # Continuation line with ':'
                    current_value.append(stripped)
            elif current_key:
                # Continuation line
                current_value.append(stripped)

        # Save last field
        if current_key:
            value = ' '.join(current_value).strip()
            if value:
                if current_key in result:
                    if not isinstance(result[current_key], list):
                        result[current_key] = [result[current_key]]
                    result[current_key].append(value)
                else:
                    result[current_key] = value

        # Add metadata fields
        available = parsed_data.get('available')
        result['Available'] = available
        result['Reason'] = parsed_data.get('availability_reason', 'Unknown')

        return result


def format_whois(
    domain_name: str,
    parsed_data: Dict[str, Any],
    registry_entry: Dict[str, Any],
    registrar_entry: Optional[Dict[str, Any]] = None,
    raw_parsed: bool = False,
    whois_server: Optional[str] = None,
    source: str = 'registry',
    registry_whois_server: Optional[str] = None,
    include_whois_registry: bool = True,
    include_raw_parsed: bool = False,
) -> Dict[str, Any]:
    """
    Format parsed WHOIS data.

    Args:
        domain_name: The domain name being queried
        parsed_data: Merged parsed WHOIS data (used for top-level fields)
        registry_entry: Dict with ``whois_endpoint``, ``raw_data``, ``parsed``
                        from the registry WHOIS query.
        registrar_entry: Same structure from registrar WHOIS query, or None.
        raw_parsed: If True, return raw line-by-line parsed format (simple key: value).
                    If False (default), return normalized Whoxy-compatible format.
        whois_server: Primary WHOIS server (registry or registrar)
        source: ``"registry"`` or ``"registrar"``
        registry_whois_server: Registry WHOIS hostname when source is ``"registrar"``
        include_whois_registry: If False, omit ``whois_registry`` from the result.

    Returns:
        Formatted WHOIS data
    """
    if raw_parsed:
        return RawFormatter.format(
            domain_name, parsed_data, registry_entry, registrar_entry,
            whois_server, source, registry_whois_server, include_whois_registry,
        )
    else:
        return WhoxyFormatter.format(
            domain_name, parsed_data, registry_entry, registrar_entry,
            whois_server, source, registry_whois_server, include_whois_registry,
            include_raw_parsed,
        )
