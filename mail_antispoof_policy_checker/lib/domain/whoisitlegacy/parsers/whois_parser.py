"""
Intelligent WHOIS parser that extracts structured data from raw WHOIS responses.
Based on pattern analysis of 5,160+ real WHOIS responses across 684 TLDs.
"""

import re
from typing import Dict, List, Optional, Any
from datetime import datetime

class WhoisParser:
    """Intelligent parser for WHOIS responses."""

    # Field patterns based on frequency analysis
    NAMESERVER_KEYS = [
        'name server', 'nserver', 'nameserver', 'dns', 'nameservers',
        'name servers',  # EURid / .uk / .be plural form
        'name server handle', 'nserver............', 'dnssec signed',
        'hostname', 'domain nameservers', 'domain servers in listed order',
        'domain servers', 'name servers dns',
    ]

    CREATION_DATE_KEYS = [
        'creation date', 'created', 'registered', 'registered on',
        'record created', 'domain created', 'registar created',
        'created............', 'option created', 'created-date',
        'registration date', 'registration time', 'created on',
        'domain registered', 'activation date',
    ]

    EXPIRY_DATE_KEYS = [
        'registry expiry date', 'registrar registration expiration date',
        'expiry date', 'expiration date', 'expire', 'expires',
        'expires on', 'expiration time', 'expires............',
        'date d\'expiration', 'paid-till',
        'renewal date', 'record will expire on', 'expiry',
        'valid until', 'validity',
    ]

    UPDATE_DATE_KEYS = [
        'updated date', 'changed', 'last-update', 'last modified',
        'last updated', 'modified', 'updated', 'last updated on',
        'last update', 'last-modified',
    ]

    STATUS_KEYS = [
        'domain status', 'status', 'eppstatus', 'eligstatus',
        'state', 'registration status',
        # 'flags' intentionally excluded: handled by _extract_block_status_values only,
        # to avoid matching EURid DNSSEC lines like "flags:KSK protocol:3 algorithm:..."
    ]

    DNSSEC_KEYS = [
        'dnssec', 'signed', 'secureDNS'.lower(),
    ]

    REGISTRAR_KEYS = [
        'registrar', 'sponsoring registrar', 'registrar name'
    ]

    REGISTRAR_IANA_ID_KEYS = [
        'registrar iana id', 'sponsoring registrar iana id', 'registrar iana',
    ]

    REGISTRAR_WHOIS_SERVER_KEYS = [
        'registrar whois server', 'whois server',
    ]

    REGISTRAR_URL_KEYS = [
        'registrar url', 'referral url', 'registrar website',
    ]

    ABUSE_EMAIL_KEYS = [
        'registrar abuse contact email', 'registrar abuse email',
        'abuse email', 'abuse contact email', 'abuse-mailbox',
    ]

    ABUSE_PHONE_KEYS = [
        'registrar abuse contact phone', 'registrar abuse phone',
        'abuse phone', 'abuse contact phone',
    ]

    REGISTRAR_EMAIL_KEYS = [
        'registrar abuse contact email', 'registrar email'
    ]

    REGISTRAR_PHONE_KEYS = [
        'registrar abuse contact phone', 'registrar phone'
    ]

    # Availability indicators — domain is NOT registered
    AVAILABLE_INDICATORS = [
        'no match', 'not found', 'no entries found', 'no data found',
        'status: available', 'status: free', 'status:available', 'status:free',
        'domain not found', 'no match for', 'not registered', 'no object found',
        'domain name not known', 'nothing found', 'not been registered',
        'has not been registered', 'no domain', 'available for registration',
        'is available', 'domain is available', 'can be registered', 'is free',
        'query returned 0 objects', 'no found', 'no information available',
        'does not exist', 'object does not exist', 'not exist',
        'no matching objects found', 'no matching record',
        'queried object does not exist', 'domain status: available',
        'no such domain', 'object_not_found',
        'no data was found to match the request criteria',
        '\navailable\n',
        # Additional availability indicators
        'domain available', 'available domain',
        'free domain', 'domain free',
        'unregistered domain', 'domain unregistered',
        'no match!!',
        'domain name not found', 'not found in database',
        'no matching record found',
        'registration status: available', 'state: available',
        'domain state: available', 'available for purchase',
        'this domain is available',
        'eligible for registration', 'free for registration',
        'open for registration', 'ready for registration',
        'registration available',
        'status code: 210', 'status code: 220',
        'response: 210', 'response: 220',
        '%error:101',
        # Chinese
        '未注册', '状态: 未注册',
    ]

    # Redemption grace period — domain expired, registrant can still renew
    # Domain is still "registered" (not yet released for public registration)
    REDEMPTION_INDICATORS = [
        'redemption', 'redemptionperiod', 'redemption period',
        'pending restore', 'pending delete restorable',
        'not available for second level registration',
        'status: redemption',
        # Chinese: 赎回期 = redemption period
        '赎回期',
    ]

    # Pending delete — domain about to be released; still not publicly registrable
    PENDING_DELETE_INDICATORS = [
        'pending delete', 'pendingdelete',
        'to be released',
        'status: pending delete',
        # Chinese: 待删除 = pending deletion
        '待删除',
    ]

    # Auto-renew grace period — recently expired, registrar can still auto-renew
    GRACE_INDICATORS = [
        'renew grace', 'auto renew period', 'autorenewperiod',
        'auto-renew grace', 'grace period', 'renewperiod',
    ]

    # Hold — domain registered but delegations suspended
    HOLD_INDICATORS = [
        'client hold', 'server hold', 'registrar hold', 'registry hold',
        'clienthold', 'serverhold',
        'status: clienthold', 'status: serverhold',
        'status: frozen', 'status: locked', 'status: suspended', 'status: quarantine',
        'domain on hold', 'name on hold',
        'domain frozen', 'name frozen',
        'domain locked', 'name locked',
        'domain suspended', 'name suspended',
        'domain quarantined', 'name quarantined',
    ]

    # Reserved / blocked / premium domains — not available for public registration
    RESERVED_INDICATORS = [
        'reserved domain name', 'reserved domain', 'domain is reserved',
        'blocked domain', 'not available for registration',
        'premium domain', 'domain blocked',
        'this name is reserved by the registry', 'this is a reserved name',
        'domain is not available for registration',
        'domain name is restricted', 'usage restrictions applied',
        'globalblock', 'adultblock',
        'domain status: prohibited string',
        'registration status: invalid',
        # EPP / registry status codes
        'status: reserved', 'status: restricted', 'status: blocked', 'status: prohibited',
        'status: reserved for registry', 'status: reserved for registrar',
        'status: reserved for registry operator', 'status: reserved for future use',
        'status: not available for registration', 'status: not available for general registration',
        'status: reserved for special purposes', 'status: reserved for government use',
        'status: premium', 'status: premium domain',
        'status: reserved by registry', 'status: reserved by registrar',
        'status: reserved by administrator', 'status: reserved by iana', 'status: reserved by icann',
        'status: trademark protected', 'status: trademark reservation',
        'status: brand protection', 'status: dpml block',
        'status: sunrise block', 'status: landrush block',
        'registry reserved', 'registrar reserved',
        'premium domain name', 'premium name',
        'trademark protected', 'trademark block', 'brand protection',
        'policy reserved', 'policy block',
        'regulatory reserved', 'regulatory block',
        'unavailable for registration', 'not available for public registration',
        'not available for general registration',
        'registration not permitted', 'registration prohibited',
        'registration restricted', 'registration blocked',
        'registration suspended', 'registration reserved',
        'this domain is reserved', 'this name is reserved',
        'domain reserved', 'name reserved',
        'domain withheld', 'name withheld', 'domain protected', 'name protected',
    ]

    # Rate-limit indicators — server is up but actively throttling this client
    # These must NOT be treated as availability signals
    RATE_LIMIT_INDICATORS = [
        'too many requests',
        'too many queries',
        'rate limit exceeded',
        'rate-limit exceeded',
        'query limit exceeded',
        'query rate limit',
        'requests of this client are not permitted',
        'exceeded the maximum allowable number',
        'exceeded the maximum allowable',
        'exceeded the allowed',
        'quota exceeded',
        'number of allowed queries',
        'maximum number of queries',
        'connection limit exceeded',
        'please slow down',
        'slow down',
        'try again in',
        'please try again later',
        'try again later',
        'access denied',
        'ip has been blocked',
        'temporarily blocked',
        'blocked by',
        'anti-spam',
        'not allowed to query',
        'too frequent',
        'throttl',
        'request limit',
        'ban',
    ]

    # Service error indicators — WHOIS server is genuinely unavailable or broken
    # (not rate-limiting, just down or timing out)
    # These must NOT be treated as availability signals
    SERVICE_ERROR_INDICATORS = [
        'the domain name search is temporarily unavailable',
        'temporarily unavailable',
        'service unavailable',
        'connection timeout',
        'service timeout',
        'whois server is temporarily unavailable',
    ]

    REGISTERED_INDICATORS = [
        # Core WHOIS fields that only appear on registered domains
        'expiry date:', 'registry expiry date:', 'registrar:',
        'creation date:', 'name server:', 'nserver:',
        'status: active', 'domain status:', 'registrant organization:',
        'registrant:', 'holder:', 'domain name:', 'updated date:',
        'dnssec:', 'registrar url:', 'registrar iana id:',
        'admin email:', 'tech email:', 'billing email:',
        # Additional WHOIS fields
        'changed:', 'sponsoring registrar:', 'referral url:',
        'registry domain id:', 'registrar whois server:',
        'registrar abuse contact email:', 'registrar abuse contact phone:',
        'reseller:', 'whois server:',
        'registered:', 'expire:', 'nsset:',
        'admin-c:', 'admin contact:', 'tech contact:', 'tech-c:',
        'billing contact:', 'person:',
        'registered on:', 'expires on:', 'last updated on:',
        'registrar registration expiration date:',
        'domain status: registered', 'domain status: active',
        'status: registered', 'status: ok', 'status: connect',
        'dnssec: unsigned', 'dnssec: signed',
        # Transfer lock EPP statuses — only appear on registered domains
        'clienttransferprohibited', 'servertransferprohibited',
        'clientupdateprohibited', 'serverupdateprohibited',
        'clientdeleteprohibited', 'serverdeleteprohibited',
        'clientrenewprohibited', 'serverrenewprohibited',
        'transfer prohibited',
        # Expired indicators (domain still in registry, just expired)
        'already expired',
        # Chinese: 已过期 = already expired
        '已过期',
    ]

    def __init__(self):
        self.lines = []
        self.parsed_data = {}

    def parse(self, raw_whois: str) -> Dict[str, Any]:
        """Parse raw WHOIS text and extract structured data."""
        if not raw_whois or len(raw_whois) < 20:
            return self._empty_result()

        self.lines = raw_whois.split('\n')
        self.parsed_data = {}
        self.raw_whois = raw_whois

        # Detect if this is a reference-based format (like .fr)
        if self._is_reference_based_format():
            # Parse reference-based format (nic-hdl blocks)
            self._parse_reference_based()
        else:
            # Parse standard format
            self._parse_standard()

        # Detect availability
        availability_result = self._detect_availability(raw_whois)
        self.parsed_data['available'] = availability_result['available']
        self.parsed_data['availability_reason'] = availability_result['reason']
        self.parsed_data['is_rate_limited'] = availability_result.get('is_rate_limited', False)
        self.parsed_data['is_service_error'] = availability_result.get('is_service_error', False)

        return self.parsed_data

    def _is_reference_based_format(self) -> bool:
        """Detect if this is a reference-based WHOIS format (like .fr with nic-hdl)."""
        raw_lower = self.raw_whois.lower()
        return 'nic-hdl:' in raw_lower or 'holder-c:' in raw_lower

    def _parse_standard(self):
        """Parse standard WHOIS format."""
        self.parsed_data['name_servers'] = self._extract_nameservers()
        self.parsed_data['create_date'] = self._extract_date(self.CREATION_DATE_KEYS)
        self.parsed_data['expiry_date'] = self._extract_date(self.EXPIRY_DATE_KEYS)
        self.parsed_data['update_date'] = self._extract_date(self.UPDATE_DATE_KEYS)
        self.parsed_data['domain_status'] = self._extract_status()
        self.parsed_data['dnssec'] = self._extract_dnssec_status()
        self.parsed_data['dnssec_keys'] = self._extract_dnssec_keys()
        self.parsed_data['registrar'] = self._extract_registrar()
        self.parsed_data['registrant'] = self._extract_contact('registrant')
        self.parsed_data['administrative_contact'] = self._extract_contact('admin')
        self.parsed_data['technical_contact'] = self._extract_contact('tech')
        self.parsed_data['billing_contact'] = self._extract_contact('billing')

        # JPRS .jp bracket-format supplement
        if self._is_jp_format():
            self._parse_jp_supplement()

    def _parse_jp_supplement(self):
        """Fill missing fields from JPRS .jp bracket format [Key]   value."""
        if not self.parsed_data.get('name_servers'):
            ns = [n.lower() for n in self._extract_jp_all('Name Server') if '.' in n]
            if ns:
                self.parsed_data['name_servers'] = list(dict.fromkeys(ns))

        if not self.parsed_data.get('create_date'):
            v = self._extract_jp_field('Created on')
            if v:
                self.parsed_data['create_date'] = self._parse_date_str(v)

        if not self.parsed_data.get('expiry_date'):
            v = self._extract_jp_field('Expires on')
            if v:
                self.parsed_data['expiry_date'] = self._parse_date_str(v)

        if not self.parsed_data.get('update_date'):
            v = self._extract_jp_field('Last Updated')
            if v:
                self.parsed_data['update_date'] = self._parse_date_str(v)

        if not self.parsed_data.get('domain_status'):
            statuses = self._extract_jp_all('Status') + self._extract_jp_all('Lock Status')
            if statuses:
                self.parsed_data['domain_status'] = statuses

        # Registrant contact
        if not self.parsed_data.get('registrant'):
            contact: Dict[str, str] = {}
            name = self._extract_jp_field('Registrant') or self._extract_jp_field('Name')
            if name:
                contact['company_name'] = name
            email = self._extract_jp_field('Email')
            if email:
                contact['email_address'] = email
            postal = self._extract_jp_field('Postal Address')
            if postal:
                contact['mailing_address'] = postal
            postal_code = self._extract_jp_field('Postal code')
            if postal_code:
                contact['zip_code'] = postal_code
            phone = self._extract_jp_field('Phone')
            if phone:
                contact['phone_number'] = phone
            fax = self._extract_jp_field('Fax')
            if fax:
                contact['fax_number'] = fax
            if contact:
                self.parsed_data['registrant'] = contact

    def _parse_reference_based(self):
        """Parse reference-based WHOIS format (like .fr with nic-hdl blocks)."""
        # Extract basic fields
        self.parsed_data['name_servers'] = self._extract_nameservers()
        self.parsed_data['create_date'] = self._extract_date(self.CREATION_DATE_KEYS)
        self.parsed_data['expiry_date'] = self._extract_date(self.EXPIRY_DATE_KEYS)
        self.parsed_data['update_date'] = self._extract_date(self.UPDATE_DATE_KEYS)
        self.parsed_data['domain_status'] = self._extract_status()
        self.parsed_data['dnssec'] = self._extract_dnssec_status()
        self.parsed_data['dnssec_keys'] = self._extract_dnssec_keys()

        # Parse nic-hdl blocks
        nic_blocks = self._extract_nic_blocks()

        # Extract registrar - try standard field first
        registrar_name = self._extract_value(['registrar'])

        # For .fr format, extract registrar details directly (not from nic-hdl blocks)
        registrar_info = {'registrar_name': registrar_name} if registrar_name else {}

        # Try extracting website, email, phone that appear near registrar field
        website = self._extract_value(['website'])
        email = self._extract_all_values(['e-mail'])
        phone = self._extract_all_values(['phone'])

        # Take first email/phone from raw (usually registrar's)
        if website:
            registrar_info['website_url'] = website
        if email and len(email) > 0:
            # Use the first email that's not a nic-hdl contact email
            for e in email:
                if '@contact.gandi.net' not in e or 'support@' in e:
                    registrar_info['email_address'] = e
                    break
            if not registrar_info.get('email_address') and email:
                registrar_info['email_address'] = email[0]
        if phone and len(phone) > 0:
            registrar_info['phone_number'] = phone[0]

        self.parsed_data['registrar'] = registrar_info

        # Map nic-hdl references to contacts
        holder_ref = self._extract_value(['holder-c'])
        admin_ref = self._extract_value(['admin-c'])
        tech_ref = self._extract_value(['tech-c'])

        # Find corresponding blocks
        self.parsed_data['registrant'] = self._find_contact_by_ref(nic_blocks, holder_ref)
        self.parsed_data['administrative_contact'] = self._find_contact_by_ref(nic_blocks, admin_ref)
        self.parsed_data['technical_contact'] = self._find_contact_by_ref(nic_blocks, tech_ref)
        self.parsed_data['billing_contact'] = {}

    def _extract_nic_blocks(self) -> List[Dict[str, Any]]:
        """Extract nic-hdl contact blocks from WHOIS response."""
        blocks = []
        current_block = None
        in_block = False

        for line in self.lines:
            stripped = line.strip()

            # Skip comments
            if not stripped or stripped.startswith('%') or stripped.startswith('#'):
                continue

            # Start of new block
            if stripped.startswith('nic-hdl:'):
                # Save previous block
                if current_block:
                    blocks.append(current_block)

                # Start new block
                parts = stripped.split(':', 1)
                current_block = {
                    'nic-hdl': parts[1].strip() if len(parts) > 1 else '',
                    'raw_text': stripped + '\n'
                }
                in_block = True
            elif in_block and ':' in stripped:
                # Add field to current block
                parts = stripped.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()

                    # Handle multiple addresses
                    if key == 'address':
                        if 'address' not in current_block:
                            current_block['address'] = []
                        current_block['address'].append(value)
                    else:
                        current_block[key] = value

                    current_block['raw_text'] += stripped + '\n'
            elif in_block and not stripped:
                # Empty line might end block
                if current_block:
                    current_block['raw_text'] += '\n'

        # Save last block
        if current_block:
            blocks.append(current_block)

        return blocks

    def _find_contact_by_ref(self, nic_blocks: List[Dict[str, Any]], ref: Optional[str]) -> Dict[str, str]:
        """Find contact information by nic-hdl reference."""
        if not ref:
            return {}

        for block in nic_blocks:
            if block.get('nic-hdl') == ref:
                # Build contact dict
                contact = {}

                if 'contact' in block:
                    contact['company_name'] = block['contact']

                # Combine addresses
                if 'address' in block and isinstance(block['address'], list):
                    contact['mailing_address'] = ', '.join(block['address'])

                if 'country' in block:
                    contact['country_code'] = block['country']
                    # Map country code to name (simple mapping)
                    country_names = {
                        'FR': 'France',
                        'US': 'United States',
                        'GB': 'United Kingdom',
                        'DE': 'Germany',
                        'ES': 'Spain',
                        'IT': 'Italy',
                        'NL': 'Netherlands',
                        'BE': 'Belgium',
                        'CH': 'Switzerland'
                    }
                    contact['country_name'] = country_names.get(block['country'], block['country'])

                if 'e-mail' in block:
                    contact['email_address'] = block['e-mail']

                if 'phone' in block:
                    contact['phone_number'] = block['phone']

                if 'fax-no' in block:
                    contact['fax_number'] = block['fax-no']

                return contact

        return {}

    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure."""
        return {
            'name_servers': [],
            'create_date': None,
            'expiry_date': None,
            'update_date': None,
            'domain_status': [],
            'registrar': {},
            'registrant': {},
            'administrative_contact': {},
            'technical_contact': {},
            'billing_contact': {},
            'available': None,
            'availability_reason': 'Unknown - insufficient data',
            'is_rate_limited': False,
            'is_service_error': False,
        }

    def _extract_value(self, keys: List[str], case_sensitive: bool = False) -> Optional[str]:
        """Extract value for given keys."""
        for line in self.lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#') or line.startswith(';'):
                continue

            if ':' not in line:
                continue

            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            key = parts[0].strip()
            value = parts[1].strip()

            if not case_sensitive:
                key = key.lower()

            for target_key in keys:
                if not case_sensitive:
                    target_key = target_key.lower()

                if key == target_key and value:
                    return value

        return None

    def _extract_all_values(self, keys: List[str]) -> List[str]:
        """Extract all values for given keys (for multi-value fields like nameservers)."""
        values = []

        for line in self.lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#') or line.startswith(';'):
                continue

            if ':' not in line:
                continue

            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            key = parts[0].strip().lower()
            value = parts[1].strip()

            for target_key in keys:
                if key == target_key.lower() and value:
                    values.append(value)
                    break

        return values

    def _extract_value_regex(self, patterns: List[str]) -> Optional[str]:
        """Regex fallback: try each pattern (applied to each line) and return first match."""
        for line in self.lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('%') or line_stripped.startswith('#') or line_stripped.startswith(';'):
                continue
            for pattern in patterns:
                m = re.match(pattern, line_stripped, re.IGNORECASE)
                if m and m.group(1).strip():
                    return m.group(1).strip()
        return None

    # ------------------------------------------------------------------
    # Block-style extraction  (EURid .eu, DNS Belgium .be, Nominet .uk,
    #                          DNS.pl .pl, JPRS .jp, and others)
    # ------------------------------------------------------------------

    @staticmethod
    def _line_indent(raw_line: str) -> int:
        """Return leading whitespace count of a raw line."""
        return len(raw_line) - len(raw_line.lstrip(' \t'))

    # No-colon block section headers (e.g. .it "Nameservers" without trailing colon)
    _NO_COLON_NS_HEADERS = {'nameservers', 'name servers'}

    def _extract_block_plain_values(self, header_keys: List[str]) -> List[str]:
        """
        Collect hostname values from block-style WHOIS sections using relative indentation.

        Works regardless of the absolute indentation of the header itself, which
        handles formats like Nominet .uk where the whole response is indented.

        Handles:
          1. Empty-header + deeper-indented values (.eu, .be, .uk, .it):
                 Name servers:           <- header at any level (with or without colon)
                         ns1.ex.com      <- deeper than header
          2. Header with first value + tab-aligned continuation (.pl):
                 nameservers: ns1.ex.com.
                              ns2.ex.com. <- deeper/same with no key
          3. Values with IP addresses on same line (.uk, .su, .pl):
                 ns1.ex.com   1.2.3.4    <- first token extracted as hostname
        """
        header_keys_lower = {k.lower() for k in header_keys}
        values: List[str] = []
        in_block = False
        header_indent = 0

        for raw_line in self.lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith('%') or stripped.startswith('#') or stripped.startswith(';'):
                if not stripped:
                    in_block = False
                continue

            line_indent = self._line_indent(raw_line)

            if in_block:
                if line_indent > header_indent:
                    # Deeper line — could be content or sub-key
                    if ':' in stripped:
                        colon_pos = stripped.find(':')
                        key_c = stripped[:colon_pos].strip()
                        if ' ' not in key_c and len(key_c) < 25:
                            continue  # sub-key (Name:, Website:, …) — skip
                    # Accept the raw stripped value; _extract_nameservers will clean it
                    first_token = stripped.split()[0] if stripped.split() else ''
                    if '.' in first_token:
                        values.append(stripped)
                else:
                    # Same or lesser indent — end of block unless it's a continuation
                    if ':' in stripped:
                        colon_pos = stripped.find(':')
                        key = stripped[:colon_pos].strip().lower()
                        val = stripped[colon_pos + 1:].strip()
                        if key in header_keys_lower:
                            # Another header of same type — reset block
                            in_block = True
                            header_indent = line_indent
                            if val:
                                values.append(val)
                            continue
                        in_block = False
                        # Fall through (don't continue) so we don't miss a new header below
                    else:
                        in_block = False

            if not in_block:
                if ':' in stripped:
                    colon_pos = stripped.find(':')
                    key = stripped[:colon_pos].strip().lower()
                    val = stripped[colon_pos + 1:].strip()
                    if key in header_keys_lower:
                        in_block = True
                        header_indent = line_indent
                        if val:
                            values.append(val)
                elif stripped.lower() in self._NO_COLON_NS_HEADERS:
                    # .it-style: "Nameservers" with no colon, values on next indented lines
                    in_block = True
                    header_indent = line_indent

        return values

    def _extract_block_status_values(self, header_keys: List[str]) -> List[str]:
        """
        Collect all deeper-indented values from block sections (relative indentation).
        Used for domain status, e.g. .be ``Flags:\\n\\tclientTransferProhibited``.
        """
        header_keys_lower = {k.lower() for k in header_keys}
        values: List[str] = []
        in_block = False
        header_indent = 0

        for raw_line in self.lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith('%') or stripped.startswith('#') or stripped.startswith(';'):
                if not stripped:
                    in_block = False
                continue

            line_indent = self._line_indent(raw_line)

            if in_block:
                if line_indent > header_indent:
                    if ':' in stripped:
                        colon_pos = stripped.find(':')
                        key_c = stripped[:colon_pos].strip()
                        if ' ' not in key_c and len(key_c) < 25:
                            val = stripped[colon_pos + 1:].strip()
                            if val:
                                values.append(val)
                            else:
                                values.append(key_c)
                            continue
                    if stripped:
                        values.append(stripped)
                else:
                    in_block = False

            if not in_block and ':' in stripped:
                colon_pos = stripped.find(':')
                key = stripped[:colon_pos].strip().lower()
                val = stripped[colon_pos + 1:].strip()
                if key in header_keys_lower and not val:
                    in_block = True
                    header_indent = line_indent

        return values

    def _extract_block_registrar(self) -> Dict[str, str]:
        """
        Extract registrar from block-style WHOIS using relative indentation.

        Handles:
          a) EURid .eu / .be — deeper sub-keys (Name:, Website:):
                 Registrar:
                         Name:    Markmonitor Inc.
                         Website: https://www.markmonitor.com
          b) Nominet .uk — first deeper plain line is name, URL: is website:
                 Registrar:
                         Markmonitor Inc. [Tag = MARKMONITOR]
                         URL: https://www.markmonitor.com
          c) DNS.pl — same-indent sequential lines after REGISTRAR::
                 REGISTRAR:
                 Nom-IQ Limited dba Com Laude
                 http://www.comlaude.com/
          d) .it — section header without colon + deeper-indented sub-keys:
                 Registrar
                   Name:  Namecheap Inc.
        """
        result: Dict[str, str] = {}
        in_block = False
        header_indent = 0
        lines_in_block = 0
        sequential = False  # True = .pl same-indent mode

        for raw_line in self.lines:
            stripped = raw_line.strip()
            if stripped.startswith('%') or stripped.startswith('#') or stripped.startswith(';'):
                continue
            if not stripped:
                if in_block and sequential:
                    break  # blank line ends .pl-style block
                continue

            line_indent = self._line_indent(raw_line)

            if in_block:
                if sequential:
                    # .pl mode: collect same-indent lines until blank or new WHOIS key
                    if line_indent == header_indent:
                        if ':' in stripped:
                            colon_pos = stripped.find(':')
                            key = stripped[:colon_pos].strip().lower()
                            val = stripped[colon_pos + 1:].strip()
                            # Looks like a new section key → stop
                            if ' ' not in key and len(key) < 20 and key not in ('tel', 'phone', 'fax', 'url', 'website'):
                                break
                            if key in ('url', 'website') and val and 'website_url' not in result:
                                result['website_url'] = val
                        elif stripped.startswith('http') and 'website_url' not in result:
                            result['website_url'] = stripped
                        elif '@' in stripped and '.' in stripped and 'email_address' not in result:
                            result['email_address'] = stripped
                        elif lines_in_block == 0 and 'registrar_name' not in result:
                            result['registrar_name'] = stripped
                        lines_in_block += 1
                    else:
                        break
                    continue

                if line_indent <= header_indent:
                    # Same/lesser indent — first content line at same indent = sequential (.pl)
                    if lines_in_block == 0:
                        # Determine mode: does this look like registrar content?
                        is_key_value = (':' in stripped and
                                        stripped.find(':') < 25 and
                                        ' ' not in stripped[:stripped.find(':')].strip())
                        if not is_key_value:
                            # Same-indent plain text → sequential mode (.pl)
                            sequential = True
                            if 'registrar_name' not in result:
                                result['registrar_name'] = stripped
                            lines_in_block += 1
                            continue
                    in_block = False
                    # Fall through to check for new header

                elif line_indent > header_indent:
                    # Deeper-indented content (EURid, .be, .uk, .it)
                    if ':' in stripped:
                        colon_pos = stripped.find(':')
                        key_c = stripped[:colon_pos].strip().lower()
                        val = stripped[colon_pos + 1:].strip()
                        if ' ' not in key_c and len(key_c) < 25:
                            if key_c == 'name' and val and 'registrar_name' not in result:
                                result['registrar_name'] = val
                            elif key_c in ('website', 'url') and val and 'website_url' not in result:
                                result['website_url'] = val
                            elif key_c == 'email' and val and 'email_address' not in result:
                                result['email_address'] = val
                            lines_in_block += 1
                            continue
                    # Plain deeper line (UK: first indented line is registrar name)
                    if lines_in_block == 0 and 'registrar_name' not in result:
                        name = re.sub(r'\s*\[.*?\]', '', stripped).strip() if '[' in stripped else stripped
                        if name and not name.lower().startswith('not shown') and '@' not in name and not name.startswith('http'):
                            result['registrar_name'] = name
                    elif stripped.startswith('http') and 'website_url' not in result:
                        result['website_url'] = stripped
                    lines_in_block += 1
                    continue

            # Look for registrar header
            if not in_block:
                if ':' in stripped:
                    colon_pos = stripped.find(':')
                    key = stripped[:colon_pos].strip().lower()
                    val = stripped[colon_pos + 1:].strip()
                    if key == 'registrar' and not val:
                        in_block = True
                        header_indent = line_indent
                        lines_in_block = 0
                        sequential = False
                elif stripped.lower() == 'registrar':
                    in_block = True
                    header_indent = line_indent
                    lines_in_block = 0
                    sequential = False

        return result

    # ------------------------------------------------------------------
    # JPRS .jp bracket-format helpers
    # ------------------------------------------------------------------

    def _is_jp_format(self) -> bool:
        """Detect JPRS-style WHOIS: fields like ``[Domain Name]   GOOGLE.JP``."""
        for line in self.lines:
            if re.match(r'^\[(?:Domain Name|Name Server|Created on|Expires on)\]', line.strip(), re.IGNORECASE):
                return True
        return False

    def _extract_jp_all(self, key_name: str) -> List[str]:
        """Return all values for a ``[Key Name]   value`` line."""
        pat = re.compile(r'^\[' + re.escape(key_name) + r'\]\s+(.*\S)', re.IGNORECASE)
        results = []
        for line in self.lines:
            m = pat.match(line.strip())
            if m:
                results.append(m.group(1).strip())
        return results

    def _extract_jp_field(self, key_name: str) -> Optional[str]:
        """Return first value for a ``[Key Name]   value`` line."""
        vals = self._extract_jp_all(key_name)
        return vals[0] if vals else None

    def _extract_nameservers(self) -> List[str]:
        """Extract nameservers (standard key:value, block-indented, JP bracket)."""
        raw_values: List[str] = []

        # 1. Standard key: value lines
        raw_values.extend(self._extract_all_values(self.NAMESERVER_KEYS))

        # 2. Block-style (EURid .eu, .be, .uk, .bn) and continuation lines (.pl)
        raw_values.extend(self._extract_block_plain_values(self.NAMESERVER_KEYS))

        # 3. JP bracket format: [Name Server]   ns1.google.com
        raw_values.extend(self._extract_jp_all('Name Server'))

        nameservers = []
        for ns in raw_values:
            # Strip common suffixes that appear in various WHOIS formats:
            ns_clean = ns.split(' | ')[0]          # .pt: "ns1.x.com | IPv4: ..."
            ns_clean = re.sub(r'\s*\(.*?\)', '', ns_clean)   # .cz: "ns1.x.cz (1.2.3.4)"
            ns_clean = re.sub(r'\s*\[.*?\]', '', ns_clean)   # .pl: "ns1.x.pl. [1.2.3.4][...]"
            ns_clean = re.sub(r'\s+https?://.*', '', ns_clean)  # any URL suffix
            ns_clean = ns_clean.strip().rstrip('.').lower()
            # If there is still whitespace (e.g. "ns1.x.com 1.2.3.4"), take first token
            if ' ' in ns_clean or '\t' in ns_clean:
                ns_clean = ns_clean.split()[0].rstrip('.')
            if 'unsigned' in ns_clean or 'signed' in ns_clean:
                continue
            if ns_clean and '.' in ns_clean and ' ' not in ns_clean:
                nameservers.append(ns_clean)

        return list(dict.fromkeys(nameservers))  # deduplicate, preserve order

    # Ordered from most-specific to least-specific so longer formats are tried first
    _DATE_FORMATS = [
        '%Y-%m-%dT%H:%M:%SZ',    # 2023-04-15T14:23:00Z  (ISO 8601)
        '%Y-%m-%dT%H:%M:%S',     # 2023-04-15T14:23:00
        '%Y-%m-%d %H:%M:%S',     # 1999-12-10 00:00:00   (.it, standard)
        '%Y.%m.%d %H:%M:%S',     # 1998.10.06 13:00:00   (.pl)
        '%Y/%m/%d %H:%M:%S',     # 2025/06/01 01:05:04   (.jp)
        '%d/%m/%Y %H:%M:%S',
        '%d-%m-%Y %H:%M:%S',
        '%a %b %d %H:%M:%S %Z %Y',  # Fri Jan  1 00:00:00 UTC 2021
        '%a %b %d %Y',           # Tue Dec 12 2000       (.be)
        '%Y-%m-%d',              # 2023-04-15             (standard)
        '%Y/%m/%d',              # 2005/05/30             (.jp)
        '%d-%b-%Y',              # 11-Jun-2014            (.uk, .bn)
        '%d %b %Y',              # 11 Jun 2014
        '%d/%m/%Y',              # 15/04/2023
        '%d-%m-%Y',              # 15-04-2023
        '%Y.%m.%d',              # 1998.10.06             (.pl)
        '%d.%m.%Y',              # 15.04.2023
        '%Y%m%d',                # 20230415
        '%b %d, %Y',             # Jan 1, 2024
        '%d-%b-%y',              # 01-Jan-24
        '%d-%m-%y',              # 01-01-24
    ]

    def _extract_date(self, keys: List[str]) -> Optional[str]:
        """Extract and normalize date from standard key:value lines."""
        date_str = self._extract_value(keys)
        if not date_str:
            return None
        return self._parse_date_str(date_str)

    def _parse_date_str(self, date_str: str) -> Optional[str]:
        """Attempt to normalise an arbitrary date string to YYYY-MM-DD."""
        if not date_str:
            return None

        # Clean noise: parenthetical remarks, trailing timezone words
        date_str = re.sub(r'\s*\([^)]*\)', '', date_str).strip()
        date_str = re.sub(r'\s+[A-Z]{2,4}$', '', date_str).strip()  # trailing TZ like UTC, JST

        # Try every format against the full string first, then against the first space-token
        candidates = [date_str]
        first_token = date_str.split()[0] if ' ' in date_str else None
        if first_token and first_token != date_str:
            candidates.append(first_token)
        # Also try stripping after T (ISO datetime)
        if 'T' in date_str:
            candidates.append(date_str.split('T')[0])

        for candidate in candidates:
            for fmt in self._DATE_FORMATS:
                try:
                    dt = datetime.strptime(candidate, fmt)
                    return dt.strftime('%Y-%m-%d')
                except ValueError:
                    continue

        # Return the raw string rather than None so has_creation_date stays truthy
        return date_str

    # Block headers that contain DNSSEC key data (not domain status)
    _DNSSEC_KEY_BLOCK_HEADERS = {'keys', 'ds data', 'ds record', 'dnskey'}

    def _extract_dnssec_status(self) -> Optional[str]:
        """Extract DNSSEC status (signedDelegation, unsigned, yes, no, …)."""
        val = self._extract_value(self.DNSSEC_KEYS)
        return val.strip() if val else None

    def _extract_dnssec_keys(self) -> List[str]:
        """
        Extract raw DNSSEC key data lines from block sections.

        Handles:
          - EURid ``Keys:\\n    flags:KSK protocol:3 algorithm:RSA_SHA256\\n    pubKey:...``
          - ICANN  ``DS Data:\\n    2371 8 2\\n    4A5C...``
          - .fr    ``key1:\\n    flags: 257\\n    protocol: 3 ...``
        """
        key_data: List[str] = []
        in_block = False
        header_indent = 0

        for raw_line in self.lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith('%') or stripped.startswith('#') or stripped.startswith(';'):
                if not stripped:
                    in_block = False
                continue

            line_indent = self._line_indent(raw_line)

            if in_block:
                if line_indent > header_indent:
                    key_data.append(stripped)
                else:
                    in_block = False
                    # Fall through to check if this line is another key block header

            if not in_block and ':' in stripped:
                colon_pos = stripped.find(':')
                key = stripped[:colon_pos].strip().lower()
                val = stripped[colon_pos + 1:].strip()
                # Named key blocks (Keys:, DS Data:, DNSKEY:)
                if key in self._DNSSEC_KEY_BLOCK_HEADERS and not val:
                    in_block = True
                    header_indent = line_indent
                # Numbered key blocks: key1:, key2: etc. (no value on header line)
                elif re.match(r'^key\d+$', key) and not val:
                    in_block = True
                    header_indent = line_indent

        return key_data

    def _extract_status(self) -> List[str]:
        """Extract domain status values (standard + block-indented like .be Flags:)."""
        raw_values = self._extract_all_values(self.STATUS_KEYS)
        # Block style: Flags:\n\tclientTransferProhibited  (.be)
        raw_values.extend(self._extract_block_status_values(['flags']))
        # JP: [Status]   Active
        jp_status = self._extract_jp_all('Status')
        jp_status += self._extract_jp_all('Lock Status')
        raw_values.extend(jp_status)

        statuses = []
        for status in raw_values:
            status_clean = re.sub(r'\s+https?://.*', '', status)
            status_clean = re.sub(r'\s*\(https?://.*?\)', '', status_clean)
            status_clean = status_clean.strip()
            if status_clean:
                statuses.append(status_clean)

        return list(dict.fromkeys(statuses))

    def _extract_registrar(self) -> Dict[str, str]:
        """Extract registrar information (standard + block formats)."""
        registrar = {}

        # Registrar name — standard key: value first
        name = self._extract_value(self.REGISTRAR_KEYS)
        if name:
            registrar['registrar_name'] = name

        # Block-style registrar (EURid .eu, .be, Nominet .uk, DNS.pl .pl, .it)
        if not registrar.get('registrar_name'):
            block = self._extract_block_registrar()
            registrar.update({k: v for k, v in block.items() if v})

        # Abuse email (takes priority as the primary contact email)
        abuse_email = self._extract_value(self.ABUSE_EMAIL_KEYS)
        if abuse_email:
            registrar['email_address'] = abuse_email

        # Abuse phone
        abuse_phone = self._extract_value(self.ABUSE_PHONE_KEYS)
        if abuse_phone:
            registrar['phone_number'] = abuse_phone

        # IANA ID — exact match first, then regex fallback
        iana_id = self._extract_value(self.REGISTRAR_IANA_ID_KEYS)
        if not iana_id:
            iana_id = self._extract_value_regex([
                r'registrar\s+iana\s+id\s*:\s*(.+)',
                r'sponsoring\s+registrar\s+iana\s+id\s*:\s*(.+)',
                r'registrar\s+iana\s*:\s*(.+)',
            ])
        if iana_id:
            try:
                registrar['iana_id'] = int(iana_id.strip())
            except (ValueError, AttributeError):
                registrar['iana_id'] = iana_id

        # WHOIS server — exact match first, then regex fallback
        whois_server = self._extract_value(self.REGISTRAR_WHOIS_SERVER_KEYS)
        if not whois_server:
            whois_server = self._extract_value_regex([
                r'registrar\s+whois\s+server\s*:\s*(.+)',
                r'whois\s+server\s*:\s*(.+)',
            ])
        if whois_server:
            registrar['whois_server'] = whois_server

        # URL — exact match first, then regex fallback
        url = self._extract_value(self.REGISTRAR_URL_KEYS)
        if not url:
            url = self._extract_value_regex([
                r'registrar\s+url\s*:\s*(.+)',
                r'referral\s+url\s*:\s*(.+)',
            ])
        if url:
            registrar['website_url'] = url

        return registrar

    def _extract_contact(self, contact_type: str) -> Dict[str, str]:
        """Extract contact information (registrant, admin, tech, billing)."""
        contact = {}

        prefixes = []
        if contact_type == 'registrant':
            prefixes = ['registrant', 'holder']
        elif contact_type == 'admin':
            prefixes = ['admin', 'administrative']
        elif contact_type == 'tech':
            prefixes = ['tech', 'technical']
        elif contact_type == 'billing':
            prefixes = ['billing']

        # Common contact fields
        fields = {
            'registry_id': ['id'],
            'full_name': ['name'],
            'company_name': ['organization', 'org', 'company'],
            'email_address': ['email', 'e-mail'],
            'phone_number': ['phone', 'phone number'],
            'phone_ext': ['phone ext'],
            'fax_number': ['fax', 'fax number'],
            'fax_ext': ['fax ext'],
            'mailing_address': ['street', 'address'],
            'city_name': ['city'],
            'state_name': ['state', 'province', 'state/province'],
            'zip_code': ['postal code', 'zip'],
            'country': ['country']
        }

        for field_name, field_keys in fields.items():
            # Build full keys with prefixes
            full_keys = []
            for prefix in prefixes:
                for field_key in field_keys:
                    full_keys.append(f'{prefix} {field_key}')

            value = self._extract_value(full_keys)
            if value:
                contact[field_name] = value

        # Normalize country field into country_code and country_name
        if 'country' in contact:
            country_value = contact.pop('country')

            # Map of country codes to names (ISO 3166-1 alpha-2)
            country_map = {
                'US': 'United States', 'GB': 'United Kingdom', 'FR': 'France',
                'DE': 'Germany', 'ES': 'Spain', 'IT': 'Italy', 'NL': 'Netherlands',
                'BE': 'Belgium', 'CH': 'Switzerland', 'AT': 'Austria', 'CN': 'China',
                'JP': 'Japan', 'KR': 'South Korea', 'IN': 'India', 'AU': 'Australia',
                'CA': 'Canada', 'BR': 'Brazil', 'MX': 'Mexico', 'RU': 'Russia',
                'ZA': 'South Africa', 'SE': 'Sweden', 'DK': 'Denmark', 'NO': 'Norway',
                'FI': 'Finland', 'PL': 'Poland', 'IE': 'Ireland', 'PT': 'Portugal',
                'GR': 'Greece', 'CZ': 'Czech Republic', 'MY': 'Malaysia', 'SG': 'Singapore',
                'IS': 'Iceland', 'BI': 'Burundi', 'AE': 'United Arab Emirates',
                'AR': 'Argentina', 'BG': 'Bulgaria', 'CL': 'Chile', 'CO': 'Colombia',
                'CR': 'Costa Rica', 'HR': 'Croatia', 'CY': 'Cyprus', 'EE': 'Estonia',
                'HK': 'Hong Kong', 'HU': 'Hungary', 'ID': 'Indonesia', 'IL': 'Israel',
                'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'MT': 'Malta',
                'NZ': 'New Zealand', 'PH': 'Philippines', 'RO': 'Romania', 'SA': 'Saudi Arabia',
                'SI': 'Slovenia', 'SK': 'Slovakia', 'TH': 'Thailand', 'TR': 'Turkey',
                'TW': 'Taiwan', 'UA': 'Ukraine', 'VN': 'Vietnam'
            }

            # If it's a 2-letter code, it's country_code
            if len(country_value) == 2:
                contact['country_code'] = country_value.upper()
                contact['country_name'] = country_map.get(country_value.upper(), country_value)
            else:
                # It's a full name, try to find code
                contact['country_name'] = country_value
                # Reverse lookup
                for code, name in country_map.items():
                    if name.lower() == country_value.lower():
                        contact['country_code'] = code
                        break

        return contact

    def _detect_availability(self, raw_whois: str) -> Dict[str, Any]:
        """
        Detect domain availability status.
        Returns: {'available': True/False/None, 'reason': str}
        """
        raw_lower = raw_whois.lower()

        # Check for empty or very short response (likely connection issue or no data)
        if len(raw_whois.strip()) < 20:
            return {
                'available': None,
                'is_rate_limited': False,
                'is_service_error': False,
                'reason': 'Unknown - WHOIS response too short or empty'
            }

        # Check for rate-limit indicators FIRST — must not be interpreted as availability signals
        for indicator in self.RATE_LIMIT_INDICATORS:
            if indicator in raw_lower:
                return {
                    'available': None,
                    'is_rate_limited': True,
                    'is_service_error': False,
                    'reason': f'Rate limited - WHOIS server is throttling requests: \'{indicator}\''
                }

        # Check for service errors — server genuinely unavailable or broken
        for indicator in self.SERVICE_ERROR_INDICATORS:
            if indicator in raw_lower:
                return {
                    'available': None,
                    'is_rate_limited': False,
                    'is_service_error': True,
                    'reason': f'Service error - WHOIS server unavailable: \'{indicator}\''
                }

        # Check for explicit availability indicators
        available_count = 0
        available_matches = []
        for indicator in self.AVAILABLE_INDICATORS:
            if indicator in raw_lower:
                available_count += 1
                available_matches.append(indicator)

        # Check for registered indicators
        registered_count = 0
        registered_matches = []
        for indicator in self.REGISTERED_INDICATORS:
            if indicator in raw_lower:
                registered_count += 1
                registered_matches.append(indicator)

        # Strong indicators for registered domains
        has_creation_date = self.parsed_data.get('create_date') is not None
        has_expiry_date = self.parsed_data.get('expiry_date') is not None
        has_registrar = bool((self.parsed_data.get('registrar') or {}).get('registrar_name'))
        has_nameservers = len(self.parsed_data.get('name_servers', [])) > 0
        has_domain_status = len(self.parsed_data.get('domain_status', [])) > 0

        strong_registered_count = sum([has_creation_date, has_expiry_date, has_registrar, has_nameservers, has_domain_status])

        # Decision logic with higher confidence thresholds

        # Special case: Reserved/Blocked/Premium domains (VERY STRONG indicator of unavailability)
        reserved_match = next(
            (ind for ind in self.RESERVED_INDICATORS if ind in raw_lower), None
        )
        if reserved_match:
            return {
                'available': False,
                'reason': f'Domain is reserved, blocked, or premium - not available for public registration ({reserved_match})'
            }

        # Special case: Hold statuses (registered but delegations suspended)
        in_hold = any(ind in raw_lower for ind in self.HOLD_INDICATORS)
        if in_hold:
            matched = next(ind for ind in self.HOLD_INDICATORS if ind in raw_lower)
            return {
                'available': False,
                'reason': f'Domain is on hold ({matched}) - still registered',
            }

        # Special case: Grace period (auto-renew) — still registered
        in_grace = any(ind in raw_lower for ind in self.GRACE_INDICATORS)
        if in_grace:
            matched = next(ind for ind in self.GRACE_INDICATORS if ind in raw_lower)
            return {
                'available': False,
                'reason': f'Domain is in auto-renew grace period ({matched}) - still registered',
            }

        # Special case: Pending delete — still not publicly registrable
        in_pending_delete = any(ind in raw_lower for ind in self.PENDING_DELETE_INDICATORS)
        if in_pending_delete:
            statuses_lower = [s.lower() for s in self.parsed_data.get('domain_status', [])]
            in_status = any(
                ind in s for s in statuses_lower for ind in self.PENDING_DELETE_INDICATORS
            )
            if in_pending_delete or in_status:
                matched = next(ind for ind in self.PENDING_DELETE_INDICATORS if ind in raw_lower)
                return {
                    'available': False,
                    'reason': f'Domain is in pending-delete period ({matched}) - not yet released',
                }

        # Strong confidence: Available
        if available_count >= 2 and registered_count == 0 and strong_registered_count == 0:
            return {
                'available': True,
                'reason': f"Domain is available - found {available_count} availability indicators"
            }

        # Strong confidence: Registered
        # BUT: Check if domain is expired first!
        if strong_registered_count >= 2:
            # Check if expiry date is in the past
            if has_expiry_date:
                expiry_str = self.parsed_data.get('expiry_date', '')
                if expiry_str:
                    try:
                        # Try to parse the expiry date
                        from datetime import datetime
                        # Try different date formats
                        for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ', '%d-%m-%Y']:
                            try:
                                expiry_dt = datetime.strptime(expiry_str.split('T')[0], '%Y-%m-%d')
                                now = datetime.now()
                                if expiry_dt < now:
                                    # Check if domain is in a deletion grace period
                                    # (redemption / pending delete → still registered)
                                    statuses_lower = [
                                        s.lower() for s in self.parsed_data.get('domain_status', [])
                                    ]
                                    in_redemption = any(
                                        ind in s
                                        for s in statuses_lower
                                        for ind in self.REDEMPTION_INDICATORS
                                    ) or any(
                                        ind in raw_lower for ind in self.REDEMPTION_INDICATORS
                                    )
                                    if in_redemption:
                                        return {
                                            'available': False,
                                            'reason': 'Domain is in redemption period - registrant can still renew',
                                        }
                                    return {
                                        'available': None,
                                        'reason': f'Domain expired on {expiry_str} - status unknown',
                                    }
                                break
                            except:
                                continue
                    except:
                        pass  # If we can't parse the date, continue with normal logic

            return {
                'available': False,
                'reason': 'Domain is registered - has creation/expiry dates, registrar info, nameservers, or domain status'
            }

        # A creation or expiry date alone (with no availability indicators) is definitive proof
        # of registration. Handles minimalist WHOIS servers like IANA that return only a few lines.
        if (has_creation_date or has_expiry_date) and available_count == 0:
            return {
                'available': False,
                'reason': 'Domain is registered - has creation/expiry date with no availability indicators'
            }

        # Strong confidence: Available (single strong indicator)
        if available_count > 0 and registered_count == 0 and strong_registered_count == 0:
            return {
                'available': True,
                'reason': f"Domain appears available - found indicator: '{available_matches[0]}'"
            }

        # Strong confidence: Registered (many indicators)
        if registered_count >= 5 and available_count == 0:
            return {
                'available': False,
                'reason': f'Domain is registered - found {registered_count} registration indicators'
            }

        # Medium confidence: Registered
        if registered_count >= 3 and registered_count > available_count * 2:
            return {
                'available': False,
                'reason': f'Domain likely registered ({registered_count} indicators vs {available_count})'
            }

        # Medium confidence: Available
        if available_count >= 2 and available_count > registered_count * 2:
            return {
                'available': True,
                'reason': f'Domain likely available ({available_count} indicators vs {registered_count})'
            }

        # Low confidence or conflicting signals - return unknown
        return {
            'available': None,
            'reason': f'Unknown - conflicting or insufficient indicators (available:{available_count}, registered:{registered_count})'
        }


def parse_whois(raw_whois: str) -> Dict[str, Any]:
    """Parse raw WHOIS response and return structured data."""
    parser = WhoisParser()
    return parser.parse(raw_whois)
