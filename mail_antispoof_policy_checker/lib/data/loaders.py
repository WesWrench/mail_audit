"""Data loaders for CSV files containing dangerous SPF records and third-party services"""

import csv
import os
from typing import List, Dict, Set, Any, Optional
from dataclasses import dataclass
import dns.resolver
from ..models.issue import IssueSeverity


@dataclass
class DangerousSPFInclude:
    """Represents a dangerous SPF include entry"""
    include: str
    service_type: str  # Changed from Enum to string (e.g., "Shared Hosting", "Marketing Service", etc.)
    service_name: str
    dangerous: bool = True


@dataclass
class WhitelistedSPFInclude:
    """
    Represents a whitelisted (non-dangerous) SPF include entry.

    Acts as a recursion guard: when a dangerous include's SPF tree points to a
    whitelisted include, the sub-tree is NOT explored and its IPs are NOT
    attributed to the dangerous service.

    Example: spf.infomaniak.ch -> newsletter.infomaniak.com -> amazonses.com.
    Without the guard, every AWS SES range would be flagged as "Infomaniak".
    """
    include: str
    service_type: str
    service_name: str
    dangerous: bool = False


@dataclass
class DangerousSPFIPRange:
    """Represents a dangerous SPF IP range entry"""
    ip_range: str
    service_type: str  # Changed from Enum to string
    service_name: str
    dangerous: bool = True
    source_include: str = None  # If this IP was extracted from a dangerous include, store the include domain


@dataclass
class WhitelistedSPFIPRange:
    """
    Represents an IP range belonging to a whitelisted platform.

    Resolved recursively from Whitelisted_SPF_Include.csv, exactly like the
    dangerous side. Acts as an exception: an IP inside one of these ranges is
    not attributed to a dangerous service.

    Precedence: anything explicitly declared dangerous wins. Ranges overlapping
    Dangerous_SPF_Records_IP_Range.csv are dropped at load time, and dangerous
    sub-includes are pruned during the walk, so this list can never neutralise
    a declared classification.
    """
    ip_range: str
    service_type: str
    service_name: str
    dangerous: bool = False
    source_include: str = None  # Whitelisted include the range was resolved from


@dataclass
class ThirdPartyService:
    """Represents a third-party service by AS organization"""
    as_organization: str
    service_type: str  # Changed from Enum to string
    service_name: str
    dangerous: bool = True


@dataclass
class ServiceTypeSeverityConfig:
    """Severity configuration for a service type"""
    service_type: str
    severity: str  # "high", "critical", etc.


@dataclass
class ServiceNameSeverityConfig:
    """Severity configuration for a specific service name"""
    service_name: str
    severity: str  # "high", "critical", etc.


@dataclass
class DangerousPTRDomain:
    """Represents a dangerous PTR domain (only stores most specific domains, no hierarchy expansion)"""
    ptr_domain: str
    service_type: str
    service_name: str
    dangerous: bool = True


class DataLoaders:
    """Loaders for CSV data files containing dangerous SPF configurations"""

    def __init__(self, data_dir: str = "./data", disable_ptr_blacklist: bool = False, disable_update_ptr_blacklist: bool = False, ptr_pool_size: int = 20, nameservers: Optional[List[str]] = None, dns_timeout: int = 10):
        """
        Initialize data loaders.

        Args:
            data_dir: Directory containing CSV data files
            disable_ptr_blacklist: If True, skip loading/building PTR blacklist from IPs (default: False = enabled)
            disable_update_ptr_blacklist: If True, skip updating PTR blacklist even if enabled (default: False = update on first run)
            ptr_pool_size: Number of parallel PTR lookups when building blacklist
            nameservers: Custom DNS resolver(s) as a list of IPs (e.g., ['1.1.1.1', '8.8.8.8']). If None, uses system default
            dns_timeout: DNS query timeout in seconds (default: 10)

        Note:
            PTR extraction from dangerous includes SPF records is ALWAYS enabled (fast, no DNS lookups).
            These flags only control the expensive reverse DNS lookups on dangerous IPs.
        """
        self.data_dir = data_dir
        self.use_ptr_blacklist = not disable_ptr_blacklist  # Enabled by default
        self.update_ptr_blacklist = not disable_update_ptr_blacklist  # Enabled by default
        self.ptr_pool_size = ptr_pool_size
        self.nameservers = list(nameservers) if nameservers else None
        self.dns_timeout = dns_timeout
        self._dangerous_includes: List[DangerousSPFInclude] = []
        self._whitelisted_includes: List[WhitelistedSPFInclude] = []
        self._whitelisted_include_set: Set[str] = set()  # lowercase include domains
        self._whitelisted_ip_ranges: List[WhitelistedSPFIPRange] = []
        self._whitelisted_networks: List[Any] = []  # parsed ip_network cache for fast lookups
        self._pruned_includes: Dict[str, Set[str]] = {}  # root dangerous include -> pruned sub-includes
        self._dangerous_in_whitelist_tree: Dict[str, Set[str]] = {}  # whitelisted root -> dangerous sub-includes pruned
        self._whitelist_conflicts: List[tuple] = []  # (whitelisted_range, declared_dangerous_range) dropped
        self._dangerous_ip_ranges: List[DangerousSPFIPRange] = []
        self._third_party_services: List[ThirdPartyService] = []
        self._dangerous_ptr_domains: List[DangerousPTRDomain] = []
        self._service_type_severity: Dict[str, str] = {}  # service_type -> severity
        self._service_name_severity: Dict[str, str] = {}  # service_name -> severity
        self._loaded = False

    def load_all(self, load_all_entries: bool = False, resolve_includes: bool = True):
        """
        Load all CSV data files.

        Args:
            load_all_entries: If True, load all entries including non-dangerous ones
            resolve_includes: If True, recursively resolve includes (both trees) to extract IPs

        Order matters. The whitelist tree is resolved *before* the dangerous tree,
        and both are resolved against the CSV-declared data only:

            1. severity configs
            2. declared includes (dangerous + whitelist) and declared IP ranges
            3. whitelist tree  -> whitelisted IP ranges, pruned on declared dangerous includes,
                                  then purged of anything overlapping a declared dangerous range
            4. dangerous tree  -> dangerous IP ranges, pruned on declared whitelisted includes
            5. PTR blacklist   -> skips IPs and PTR domains covered by the whitelist

        Resolving the whitelist first means step 4 and 5 can use it, while the
        whitelist itself only ever sees human-declared dangerous data — never IPs
        inherited through an include chain. That is what keeps the precedence rule
        (declared dangerous > whitelist) free of ordering ambiguity.
        """
        # Load severity configurations first
        self.load_service_type_severity_config()
        self.load_service_name_severity_config()

        # Load the include whitelist before anything that resolves includes:
        # it prunes the recursive SPF walk (see _extract_ips_from_spf_domain)
        self.load_whitelisted_includes()

        # Load dangerous data
        self.load_dangerous_includes(load_all_entries=load_all_entries)
        self.load_dangerous_ip_ranges(load_all_entries=load_all_entries)
        self.load_third_party_services(load_all_entries=load_all_entries)

        # Resolve the whitelist tree FIRST (see ordering note above)
        if resolve_includes and self._whitelisted_includes:
            self._resolve_whitelisted_includes()

        # Resolve dangerous includes to extract IP ranges AND PTR domains
        # This ALWAYS runs to extract PTR from includes (e.g., mx.ovh.com → mail-out.ovh.net)
        if resolve_includes and self._dangerous_includes:
            resolved_ips = self._resolve_dangerous_includes()
            # Add resolved IPs to dangerous_ip_ranges
            self._dangerous_ip_ranges.extend(resolved_ips)

        # PTR blacklist management (only if enabled)
        if self.use_ptr_blacklist:
            # Try to load existing CSV
            ptr_csv_exists = self._load_ptr_blacklist_from_csv()

            # Build from IPs if: forced update OR CSV doesn't exist
            if self.update_ptr_blacklist or not ptr_csv_exists:
                self._build_ptr_blacklist_from_dangerous_ips()

                # Save to CSV after building
                self._save_ptr_blacklist_to_csv()

        self._loaded = True

        # Print summary
        self._print_load_summary()

    def load_dangerous_includes(self, load_all_entries: bool = False) -> List[DangerousSPFInclude]:
        """
        Load dangerous SPF includes from CSV file.

        Args:
            load_all_entries: If True, load all entries including non-dangerous ones

        Returns:
            List of DangerousSPFInclude objects

        Raises:
            ValueError: If CSV file has invalid format or missing required columns
        """
        csv_path = os.path.join(self.data_dir, "Dangerous_SPF_Include.csv")
        self._dangerous_includes = []

        if not os.path.exists(csv_path):
            return self._dangerous_includes

        required_columns = {'include', 'service_type', 'service_name', 'dangerous'}
        valid_dangerous_values = {'yes', 'no', 'n/d'}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')

            # Validate headers
            if not reader.fieldnames:
                raise ValueError(f"[{csv_path}] CSV file has no headers")

            missing_columns = required_columns - set(reader.fieldnames)
            if missing_columns:
                raise ValueError(
                    f"[{csv_path}] Missing required columns: {', '.join(missing_columns)}\n"
                    f"Expected columns: include;service_type;service_name;dangerous"
                )

            for line_num, row in enumerate(reader, start=2):  # Start at 2 (header is line 1)
                # Check for None values (missing columns in row)
                if None in row.values():
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Row has missing columns\n"
                        f"Expected 4 columns (include;service_type;service_name;dangerous)\n"
                        f"Got: {list(row.values())}"
                    )

                # Validate required fields are not empty
                include = row.get('include', '').strip()
                service_type_str = row.get('service_type', '').strip()
                service_name = row.get('service_name', '').strip()
                dangerous_str = row.get('dangerous', '').strip()

                if not include:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'include' column is empty"
                    )

                if not service_type_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_type' column is empty\n"
                        f"Include: {include}"
                    )

                if not service_name:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_name' column is empty\n"
                        f"Include: {include}"
                    )

                if not dangerous_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'dangerous' column is empty\n"
                        f"Include: {include}\n"
                        f"Valid values: Yes, No, N/D"
                    )

                # Validate dangerous column value
                dangerous_lower = dangerous_str.lower()
                if dangerous_lower not in valid_dangerous_values:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Invalid 'dangerous' value: '{dangerous_str}'\n"
                        f"Include: {include}\n"
                        f"Valid values: Yes, No, N/D (got: '{dangerous_str}')"
                    )

                # service_type can be any arbitrary value (Marketing Service, Cloud Service, etc.)
                dangerous = dangerous_lower == 'yes'

                # Skip non-dangerous entries unless load_all_entries is True
                if not load_all_entries and not dangerous:
                    continue

                self._dangerous_includes.append(DangerousSPFInclude(
                    include=include,
                    service_type=service_type_str,  # Store as string directly
                    service_name=service_name,
                    dangerous=dangerous
                ))

        return self._dangerous_includes

    def load_whitelisted_includes(self) -> List[WhitelistedSPFInclude]:
        """
        Load whitelisted (explicitly non-dangerous) SPF includes from CSV file.

        Same format as Dangerous_SPF_Include.csv, but every row must have
        dangerous=No. These includes act as a recursion guard: when the SPF tree
        of a dangerous include points to one of them, the sub-tree is not walked
        and its IPs are not attributed to the dangerous service.

        Returns:
            List of WhitelistedSPFInclude objects

        Raises:
            ValueError: If CSV file has invalid format or missing required columns
        """
        csv_path = os.path.join(self.data_dir, "Whitelisted_SPF_Include.csv")
        self._whitelisted_includes = []
        self._whitelisted_include_set = set()

        if not os.path.exists(csv_path):
            return self._whitelisted_includes

        required_columns = {'include', 'service_type', 'service_name', 'dangerous'}
        valid_dangerous_values = {'no', 'n/d'}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')

            # Validate headers
            if not reader.fieldnames:
                raise ValueError(f"[{csv_path}] CSV file has no headers")

            missing_columns = required_columns - set(reader.fieldnames)
            if missing_columns:
                raise ValueError(
                    f"[{csv_path}] Missing required columns: {', '.join(missing_columns)}\n"
                    f"Expected columns: include;service_type;service_name;dangerous"
                )

            for line_num, row in enumerate(reader, start=2):  # Start at 2 (header is line 1)
                # Check for None values (missing columns in row)
                if None in row.values():
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Row has missing columns\n"
                        f"Expected 4 columns (include;service_type;service_name;dangerous)\n"
                        f"Got: {list(row.values())}"
                    )

                include = row.get('include', '').strip()
                service_type_str = row.get('service_type', '').strip()
                service_name = row.get('service_name', '').strip()
                dangerous_str = row.get('dangerous', '').strip()

                if not include:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'include' column is empty"
                    )

                if not service_type_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_type' column is empty\n"
                        f"Include: {include}"
                    )

                if not service_name:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_name' column is empty\n"
                        f"Include: {include}"
                    )

                if not dangerous_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'dangerous' column is empty\n"
                        f"Include: {include}\n"
                        f"Valid values: No, N/D"
                    )

                # This file is a whitelist: a 'Yes' here contradicts its purpose
                # and is almost certainly a copy/paste from Dangerous_SPF_Include.csv.
                dangerous_lower = dangerous_str.lower()
                if dangerous_lower not in valid_dangerous_values:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Invalid 'dangerous' value: '{dangerous_str}'\n"
                        f"Include: {include}\n"
                        f"This file is a whitelist: valid values are No, N/D (got: '{dangerous_str}').\n"
                        f"Dangerous includes belong in Dangerous_SPF_Include.csv."
                    )

                self._whitelisted_includes.append(WhitelistedSPFInclude(
                    include=include,
                    service_type=service_type_str,
                    service_name=service_name,
                    dangerous=False
                ))
                self._whitelisted_include_set.add(include.lower())

        return self._whitelisted_includes

    def is_whitelisted_include(self, include: str) -> bool:
        """
        Check whether an include domain is whitelisted (explicitly non-dangerous).

        Args:
            include: Include domain to test (case-insensitive)

        Returns:
            True if the domain is present in Whitelisted_SPF_Include.csv
        """
        if not include:
            return False
        return include.strip().lower().rstrip('.') in self._whitelisted_include_set

    def find_whitelisted_include(self, include: str) -> List[WhitelistedSPFInclude]:
        """
        Find whitelisted include entries matching a given include domain.

        Args:
            include: Include domain to search for

        Returns:
            List of matching WhitelistedSPFInclude objects
        """
        return [item for item in self._whitelisted_includes if item.include.lower() == include.lower()]

    def load_dangerous_ip_ranges(self, load_all_entries: bool = False) -> List[DangerousSPFIPRange]:
        """
        Load dangerous SPF IP ranges from CSV file.

        Args:
            load_all_entries: If True, load all entries including non-dangerous ones

        Returns:
            List of DangerousSPFIPRange objects

        Raises:
            ValueError: If CSV file has invalid format or missing required columns
        """
        csv_path = os.path.join(self.data_dir, "Dangerous_SPF_Records_IP_Range.csv")
        self._dangerous_ip_ranges = []

        if not os.path.exists(csv_path):
            return self._dangerous_ip_ranges

        required_columns = {'spf include', 'service_type', 'service_name', 'dangerous'}
        valid_dangerous_values = {'yes', 'no', 'n/d'}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')

            # Validate headers
            if not reader.fieldnames:
                raise ValueError(f"[{csv_path}] CSV file has no headers")

            missing_columns = required_columns - set(reader.fieldnames)
            if missing_columns:
                raise ValueError(
                    f"[{csv_path}] Missing required columns: {', '.join(missing_columns)}\n"
                    f"Expected columns: spf include;service_type;service_name;dangerous"
                )

            for line_num, row in enumerate(reader, start=2):  # Start at 2 (header is line 1)
                # Check for None values (missing columns in row)
                if None in row.values():
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Row has missing columns\n"
                        f"Expected 4 columns (spf include;service_type;service_name;dangerous)\n"
                        f"Got: {list(row.values())}"
                    )

                # Validate required fields are not empty
                ip_range = row.get('spf include', '').strip()
                service_type_str = row.get('service_type', '').strip()
                service_name = row.get('service_name', '').strip()
                dangerous_str = row.get('dangerous', '').strip()

                if not ip_range:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'spf include' column is empty"
                    )

                if not service_type_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_type' column is empty\n"
                        f"IP Range: {ip_range}"
                    )

                if not service_name:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_name' column is empty\n"
                        f"IP Range: {ip_range}"
                    )

                if not dangerous_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'dangerous' column is empty\n"
                        f"IP Range: {ip_range}\n"
                        f"Valid values: Yes, No, N/D"
                    )

                # Validate dangerous column value
                dangerous_lower = dangerous_str.lower()
                if dangerous_lower not in valid_dangerous_values:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Invalid 'dangerous' value: '{dangerous_str}'\n"
                        f"IP Range: {ip_range}\n"
                        f"Valid values: Yes, No, N/D (got: '{dangerous_str}')"
                    )

                # service_type can be any arbitrary value
                dangerous = dangerous_lower == 'yes'

                # Skip non-dangerous entries unless load_all_entries is True
                if not load_all_entries and not dangerous:
                    continue

                self._dangerous_ip_ranges.append(DangerousSPFIPRange(
                    ip_range=ip_range,
                    service_type=service_type_str,  # Store as string directly
                    service_name=service_name,
                    dangerous=dangerous
                ))

        return self._dangerous_ip_ranges

    def load_third_party_services(self, load_all_entries: bool = False) -> List[ThirdPartyService]:
        """
        Load third-party service AS organizations from CSV file.

        Args:
            load_all_entries: If True, load all entries including non-dangerous ones

        Returns:
            List of ThirdPartyService objects

        Raises:
            ValueError: If CSV file has invalid format or missing required columns
        """
        csv_path = os.path.join(self.data_dir, "Dangerous_AS_Organization.csv")
        self._third_party_services = []

        if not os.path.exists(csv_path):
            return self._third_party_services

        required_columns = {'include', 'service_type', 'service_name', 'dangerous'}
        valid_dangerous_values = {'yes', 'no', 'n/d'}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')

            # Validate headers
            if not reader.fieldnames:
                raise ValueError(f"[{csv_path}] CSV file has no headers")

            missing_columns = required_columns - set(reader.fieldnames)
            if missing_columns:
                raise ValueError(
                    f"[{csv_path}] Missing required columns: {', '.join(missing_columns)}\n"
                    f"Expected columns: include;service_type;service_name;dangerous"
                )

            for line_num, row in enumerate(reader, start=2):  # Start at 2 (header is line 1)
                # Check for None values (missing columns in row)
                if None in row.values():
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Row has missing columns\n"
                        f"Expected 4 columns (include;service_type;service_name;dangerous)\n"
                        f"Got: {list(row.values())}"
                    )

                # Validate required fields are not empty
                as_org = row.get('include', '').strip()
                service_type_str = row.get('service_type', '').strip()
                service_name = row.get('service_name', '').strip()
                dangerous_str = row.get('dangerous', '').strip()

                if not as_org:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'include' column is empty"
                    )

                if not service_type_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_type' column is empty\n"
                        f"AS Organization: {as_org}"
                    )

                if not service_name:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_name' column is empty\n"
                        f"AS Organization: {as_org}"
                    )

                if not dangerous_str:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'dangerous' column is empty\n"
                        f"AS Organization: {as_org}\n"
                        f"Valid values: Yes, No, N/D"
                    )

                # Validate dangerous column value
                dangerous_lower = dangerous_str.lower()
                if dangerous_lower not in valid_dangerous_values:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Invalid 'dangerous' value: '{dangerous_str}'\n"
                        f"AS Organization: {as_org}\n"
                        f"Valid values: Yes, No, N/D (got: '{dangerous_str}')"
                    )

                # service_type can be any arbitrary value
                dangerous = dangerous_lower == 'yes'

                # Skip non-dangerous entries unless load_all_entries is True
                if not load_all_entries and not dangerous:
                    continue

                self._third_party_services.append(ThirdPartyService(
                    as_organization=as_org,
                    service_type=service_type_str,  # Store as string directly
                    service_name=service_name,
                    dangerous=dangerous
                ))

        return self._third_party_services

    def load_service_type_severity_config(self) -> Dict[str, str]:
        """
        Load service type severity configuration from CSV file.

        Returns:
            Dictionary mapping service_type to severity level

        Raises:
            ValueError: If CSV file has invalid format or missing required columns
        """
        csv_path = os.path.join(self.data_dir, "Service_Type_Severity_Config.csv")
        self._service_type_severity = {}

        if not os.path.exists(csv_path):
            return self._service_type_severity

        required_columns = {'service_type', 'severity'}
        valid_severity_values = {'low', 'medium', 'high', 'critical'}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')

            # Validate headers
            if not reader.fieldnames:
                raise ValueError(f"[{csv_path}] CSV file has no headers")

            missing_columns = required_columns - set(reader.fieldnames)
            if missing_columns:
                raise ValueError(
                    f"[{csv_path}] Missing required columns: {', '.join(missing_columns)}\n"
                    f"Expected columns: service_type;severity"
                )

            for line_num, row in enumerate(reader, start=2):
                # Check for None values (missing columns in row)
                if None in row.values():
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Row has missing columns\n"
                        f"Expected 2 columns (service_type;severity)\n"
                        f"Got: {list(row.values())}"
                    )

                # Validate required fields are not empty
                service_type = row.get('service_type', '').strip()
                severity = row.get('severity', '').strip()

                if not service_type:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_type' column is empty"
                    )

                if not severity:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'severity' column is empty\n"
                        f"Service Type: {service_type}\n"
                        f"Valid values: low, medium, high, critical"
                    )

                # Validate severity value
                severity_lower = severity.lower()
                if severity_lower not in valid_severity_values:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Invalid 'severity' value: '{severity}'\n"
                        f"Service Type: {service_type}\n"
                        f"Valid values: low, medium, high, critical (got: '{severity}')"
                    )

                self._service_type_severity[service_type] = severity_lower

        return self._service_type_severity

    def load_service_name_severity_config(self) -> Dict[str, str]:
        """
        Load service name severity configuration from CSV file.

        Returns:
            Dictionary mapping service_name to severity level

        Raises:
            ValueError: If CSV file has invalid format or missing required columns
        """
        csv_path = os.path.join(self.data_dir, "Service_Name_Severity_Config.csv")
        self._service_name_severity = {}

        if not os.path.exists(csv_path):
            return self._service_name_severity

        required_columns = {'service_name', 'severity'}
        valid_severity_values = {'low', 'medium', 'high', 'critical'}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')

            # Validate headers
            if not reader.fieldnames:
                raise ValueError(f"[{csv_path}] CSV file has no headers")

            missing_columns = required_columns - set(reader.fieldnames)
            if missing_columns:
                raise ValueError(
                    f"[{csv_path}] Missing required columns: {', '.join(missing_columns)}\n"
                    f"Expected columns: service_name;severity"
                )

            for line_num, row in enumerate(reader, start=2):
                # Check for None values (missing columns in row)
                if None in row.values():
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Row has missing columns\n"
                        f"Expected 2 columns (service_name;severity)\n"
                        f"Got: {list(row.values())}"
                    )

                # Validate required fields are not empty
                service_name = row.get('service_name', '').strip()
                severity = row.get('severity', '').strip()

                if not service_name:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'service_name' column is empty"
                    )

                if not severity:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: 'severity' column is empty\n"
                        f"Service Name: {service_name}\n"
                        f"Valid values: low, medium, high, critical"
                    )

                # Validate severity value
                severity_lower = severity.lower()
                if severity_lower not in valid_severity_values:
                    raise ValueError(
                        f"[{csv_path}] Line {line_num}: Invalid 'severity' value: '{severity}'\n"
                        f"Service Name: {service_name}\n"
                        f"Valid values: low, medium, high, critical (got: '{severity}')"
                    )

                self._service_name_severity[service_name] = severity_lower

        return self._service_name_severity

    @staticmethod
    def _severity_str_to_enum(severity_str: str) -> IssueSeverity:
        """
        Convert severity string to IssueSeverity enum.

        Args:
            severity_str: Severity string ("low", "medium", "high", "critical")

        Returns:
            IssueSeverity enum value
        """
        severity_map = {
            'low': IssueSeverity.LOW,
            'medium': IssueSeverity.MEDIUM,
            'high': IssueSeverity.HIGH,
            'critical': IssueSeverity.CRITICAL
        }
        return severity_map.get(severity_str.lower(), IssueSeverity.HIGH)

    def get_severity_for_service(self, service_type: str, service_name: str, base_severity: IssueSeverity) -> IssueSeverity:
        """
        Get the appropriate severity level for a service based on the cascade:
        Service Name > Service Type > Base Severity

        Args:
            service_type: Type of service (e.g., "Shared Hosting", "Marketing Service")
            service_name: Name of service (e.g., "SendGrid", "Sarbacane")
                         May include a "(from ...)" suffix when resolved from includes.
            base_severity: Base severity level (IssueSeverity enum)

        Returns:
            Final severity level to use (IssueSeverity enum)
        """
        # Priority 1: Service Name (most specific) — case-insensitive
        # service_name may have a "(from ...)" suffix (e.g. "SendGrid (from sendgrid.net)")
        # so we also try matching against the base name without that suffix.
        candidates = [service_name]
        if ' (' in service_name:
            candidates.append(service_name.split(' (')[0].strip())

        service_name_lower_map = {k.lower(): v for k, v in self._service_name_severity.items()}
        for candidate in candidates:
            match = service_name_lower_map.get(candidate.lower())
            if match is not None:
                return self._severity_str_to_enum(match)

        # Priority 2: Service Type (case-insensitive)
        service_type_lower_map = {k.lower(): v for k, v in self._service_type_severity.items()}
        match = service_type_lower_map.get(service_type.lower())
        if match is not None:
            return self._severity_str_to_enum(match)

        # Priority 3: Base severity (least specific)
        return base_severity

    def _resolve_dangerous_includes(self) -> List[DangerousSPFIPRange]:
        """
        Recursively resolve dangerous includes to extract IP ranges.
        Only resolves includes marked as dangerous=True.

        Resolves the following SPF mechanisms, following include: chains recursively:
        - ip4: / ip6: (direct IP addresses)
        - include: (followed recursively, up to MAX_DEPTH)
        - a / a:domain (A/AAAA record resolution)
        - mx / mx:domain (MX record resolution, then A/AAAA)

        Deduplicates IPs and removes redundant ranges (e.g., 1.2.3.4/32 if 1.2.3.0/24 exists).

        Returns:
            List of DangerousSPFIPRange objects extracted from includes
        """
        resolved_ranges = []
        self._pruned_includes = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout

        # Use custom DNS server if specified
        if self.nameservers:
            resolver.nameservers = list(self.nameservers)

        for include_entry in self._dangerous_includes:
            # Only resolve dangerous includes
            if not include_entry.dangerous:
                continue

            # Track IPs and PTR domains seen for this include to avoid duplicates
            seen_ips_for_include: Set[str] = set()

            # Recursively extract all IP ranges from the include's SPF tree
            self._extract_ips_from_spf_domain(
                domain=include_entry.include,
                root_domain=include_entry.include,
                include_entry=include_entry,
                resolver=resolver,
                resolved_ranges=resolved_ranges,
                seen_ips=seen_ips_for_include,
                visited=set(),
                depth=0
            )

        # Drop anything sitting inside whitelisted space. The include: guard already
        # prunes whitelisted sub-includes, but a dangerous service can also inline a
        # shared platform's IPs directly (ip4:/a:/mx: on SES-hosted addresses).
        # Without this, those IPs would still be attributed to the dangerous service.
        filtered = []
        for entry in resolved_ranges:
            if self.is_whitelisted_ip_range(entry.ip_range):
                self._pruned_includes.setdefault(entry.source_include, set()).add(entry.ip_range)
                continue
            filtered.append(entry)

        # Deduplicate and remove redundant ranges across all includes
        return self._deduplicate_ip_ranges(filtered)

    def _resolve_whitelisted_includes(self) -> List[WhitelistedSPFIPRange]:
        """
        Recursively resolve whitelisted includes to extract their IP ranges.

        Mirrors _resolve_dangerous_includes(): same SPF mechanisms (ip4/ip6/a/mx,
        include: followed recursively up to MAX_DEPTH), same deduplication.

        Two safety nets stop a whitelist entry from ever neutralising a declared
        dangerous classification:

        1. During the walk, any sub-include listed in Dangerous_SPF_Include.csv is
           pruned (handled in _extract_ips_from_spf_domain, whitelist_mode=True).
           Whitelisting a platform therefore cannot whitelist a dangerous service
           that platform happens to include.
        2. After the walk, any resolved range overlapping a range declared in
           Dangerous_SPF_Records_IP_Range.csv is dropped.

        Both are recorded (_dangerous_in_whitelist_tree, _whitelist_conflicts) and
        reported in the load summary, so a whitelist entry that turns out to be too
        broad is visible rather than silent.

        Returns:
            List of WhitelistedSPFIPRange objects (also stored on the instance)
        """
        import ipaddress

        resolved_ranges: List[WhitelistedSPFIPRange] = []
        self._dangerous_in_whitelist_tree = {}
        self._whitelist_conflicts = []

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        if self.nameservers:
            resolver.nameservers = list(self.nameservers)

        for entry in self._whitelisted_includes:
            self._extract_ips_from_spf_domain(
                domain=entry.include,
                root_domain=entry.include,
                include_entry=entry,
                resolver=resolver,
                resolved_ranges=resolved_ranges,
                seen_ips=set(),
                visited=set(),
                depth=0,
                whitelist_mode=True
            )

        resolved_ranges = self._deduplicate_ip_ranges(resolved_ranges)

        # Safety net 2: declared dangerous ranges win over the whitelist.
        # Only ranges declared in the CSV are considered here — include-derived
        # dangerous ranges are not yet resolved at this point, by design.
        declared_dangerous = []
        for entry in self._dangerous_ip_ranges:
            try:
                declared_dangerous.append((entry, ipaddress.ip_network(entry.ip_range, strict=False)))
            except ValueError:
                continue

        kept: List[WhitelistedSPFIPRange] = []
        for wl in resolved_ranges:
            try:
                wl_net = ipaddress.ip_network(wl.ip_range, strict=False)
            except ValueError:
                continue

            conflict = None
            for dangerous_entry, dangerous_net in declared_dangerous:
                if wl_net.version == dangerous_net.version and wl_net.overlaps(dangerous_net):
                    conflict = dangerous_entry
                    break

            if conflict:
                self._whitelist_conflicts.append((wl, conflict))
            else:
                kept.append(wl)

        self._whitelisted_ip_ranges = kept
        self._whitelisted_networks = []
        for wl in kept:
            try:
                self._whitelisted_networks.append(ipaddress.ip_network(wl.ip_range, strict=False))
            except ValueError:
                continue

        return self._whitelisted_ip_ranges

    def is_whitelisted_ip(self, ip: str) -> bool:
        """
        Check whether a single IP address falls inside a whitelisted platform's space.

        Args:
            ip: IP address (IPv4 or IPv6), without prefix

        Returns:
            True if the IP is covered by a whitelisted range
        """
        import ipaddress

        if not ip or not self._whitelisted_networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == net.version and addr in net for net in self._whitelisted_networks)

    def is_whitelisted_ip_range(self, ip_range: str) -> bool:
        """
        Check whether an IP range is fully contained in a whitelisted platform's space.

        Containment (not overlap) is required on purpose: a range that merely clips a
        whitelisted network still exposes addresses outside it, and must stay checkable.

        Args:
            ip_range: IP address or CIDR range

        Returns:
            True if the whole range is covered by a single whitelisted range
        """
        import ipaddress

        if not ip_range or not self._whitelisted_networks:
            return False
        try:
            net = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return False
        return any(net.version == wl.version and net.subnet_of(wl) for wl in self._whitelisted_networks)

    def find_whitelisted_ip_range(self, ip_range: str) -> Optional[WhitelistedSPFIPRange]:
        """
        Return the whitelist entry covering an IP range, if any.

        Args:
            ip_range: IP address or CIDR range

        Returns:
            The matching WhitelistedSPFIPRange, or None
        """
        import ipaddress

        if not ip_range:
            return None
        try:
            net = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return None
        for wl in self._whitelisted_ip_ranges:
            try:
                wl_net = ipaddress.ip_network(wl.ip_range, strict=False)
            except ValueError:
                continue
            if net.version == wl_net.version and net.subnet_of(wl_net):
                return wl
        return None

    def is_whitelisted_ptr(self, ptr_domain: str) -> bool:
        """
        Check whether a PTR domain belongs to a whitelisted platform.

        Matches the PTR against whitelisted include domains by suffix, which is how
        shared platforms name their outbound hosts
        (e.g. a192-1.smtp-out.amazonses.com -> amazonses.com).

        Args:
            ptr_domain: PTR hostname

        Returns:
            True if the PTR belongs to a whitelisted platform
        """
        if not ptr_domain:
            return False
        d = ptr_domain.strip().lower().rstrip('.')
        return any(d == w or d.endswith('.' + w) for w in self._whitelisted_include_set)

    def _extract_ips_from_spf_domain(
        self,
        domain: str,
        root_domain: str,
        include_entry,
        resolver,
        resolved_ranges: list,
        seen_ips: set,
        visited: set,
        depth: int,
        max_depth: int = 10,
        whitelist_mode: bool = False
    ):
        """
        Recursively extract IP ranges from an SPF TXT record, following include: chains.

        Serves both trees. The two modes are mirror images of each other and each
        prunes on the other's *declared* entries, so a declared classification is
        never overridden by something merely inherited through a chain:

        - Dangerous mode (default): collects DangerousSPFIPRange, prunes sub-includes
          listed in Whitelisted_SPF_Include.csv.
        - Whitelist mode: collects WhitelistedSPFIPRange, prunes sub-includes listed
          in Dangerous_SPF_Include.csv — so whitelisting amazonses.com can never
          whitelist a dangerous service it happens to include.

        Args:
            domain: Domain whose TXT/SPF record to parse.
            root_domain: Top-level include domain (used as source_include).
            include_entry: DangerousSPFInclude or WhitelistedSPFInclude entry
                           (for service_type/service_name).
            resolver: DNS resolver instance.
            resolved_ranges: Accumulator list for the produced range objects.
            seen_ips: Set of already-seen ip_range strings (dedup within one include tree).
            visited: Set of already-visited domains (loop protection).
            depth: Current recursion depth.
            max_depth: Maximum recursion depth (default 10, mirrors SPF lookup limit).
            whitelist_mode: Walk a whitelisted include tree instead of a dangerous one.
        """
        if depth > max_depth or domain in visited:
            return
        visited.add(domain)

        def add_range(ip_range: str):
            """Record one IP range for the tree currently being walked."""
            if ip_range in seen_ips:
                return
            seen_ips.add(ip_range)
            range_cls = WhitelistedSPFIPRange if whitelist_mode else DangerousSPFIPRange
            resolved_ranges.append(range_cls(
                ip_range=ip_range,
                service_type=include_entry.service_type,
                service_name=include_entry.service_name,
                dangerous=not whitelist_mode,
                source_include=root_domain
            ))

        try:
            answers = resolver.resolve(domain, 'TXT')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            return

        for rdata in answers:
            txt_record = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])

            if not txt_record.startswith('v=spf1'):
                continue

            tokens = txt_record.split()
            for token in tokens:

                # ip4:x.x.x.x or ip4:x.x.x.x/xx
                if token.startswith('ip4:'):
                    ip_range = token[4:]
                    if '/' not in ip_range:
                        ip_range += '/32'
                    add_range(ip_range)

                # ip6:xxxx or ip6:xxxx/xx
                elif token.startswith('ip6:'):
                    ip_range = token[4:]
                    if '/' not in ip_range:
                        ip_range += '/128'
                    add_range(ip_range)

                # include:sub.domain.com — follow recursively
                elif token.startswith('include:'):
                    sub_domain = token[len('include:'):]
                    if sub_domain:
                        if whitelist_mode:
                            # Mirror guard: never let a whitelisted tree absorb a
                            # service explicitly declared dangerous.
                            if self.find_dangerous_include(sub_domain):
                                self._dangerous_in_whitelist_tree.setdefault(root_domain, set()).add(sub_domain)
                                continue
                        else:
                            # Recursion guard: a whitelisted sub-include is a shared
                            # platform of its own (e.g. amazonses.com reached through
                            # spf.infomaniak.ch -> newsletter.infomaniak.com). Walking
                            # it would attribute the whole platform's IP space to the
                            # dangerous service and flag every unrelated user of it.
                            if self.is_whitelisted_include(sub_domain):
                                self._pruned_includes.setdefault(root_domain, set()).add(sub_domain)
                                continue

                        self._extract_ips_from_spf_domain(
                            domain=sub_domain,
                            root_domain=root_domain,
                            include_entry=include_entry,
                            resolver=resolver,
                            resolved_ranges=resolved_ranges,
                            seen_ips=seen_ips,
                            visited=visited,
                            depth=depth + 1,
                            max_depth=max_depth,
                            whitelist_mode=whitelist_mode
                        )

                # a / a:domain.com / a/24 / a:domain.com/24
                elif token == 'a' or token.startswith('a:') or token.startswith('a/'):
                    domain_to_resolve = domain
                    if ':' in token:
                        domain_part = token.split(':', 1)[1]
                        domain_to_resolve = domain_part.split('/')[0] if '/' in domain_part else domain_part
                    for ip in self._resolve_a_record(domain_to_resolve, resolver):
                        add_range(f"{ip}/32" if ':' not in ip else f"{ip}/128")

                # mx / mx:domain.com / mx/24 / mx:domain.com/24
                elif token == 'mx' or token.startswith('mx:') or token.startswith('mx/'):
                    domain_to_resolve = domain
                    if ':' in token:
                        domain_part = token.split(':', 1)[1]
                        domain_to_resolve = domain_part.split('/')[0] if '/' in domain_part else domain_part
                    for ip in self._resolve_mx_record(domain_to_resolve, resolver):
                        add_range(f"{ip}/32" if ':' not in ip else f"{ip}/128")

                # ptr / ptr:domain.com — add to PTR blacklist (top-level domain only).
                # Never in whitelist mode: that list is a blacklist.
                elif (token == 'ptr' or token.startswith('ptr:')) and depth == 0 and not whitelist_mode:
                    ptr_domain = domain
                    if ':' in token:
                        parts = token.split(':', 1)
                        if len(parts) == 2:
                            ptr_domain = parts[1]
                    ptr_entry = DangerousPTRDomain(
                        ptr_domain=ptr_domain,
                        service_type=include_entry.service_type,
                        service_name=include_entry.service_name,
                        dangerous=True
                    )
                    if not any(existing.ptr_domain == ptr_domain for existing in self._dangerous_ptr_domains):
                        self._dangerous_ptr_domains.append(ptr_entry)

    def _resolve_a_record(self, domain: str, resolver: dns.resolver.Resolver) -> List[str]:
        """
        Resolve A and AAAA records for a domain.

        Args:
            domain: Domain to resolve
            resolver: DNS resolver to use

        Returns:
            List of IP addresses (both IPv4 and IPv6)
        """
        ips = []

        # Try A records (IPv4)
        try:
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ips.append(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            pass

        # Try AAAA records (IPv6)
        try:
            answers = resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                ips.append(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            pass

        return ips

    def _resolve_mx_record(self, domain: str, resolver: dns.resolver.Resolver) -> List[str]:
        """
        Resolve MX records for a domain, then resolve A/AAAA for each MX host.

        Args:
            domain: Domain to resolve
            resolver: DNS resolver to use

        Returns:
            List of IP addresses from all MX hosts
        """
        ips = []

        # Get MX records
        try:
            mx_answers = resolver.resolve(domain, 'MX')

            # For each MX host, resolve A/AAAA
            for mx_rdata in mx_answers:
                mx_host = str(mx_rdata.exchange).rstrip('.')

                # Resolve A records for MX host
                try:
                    a_answers = resolver.resolve(mx_host, 'A')
                    for rdata in a_answers:
                        ips.append(str(rdata))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                    pass

                # Resolve AAAA records for MX host
                try:
                    aaaa_answers = resolver.resolve(mx_host, 'AAAA')
                    for rdata in aaaa_answers:
                        ips.append(str(rdata))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                    pass

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            pass

        return ips

    def _print_load_summary(self):
        """Print a summary of loaded data."""
        print("\n" + "=" * 70)
        print("DATA LOADING SUMMARY")
        print("=" * 70)
        print(f"Dangerous Includes:    {len(self._dangerous_includes)}")
        print(f"Dangerous IP Ranges:   {len(self._dangerous_ip_ranges)}")
        print(f"Third-Party Services:  {len(self._third_party_services)}")
        print(f"Whitelisted Includes:  {len(self._whitelisted_includes)}")
        print(f"Whitelisted IP Ranges: {len(self._whitelisted_ip_ranges)}")

        # What the whitelist pruned out of the dangerous tree
        if self._pruned_includes:
            total_pruned = sum(len(v) for v in self._pruned_includes.values())
            print(f"\nPruned by whitelist:   {total_pruned}")
            for root_domain in sorted(self._pruned_includes, key=lambda d: d or ''):
                for sub in sorted(self._pruned_includes[root_domain]):
                    print(f"  {root_domain} -> {sub} (not attributed)")

        # Precedence in action: declared-dangerous data winning over the whitelist.
        # Both blocks below mean a whitelist entry is broader than intended.
        if self._dangerous_in_whitelist_tree:
            total = sum(len(v) for v in self._dangerous_in_whitelist_tree.values())
            print(f"\nDangerous kept over whitelist: {total} sub-include(s)")
            for root_domain in sorted(self._dangerous_in_whitelist_tree):
                for sub in sorted(self._dangerous_in_whitelist_tree[root_domain]):
                    print(f"  {root_domain} -> {sub} (declared dangerous, NOT whitelisted)")

        if self._whitelist_conflicts:
            print(f"\nWhitelist ranges dropped: {len(self._whitelist_conflicts)}")
            for wl, dangerous_entry in self._whitelist_conflicts:
                print(f"  {wl.ip_range} (from {wl.source_include}) overlaps declared "
                      f"dangerous {dangerous_entry.ip_range} ({dangerous_entry.service_name})")

        # PTR domains summary
        total_ptr = len(self._dangerous_ptr_domains)
        print(f"Dangerous PTR Domains: {total_ptr}")

        print("=" * 70 + "\n")

    def _deduplicate_ip_ranges(self, ranges: List[DangerousSPFIPRange]) -> List[DangerousSPFIPRange]:
        """
        Deduplicate IP ranges and remove redundant ranges.

        Removes:
        - Exact duplicates (same IP range)
        - Redundant ranges (e.g., 1.2.3.4/32 if 1.2.3.0/24 already exists)

        Args:
            ranges: List of DangerousSPFIPRange objects

        Returns:
            Deduplicated list of DangerousSPFIPRange objects
        """
        import ipaddress

        if not ranges:
            return []

        # Step 1: Remove exact duplicates by IP range string
        seen_ranges = {}
        for range_obj in ranges:
            if range_obj.ip_range not in seen_ranges:
                seen_ranges[range_obj.ip_range] = range_obj

        # Step 2: Parse all ranges as network objects
        parsed_ranges = []
        for range_str, range_obj in seen_ranges.items():
            try:
                network = ipaddress.ip_network(range_str, strict=False)
                parsed_ranges.append({
                    'network': network,
                    'range_obj': range_obj
                })
            except ValueError:
                # Invalid IP range, skip it
                continue

        # Step 3: Sort by prefix length (smaller networks first, e.g., /16 before /24 before /32)
        parsed_ranges.sort(key=lambda x: x['network'].prefixlen)

        # Step 4: Remove redundant ranges (IPs contained in larger networks)
        result = []
        for i, current in enumerate(parsed_ranges):
            is_redundant = False

            # Check if this range is contained in any previous (larger) range
            for j in range(i):
                previous = parsed_ranges[j]

                # Skip if different IP versions
                if current['network'].version != previous['network'].version:
                    continue

                # Check if current network is subnet of previous network
                if current['network'].subnet_of(previous['network']):
                    is_redundant = True
                    break

            if not is_redundant:
                result.append(current['range_obj'])

        return result

    @property
    def dangerous_includes(self) -> List[DangerousSPFInclude]:
        """Get dangerous includes (lazy load)"""
        if not self._dangerous_includes:
            self.load_dangerous_includes()
        return self._dangerous_includes

    @property
    def whitelisted_includes(self) -> List[WhitelistedSPFInclude]:
        """Get whitelisted includes (lazy load)"""
        if not self._whitelisted_includes:
            self.load_whitelisted_includes()
        return self._whitelisted_includes

    @property
    def whitelisted_ip_ranges(self) -> List[WhitelistedSPFIPRange]:
        """IP ranges resolved from the whitelisted include tree"""
        return self._whitelisted_ip_ranges

    @property
    def pruned_includes(self) -> Dict[str, Set[str]]:
        """Sub-includes and IP ranges skipped in the dangerous tree because whitelisted"""
        return self._pruned_includes

    @property
    def dangerous_in_whitelist_tree(self) -> Dict[str, Set[str]]:
        """Dangerous sub-includes found inside a whitelisted tree and NOT whitelisted"""
        return self._dangerous_in_whitelist_tree

    @property
    def whitelist_conflicts(self) -> List[tuple]:
        """(whitelisted_range, declared_dangerous_range) pairs dropped by precedence"""
        return self._whitelist_conflicts

    @property
    def dangerous_ip_ranges(self) -> List[DangerousSPFIPRange]:
        """Get dangerous IP ranges (lazy load)"""
        if not self._dangerous_ip_ranges:
            self.load_dangerous_ip_ranges()
        return self._dangerous_ip_ranges

    @property
    def third_party_services(self) -> List[ThirdPartyService]:
        """Get third-party services (lazy load)"""
        if not self._third_party_services:
            self.load_third_party_services()
        return self._third_party_services

    def get_dangerous_include_set(self) -> Set[str]:
        """Get a set of all dangerous include domains"""
        return {item.include for item in self.dangerous_includes}

    def get_dangerous_ip_range_list(self) -> List[str]:
        """Get a list of all dangerous IP ranges"""
        return [item.ip_range for item in self.dangerous_ip_ranges]

    def get_third_party_service_set(self) -> Set[str]:
        """Get a set of all third-party service AS organizations"""
        return {item.as_organization for item in self.third_party_services}

    def get_service_info_by_name(self, service_name: str) -> Optional[DangerousSPFInclude]:
        """
        Return the first dangerous include entry whose service_name matches exactly.

        Useful for external tools (e.g. mail_audit) that already know the service
        name from a SPF result and need the associated service_type / dangerous flag
        without re-parsing the CSV themselves.

        Args:
            service_name: Exact service name as stored in the CSV
                          (e.g. "SendGrid", "OVH", "Gmail.com Service").

        Returns:
            The matching DangerousSPFInclude, or None if not found.
        """
        for entry in self.dangerous_includes:
            if entry.service_name == service_name:
                return entry
        return None

    def get_all_dangerous_service_names(self) -> List[str]:
        """
        Return a deduplicated, ordered list of all service names present in the
        dangerous includes CSV (dangerous=True entries only).

        Useful for building or validating an external service configuration file
        (e.g. email_services.json in mail_audit) against the canonical CSV data.
        """
        seen: Set[str] = set()
        result: List[str] = []
        for entry in self.dangerous_includes:
            if entry.dangerous and entry.service_name not in seen:
                seen.add(entry.service_name)
                result.append(entry.service_name)
        return result

    def find_dangerous_include(self, include: str) -> List[DangerousSPFInclude]:
        """
        Find dangerous include entries matching a given include domain.

        Args:
            include: Include domain to search for

        Returns:
            List of matching DangerousSPFInclude objects
        """
        return [item for item in self.dangerous_includes if item.include.lower() == include.lower()]

    def find_third_party_service(self, as_organization: str) -> List[ThirdPartyService]:
        """
        Find third-party service entries matching an AS organization.

        Args:
            as_organization: AS organization to search for

        Returns:
            List of matching ThirdPartyService objects
        """
        if not as_organization:
            return []
        return [item for item in self.third_party_services
                if as_organization.lower() in item.as_organization.lower()
                or item.as_organization.lower() in as_organization.lower()]

    def load_dangerous_ptr_domains(self, load_all_entries: bool = False) -> List[DangerousPTRDomain]:
        """
        Load dangerous PTR domains from CSV file.

        Automatically expands each PTR domain to include all parent domains in the hierarchy.
        For example: "servers.mcsv.net" → ["servers.mcsv.net", "mcsv.net"]

        Args:
            load_all_entries: If True, load all entries including non-dangerous ones

        Returns:
            List of DangerousPTRDomain objects
        """
        from ..utils.ptr_utils import PTRUtils

        csv_path = os.path.join(self.data_dir, "Dangerous_PTR_Domains.csv")
        self._dangerous_ptr_domains = []

        if not os.path.exists(csv_path):
            return self._dangerous_ptr_domains

        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter=';')
                for row in reader:
                    dangerous = row.get('dangerous', 'Yes').lower() == 'yes'

                    # Skip non-dangerous entries unless load_all_entries is True
                    if not dangerous and not load_all_entries:
                        continue

                    # Extract domain hierarchy (e.g., "servers.mcsv.net" → ["servers.mcsv.net", "mcsv.net"])
                    ptr_domain = row['ptr_domain']
                    domain_hierarchy = PTRUtils.extract_domain_hierarchy(ptr_domain)

                    # Add all levels of the hierarchy
                    for domain_level in domain_hierarchy:
                        # Create entry for this domain level
                        ptr_entry = DangerousPTRDomain(
                            ptr_domain=domain_level,
                            service_type=row.get('service_type', ''),
                            service_name=row.get('service_name', ''),
                            dangerous=dangerous
                        )

                        # Avoid duplicates
                        if not any(existing.ptr_domain == domain_level for existing in self._dangerous_ptr_domains):
                            self._dangerous_ptr_domains.append(ptr_entry)

        except FileNotFoundError:
            pass
        except Exception as e:
            raise ValueError(f"Error loading Dangerous_PTR_Domains.csv: {e}")

        return self._dangerous_ptr_domains

    def _load_ptr_blacklist_from_csv(self) -> bool:
        """
        Load PTR blacklist from CSV file (./data/Dangerous_SPF_PTR_Records.csv).

        This allows reusing previously built PTR blacklists without expensive DNS lookups.
        Merges loaded entries with existing PTR domains (avoids duplicates).

        Returns:
            True if file exists and was loaded, False otherwise
        """
        import csv
        import os

        ptr_file = os.path.join(self.data_dir, "Dangerous_SPF_PTR_Records.csv")

        if not os.path.exists(ptr_file):
            print(f"[DataLoaders] No PTR blacklist CSV found at {ptr_file}")
            return False

        try:
            print(f"[DataLoaders] Loading PTR blacklist from {ptr_file}...")

            with open(ptr_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter=';')

                # Load PTR domains
                added_count = 0
                skipped_whitelisted = 0
                for row in reader:
                    ptr_domain = row.get('ptr_domain', '').strip()
                    service_type = row.get('service_type', '').strip()
                    service_name = row.get('service_name', '').strip()
                    dangerous_str = row.get('dangerous', 'Yes').strip()

                    if not ptr_domain:
                        continue

                    # Drop rows belonging to a whitelisted platform. This lets a
                    # previously-built CSV self-heal after a whitelist entry is added,
                    # instead of carrying the stale attribution forever.
                    if self.is_whitelisted_ptr(ptr_domain):
                        skipped_whitelisted += 1
                        continue

                    # Check if already exists (avoid duplicates)
                    if any(existing.ptr_domain == ptr_domain for existing in self._dangerous_ptr_domains):
                        continue

                    # Parse dangerous flag
                    dangerous = dangerous_str.lower() in ('yes', 'true', '1')

                    # Add to list
                    ptr_entry = DangerousPTRDomain(
                        ptr_domain=ptr_domain,
                        service_type=service_type,
                        service_name=service_name,
                        dangerous=dangerous
                    )
                    self._dangerous_ptr_domains.append(ptr_entry)
                    added_count += 1

            print(f"  Loaded {added_count} PTR domains from CSV (total: {len(self._dangerous_ptr_domains)})")
            if skipped_whitelisted:
                print(f"  Skipped {skipped_whitelisted} PTR domains belonging to whitelisted platforms")
            return True

        except Exception as e:
            print(f"[DataLoaders] Error loading PTR blacklist CSV: {e}")
            return False

    def _save_ptr_blacklist_to_csv(self):
        """
        Save PTR blacklist to CSV file (./data/Dangerous_SPF_PTR_Records.csv).

        This allows reusing the blacklist without expensive DNS lookups.
        """
        import csv
        import os

        ptr_file = os.path.join(self.data_dir, "Dangerous_SPF_PTR_Records.csv")

        try:
            print(f"[DataLoaders] Saving PTR blacklist to {ptr_file}...")

            with open(ptr_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['ptr_domain', 'service_type', 'service_name', 'dangerous']
                writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';')

                # Write header
                writer.writeheader()

                # Write PTR domains (sorted for consistency)
                for ptr in sorted(self._dangerous_ptr_domains, key=lambda x: x.ptr_domain):
                    writer.writerow({
                        'ptr_domain': ptr.ptr_domain,
                        'service_type': ptr.service_type,
                        'service_name': ptr.service_name,
                        'dangerous': 'Yes' if ptr.dangerous else 'No'
                    })

            print(f"  Saved {len(self._dangerous_ptr_domains)} PTR domains to {ptr_file}")

        except Exception as e:
            print(f"[DataLoaders] Error saving PTR blacklist CSV: {e}")

    def _build_ptr_blacklist_from_dangerous_ips(self):
        """
        Build PTR blacklist from dangerous IPs by performing reverse PTR lookups.

        This is EXPENSIVE as it performs PTR lookups for all dangerous IPs.
        Use sparingly and consider caching results.

        Stores results in _dangerous_ptr_domains (only most specific domains, no hierarchy expansion).
        """
        from ..utils.ip_utils import IPUtils

        print("[DataLoaders] Building PTR blacklist from dangerous IPs...")
        print(f"  This may take a while (PTR lookups for {len(self._dangerous_ip_ranges)} ranges)")

        all_ips = []
        ip_to_service = {}  # Track which service each IP belongs to

        # Collect IPs from dangerous ranges
        for ip_range_entry in self._dangerous_ip_ranges:
            ip_range = ip_range_entry.ip_range

            # For ranges, sample IPs
            if '/' in ip_range:
                # Get CIDR prefix
                try:
                    prefix = int(ip_range.split('/')[1])

                    # For /24 and smaller, get all IPs
                    if prefix >= 24:
                        ips = IPUtils.expand_ip_range(ip_range, limit=256)
                        for ip in ips:
                            all_ips.append(ip)
                            ip_to_service[ip] = ip_range_entry
                    # For larger ranges, sample
                    else:
                        # Get first, last, and a few random IPs
                        first_ip = IPUtils.get_first_ip_in_range(ip_range)
                        if first_ip:
                            all_ips.append(first_ip)
                            ip_to_service[first_ip] = ip_range_entry

                except Exception:
                    # Fallback: just get first IP
                    first_ip = IPUtils.get_first_ip_in_range(ip_range)
                    if first_ip:
                        all_ips.append(first_ip)
                        ip_to_service[first_ip] = ip_range_entry
            else:
                # Single IP
                all_ips.append(ip_range)
                ip_to_service[ip_range] = ip_range_entry

        print(f"  Performing PTR lookups for {len(all_ips)} IPs...")

        # Perform batch PTR lookups with IP tracking
        # PTRUtils.build_ptr_blacklist_from_ips returns Set[str] (just domain names)
        # We need to track which IPs resolved to which PTR domains to preserve service info
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import socket

        print(f"  Performing PTR lookups for {len(all_ips)} IPs (preserving service info)...")

        ptr_to_services = {}  # ptr_domain -> list of (service_type, service_name)

        def lookup_ptr_with_service(ip):
            """Lookup PTR for IP and track service info"""
            try:
                ptr_records = socket.gethostbyaddr(ip)[0]
                if ptr_records and ip in ip_to_service:
                    ptr_domain = ptr_records.lower().rstrip('.')
                    # A dangerous service relaying through a whitelisted platform
                    # reverse-resolves into that platform's namespace
                    # (e.g. *.smtp-out.amazonses.com). Recording it would blacklist
                    # the platform under the dangerous service's name — the same
                    # mis-attribution the include: guard prevents, via the PTR path.
                    if self.is_whitelisted_ptr(ptr_domain):
                        return None
                    service_entry = ip_to_service[ip]
                    return (ptr_domain, service_entry.service_type, service_entry.service_name)
            except:
                pass
            return None

        # Parallel PTR lookups
        with ThreadPoolExecutor(max_workers=self.ptr_pool_size) as executor:
            futures = {executor.submit(lookup_ptr_with_service, ip): ip for ip in all_ips}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ptr_domain, service_type, service_name = result
                    if ptr_domain not in ptr_to_services:
                        ptr_to_services[ptr_domain] = []
                    ptr_to_services[ptr_domain].append((service_type, service_name))

        print(f"  PTR lookup complete: {len(ptr_to_services)} unique domains found")

        # Convert to DangerousPTRDomain objects and add to _dangerous_ptr_domains
        # Store ONLY the most specific domain (no hierarchy expansion)
        added_count = 0
        for ptr_domain, services in ptr_to_services.items():
            # Check if this domain is already in the list (avoid duplicates)
            if any(existing.ptr_domain == ptr_domain for existing in self._dangerous_ptr_domains):
                continue

            # Use the first service info (they should all be from same dangerous range)
            service_type, service_name = services[0]

            # Create entry with proper service info
            ptr_entry = DangerousPTRDomain(
                ptr_domain=ptr_domain,
                service_type=service_type,
                service_name=service_name,
                dangerous=True
            )
            self._dangerous_ptr_domains.append(ptr_entry)
            added_count += 1

        print(f"  Added {added_count} new PTR domains to blacklist (total: {len(self._dangerous_ptr_domains)})")

    def find_dangerous_ptr_domain(self, ptr_domain: str) -> List[DangerousPTRDomain]:
        """
        Find dangerous PTR domain entries matching a given PTR domain.

        Uses hierarchical matching via PTRUtils.ptr_matches_domain().
        Returns only the MOST SPECIFIC match to avoid duplicates.

        For example, if we have ["mail-out.ovh.net", "ovh.net"] stored,
        and we search for "mail-out.ovh.net", we return only "mail-out.ovh.net",
        not both.

        Args:
            ptr_domain: PTR domain to search for

        Returns:
            List of matching DangerousPTRDomain objects (typically 0 or 1)
        """
        from ..utils.ptr_utils import PTRUtils

        matches = []

        # Check all PTR domains (from includes, IPs, and static CSV)
        for item in self._dangerous_ptr_domains:
            if PTRUtils.ptr_matches_domain(ptr_domain, item.ptr_domain):
                matches.append(item)

        # If multiple matches, return only the most specific one
        # (longest domain name = most specific)
        if len(matches) > 1:
            # Sort by domain length (descending) and return only the longest
            matches.sort(key=lambda x: len(x.ptr_domain), reverse=True)
            return [matches[0]]

        return matches

    @property
    def dangerous_ptr_domains(self) -> List[DangerousPTRDomain]:
        """Get list of dangerous PTR domains from CSV"""
        return self._dangerous_ptr_domains

    @property
    def ptr_blacklist_from_ips(self) -> Set[str]:
        """Get PTR blacklist built from dangerous IPs"""
        return self._ptr_blacklist_from_ips
