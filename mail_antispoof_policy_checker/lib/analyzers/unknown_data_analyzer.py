"""Analyzer for unknown SPF data not in CSV databases"""

import json
import ipaddress
import asyncio
import dns.resolver
import dns.reversename
import pandas as pd
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from ..data.loaders import DataLoaders
from ..utils.maxmind_client import MaxMindClient
from ..utils.ip_utils import IPUtils


class UnknownDataAnalyzer:
    """Analyzes JSON output to find unknown SPF data not in CSV databases"""

    def __init__(
        self,
        data_loaders: DataLoaders,
        maxmind_client: Optional[MaxMindClient] = None,
        ptr_pool_size: int = 20
    ):
        """
        Initialize UnknownDataAnalyzer.

        Args:
            data_loaders: DataLoaders instance with CSV data
            maxmind_client: Optional MaxMindClient for AS organization lookup
            ptr_pool_size: Number of parallel PTR lookups (default: 20)
        """
        self.data_loaders = data_loaders
        self.maxmind_client = maxmind_client
        self.ptr_pool_size = ptr_pool_size

    def analyze_json_output(self, json_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze JSON output to find unknown SPF data.

        Args:
            json_data: List of SPF analysis results from JSON file

        Returns:
            Dictionary with unknown_includes, unknown_ip_ranges, unknown_ip_addresses
        """
        # Get known data sets
        known_includes = self.data_loaders.get_dangerous_include_set()
        known_ip_ranges = set(self.data_loaders.get_dangerous_ip_range_list())
        known_as_orgs = self.data_loaders.get_third_party_service_set()

        unknown_includes = []
        unknown_ip_ranges = []
        unknown_ip_addresses = []

        for record in json_data:
            record_id = record.get('record_id', 'Unknown')
            spf_record = record.get('spf_record', '')

            # Check includes
            all_includes = record.get('all_includes', [])
            for inc in all_includes:
                include_domain = inc.get('include', '')
                # Skip if dangerous flag is already True (means it's in CSV)
                if inc.get('dangerous', False):
                    continue
                # Add to unknown includes
                if include_domain and include_domain.lower() not in {k.lower() for k in known_includes}:
                    unknown_includes.append({
                        'record_id': record_id,
                        'include': include_domain,
                        'path': inc.get('path', record_id),
                        'spf_record': spf_record
                    })

            # Check IP ranges
            all_ip_ranges = record.get('all_ip_ranges', [])
            for ipr in all_ip_ranges:
                ip_range = ipr.get('ip_range', '')
                # Skip if dangerous flag is already True
                if ipr.get('dangerous', False):
                    continue
                # Add to unknown IP ranges
                if ip_range:
                    unknown_ip_ranges.append({
                        'record_id': record_id,
                        'ip_range': ip_range,
                        'path': ipr.get('path', record_id),
                        'spf_record': spf_record
                    })

            # Check IP addresses
            all_ip_addresses = record.get('all_ip_addresses', [])
            for ipa in all_ip_addresses:
                ip = ipa.get('ip', '')
                # Skip if dangerous flag is already True
                if ipa.get('dangerous', False):
                    continue
                # Add to unknown IP addresses
                if ip:
                    unknown_ip_addresses.append({
                        'record_id': record_id,
                        'ip': ip,
                        'path': ipa.get('path', record_id),
                        'spf_record': spf_record
                    })

        return {
            'unknown_includes': unknown_includes,
            'unknown_ip_ranges': unknown_ip_ranges,
            'unknown_ip_addresses': unknown_ip_addresses
        }

    async def lookup_ptr_for_range(self, ip_range: str) -> List[Dict[str, Any]]:
        """
        Perform async PTR lookups for all IPs in a range.

        Args:
            ip_range: IP range in CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            List of dictionaries with ip and ptr fields
        """
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return []

        # Limit to reasonable range size (e.g., /24 max = 256 hosts)
        if network.num_addresses > 256:
            # For large ranges, only check first IP
            first_ip = str(network.network_address)
            result = self._ptr_lookup(first_ip)
            return [result] if result else []

        # Create tasks for all hosts
        with ThreadPoolExecutor(max_workers=self.ptr_pool_size) as executor:
            loop = asyncio.get_event_loop()
            tasks = [
                loop.run_in_executor(executor, self._ptr_lookup, str(ip))
                for ip in network.hosts()
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out None results and exceptions
        return [r for r in results if r is not None and isinstance(r, dict)]

    def _ptr_lookup(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Synchronous PTR lookup for a single IP.

        Args:
            ip: IP address to lookup

        Returns:
            Dictionary with ip and ptr, or None if lookup fails
        """
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(addr, 'PTR')
            return {
                'ip': ip,
                'ptr': str(answers[0]).rstrip('.')
            }
        except Exception:
            return None

    def get_as_organization(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get AS organization for an IP address using MaxMind.

        Args:
            ip: IP address

        Returns:
            Dictionary with AS organization info, or None
        """
        if not self.maxmind_client:
            return None

        try:
            info = self.maxmind_client.get_ip_information(ip)
            if info and info.get('as_organization'):
                return {
                    'as_organization': info['as_organization'],
                    'country_name': info.get('country_name'),
                    'country_iso_code': info.get('country_iso_code')
                }
        except Exception:
            pass

        return None

    def export_to_json(self, analysis_result: Dict[str, Any], output_path: str) -> None:
        """
        Export analysis results to JSON.

        Args:
            analysis_result: Result from analyze_json_output()
            output_path: Path to output JSON file
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, indent=2, ensure_ascii=False)

    def export_to_excel(
        self,
        analysis_result: Dict[str, Any],
        output_path: str,
        include_ptr: bool = False,
        ptr_results: Optional[Dict[str, List[Dict]]] = None
    ) -> None:
        """
        Export analysis results to Excel with multiple sheets.

        Args:
            analysis_result: Result from analyze_json_output()
            output_path: Path to output Excel file
            include_ptr: Whether to include PTR lookup results
            ptr_results: PTR lookup results by IP range
        """
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Sheet 1: Unknown Includes
            unknown_includes = analysis_result.get('unknown_includes', [])
            if unknown_includes:
                df_includes = pd.DataFrame(unknown_includes)
                df_includes.to_excel(writer, sheet_name='Unknown Includes', index=False)
            else:
                pd.DataFrame([{'Message': 'No unknown includes found'}]).to_excel(
                    writer, sheet_name='Unknown Includes', index=False
                )

            # Sheet 2: IP AS Organization (IP Ranges)
            unknown_ip_ranges = analysis_result.get('unknown_ip_ranges', [])
            if unknown_ip_ranges and self.maxmind_client:
                as_org_data = []
                for ipr in unknown_ip_ranges:
                    ip_range = ipr['ip_range']
                    # Get first IP in range
                    first_ip = IPUtils.get_first_ip_in_range(ip_range)
                    if first_ip:
                        as_info = self.get_as_organization(first_ip)
                        as_org_data.append({
                            'Record ID': ipr['record_id'],
                            'IP Range': ip_range,
                            'First IP': first_ip,
                            'AS Organization': as_info.get('as_organization') if as_info else 'N/A',
                            'Country': as_info.get('country_name') if as_info else 'N/A',
                            'Country Code': as_info.get('country_iso_code') if as_info else 'N/A',
                            'SPF Record': ipr['spf_record']
                        })

                if as_org_data:
                    df_as_org = pd.DataFrame(as_org_data)
                    df_as_org.to_excel(writer, sheet_name='IP AS Organization', index=False)
                else:
                    pd.DataFrame([{'Message': 'No AS organization data available'}]).to_excel(
                        writer, sheet_name='IP AS Organization', index=False
                    )
            else:
                msg = 'No unknown IP ranges found' if not unknown_ip_ranges else 'MaxMind client not available'
                pd.DataFrame([{'Message': msg}]).to_excel(
                    writer, sheet_name='IP AS Organization', index=False
                )

            # Sheet 3: IP AS Organization (IP Addresses)
            unknown_ip_addresses = analysis_result.get('unknown_ip_addresses', [])
            if unknown_ip_addresses and self.maxmind_client:
                ip_as_org_data = []
                for ipa in unknown_ip_addresses:
                    ip = ipa['ip']
                    as_info = self.get_as_organization(ip)
                    ip_as_org_data.append({
                        'Record ID': ipa['record_id'],
                        'IP Address': ip,
                        'AS Organization': as_info.get('as_organization') if as_info else 'N/A',
                        'Country': as_info.get('country_name') if as_info else 'N/A',
                        'Country Code': as_info.get('country_iso_code') if as_info else 'N/A',
                        'SPF Record': ipa['spf_record']
                    })

                if ip_as_org_data:
                    df_ip_as_org = pd.DataFrame(ip_as_org_data)
                    df_ip_as_org.to_excel(writer, sheet_name='IP Address AS Org', index=False)
                else:
                    pd.DataFrame([{'Message': 'No AS organization data available'}]).to_excel(
                        writer, sheet_name='IP Address AS Org', index=False
                    )
            else:
                msg = 'No unknown IP addresses found' if not unknown_ip_addresses else 'MaxMind client not available'
                pd.DataFrame([{'Message': msg}]).to_excel(
                    writer, sheet_name='IP Address AS Org', index=False
                )

            # Sheet 4: IP PTR Records (optional)
            if include_ptr and ptr_results:
                ptr_data = []
                for ip_range, ptr_list in ptr_results.items():
                    # Find matching IP range entry
                    matching_entry = next(
                        (ipr for ipr in unknown_ip_ranges if ipr['ip_range'] == ip_range),
                        None
                    )
                    record_id = matching_entry['record_id'] if matching_entry else 'Unknown'
                    spf_record = matching_entry['spf_record'] if matching_entry else ''

                    # Get AS org for first IP
                    first_ip = IPUtils.get_first_ip_in_range(ip_range)
                    as_info = self.get_as_organization(first_ip) if first_ip and self.maxmind_client else None

                    for ptr_entry in ptr_list:
                        ptr_data.append({
                            'Record ID': record_id,
                            'IP Range': ip_range,
                            'IP Address': ptr_entry['ip'],
                            'PTR Record': ptr_entry['ptr'],
                            'AS Organization': as_info.get('as_organization') if as_info else 'N/A',
                            'SPF Record': spf_record
                        })

                if ptr_data:
                    df_ptr = pd.DataFrame(ptr_data)
                    df_ptr.to_excel(writer, sheet_name='IP PTR Records', index=False)
                else:
                    pd.DataFrame([{'Message': 'No PTR records found'}]).to_excel(
                        writer, sheet_name='IP PTR Records', index=False
                    )


async def async_check_unknown_spf_data(
    input_json_path: str,
    output_dir: str = "./output",
    data_dir: str = "./data",
    ptr_pool_size: int = 20,
    include_ptr_lookups: bool = False,
    maxmind_license_key: Optional[str] = None
) -> None:
    """
    Async entry point for unknown SPF data analysis.

    Args:
        input_json_path: Path to JSON file from SPF scanner
        output_dir: Directory for output files (default: ./output)
        data_dir: Directory with CSV databases (default: ./data)
        ptr_pool_size: Number of parallel PTR lookups (default: 20)
        include_ptr_lookups: Whether to perform PTR lookups on IP ranges
        maxmind_license_key: Optional MaxMind license key
    """
    # Load input JSON
    with open(input_json_path, 'r', encoding='utf-8') as f:
        json_data = json.load(f)

    # Initialize components
    data_loaders = DataLoaders(data_dir=data_dir)
    data_loaders.load_all()

    maxmind_client = None
    if maxmind_license_key:
        try:
            import os
            os.environ['MAXMIND_LICENSE_KEY'] = maxmind_license_key
            maxmind_client = MaxMindClient.from_environment()
        except Exception:
            pass

    analyzer = UnknownDataAnalyzer(
        data_loaders=data_loaders,
        maxmind_client=maxmind_client,
        ptr_pool_size=ptr_pool_size
    )

    # Analyze JSON
    print(f"Analyzing {len(json_data)} SPF records...")
    analysis_result = analyzer.analyze_json_output(json_data)

    print(f"  Unknown includes: {len(analysis_result['unknown_includes'])}")
    print(f"  Unknown IP ranges: {len(analysis_result['unknown_ip_ranges'])}")
    print(f"  Unknown IP addresses: {len(analysis_result['unknown_ip_addresses'])}")

    # PTR lookups
    ptr_results = {}
    if include_ptr_lookups:
        print(f"\nPerforming PTR lookups (pool size: {ptr_pool_size})...")
        for ipr in analysis_result['unknown_ip_ranges']:
            ip_range = ipr['ip_range']
            print(f"  Looking up PTR for {ip_range}...")
            ptr_list = await analyzer.lookup_ptr_for_range(ip_range)
            if ptr_list:
                ptr_results[ip_range] = ptr_list
                print(f"    Found {len(ptr_list)} PTR records")
            else:
                print(f"    No PTR records found")

    # Export results
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON export
    json_filename = f"{output_dir}/unknown_spf_data_{timestamp}.json"
    analyzer.export_to_json(analysis_result, json_filename)
    print(f"\nJSON exported: {json_filename}")

    # Excel export
    excel_filename = f"{output_dir}/unknown_spf_data_{timestamp}.xlsx"
    analyzer.export_to_excel(
        analysis_result,
        excel_filename,
        include_ptr=include_ptr_lookups,
        ptr_results=ptr_results
    )
    print(f"Excel exported: {excel_filename}")


def check_unknown_spf_data(
    input_json_path: str,
    output_dir: str = "./output",
    data_dir: str = "./data",
    ptr_pool_size: int = 20,
    include_ptr_lookups: bool = False,
    maxmind_license_key: Optional[str] = None
) -> None:
    """
    Main entry point for unknown SPF data analysis.

    Args:
        input_json_path: Path to JSON file from SPF scanner
        output_dir: Directory for output files (default: ./output)
        data_dir: Directory with CSV databases (default: ./data)
        ptr_pool_size: Number of parallel PTR lookups (default: 20)
        include_ptr_lookups: Whether to perform PTR lookups on IP ranges
        maxmind_license_key: Optional MaxMind license key
    """
    asyncio.run(async_check_unknown_spf_data(
        input_json_path=input_json_path,
        output_dir=output_dir,
        data_dir=data_dir,
        ptr_pool_size=ptr_pool_size,
        include_ptr_lookups=include_ptr_lookups,
        maxmind_license_key=maxmind_license_key
    ))
