"""Output generator for unrecognized includes, IPs, and IP ranges"""

import os
import csv
from typing import List, Set, Dict, Any
from datetime import datetime
from ..models.spf_result import SPFResult
from ..utils.maxmind_client import MaxMindClient
from ..utils.ip_utils import IPUtils


class OutputGenerator:
    """
    Generates output files for continuous improvement of detection lists.
    Tracks unrecognized includes, IP ranges, and IP addresses.
    """

    def __init__(self, output_dir: str = "./output", maxmind_client: MaxMindClient = None):
        """
        Initialize output generator.

        Args:
            output_dir: Directory for output files
            maxmind_client: Optional MaxMind client for AS organization lookups
        """
        self.output_dir = output_dir
        self.maxmind_client = maxmind_client
        os.makedirs(output_dir, exist_ok=True)

    def generate_unrecognized_report(self, spf_results: List[SPFResult], filename: str = None):
        """
        Generate a report of all unrecognized includes, IP ranges, and IPs.

        Args:
            spf_results: List of SPFResult objects to analyze
            filename: Optional custom filename (defaults to timestamped name)
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"unrecognized_spf_entries_{timestamp}.csv"

        filepath = os.path.join(self.output_dir, filename)

        # Collect all unrecognized entries
        unrecognized_includes = []
        unrecognized_ip_ranges = []
        unrecognized_ips = []

        for result in spf_results:
            # Process includes
            for include_data in result.all_includes:
                if not include_data.get('dangerous', False):
                    unrecognized_includes.append({
                        'domain': result.domain,
                        'include': include_data['include'],
                        'path': include_data['path']
                    })

            # Process IP ranges
            for ip_range_data in result.all_ip_ranges:
                if not ip_range_data.get('dangerous', False):
                    entry = {
                        'domain': result.domain,
                        'ip_range': ip_range_data['ip_range'],
                        'path': ip_range_data['path']
                    }

                    # Add MaxMind data if available
                    if self.maxmind_client:
                        first_ip = IPUtils.get_first_ip_in_range(ip_range_data['ip_range'])
                        if first_ip:
                            ip_info = self.maxmind_client.get_ip_information(first_ip)
                            entry['as_organization'] = ip_info.get('as_organization', '')
                            entry['country'] = ip_info.get('country_name', '')
                        else:
                            entry['as_organization'] = ''
                            entry['country'] = ''
                    else:
                        entry['as_organization'] = ''
                        entry['country'] = ''

                    unrecognized_ip_ranges.append(entry)

            # Process individual IPs
            for ip_data in result.all_ip_addresses:
                if not ip_data.get('dangerous', False):
                    entry = {
                        'domain': result.domain,
                        'ip': ip_data['ip'],
                        'path': ip_data['path']
                    }

                    # Add MaxMind data if available
                    if self.maxmind_client:
                        ip_info = self.maxmind_client.get_ip_information(ip_data['ip'])
                        entry['as_organization'] = ip_info.get('as_organization', '')
                        entry['country'] = ip_info.get('country_name', '')
                    else:
                        entry['as_organization'] = ''
                        entry['country'] = ''

                    unrecognized_ips.append(entry)

        # Write to CSV
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write includes section
            if unrecognized_includes:
                writer.writerow(['=== UNRECOGNIZED INCLUDES ==='])
                writer.writerow(['Domain', 'Include', 'Resolution Path'])
                for entry in unrecognized_includes:
                    writer.writerow([entry['domain'], entry['include'], entry['path']])
                writer.writerow([])

            # Write IP ranges section
            if unrecognized_ip_ranges:
                writer.writerow(['=== UNRECOGNIZED IP RANGES ==='])
                writer.writerow(['Domain', 'IP Range', 'Resolution Path', 'AS Organization', 'Country'])
                for entry in unrecognized_ip_ranges:
                    writer.writerow([
                        entry['domain'],
                        entry['ip_range'],
                        entry['path'],
                        entry.get('as_organization', ''),
                        entry.get('country', '')
                    ])
                writer.writerow([])

            # Write IPs section
            if unrecognized_ips:
                writer.writerow(['=== UNRECOGNIZED IP ADDRESSES ==='])
                writer.writerow(['Domain', 'IP Address', 'Resolution Path', 'AS Organization', 'Country'])
                for entry in unrecognized_ips:
                    writer.writerow([
                        entry['domain'],
                        entry['ip'],
                        entry['path'],
                        entry.get('as_organization', ''),
                        entry.get('country', '')
                    ])

        return filepath

    def generate_statistics(self, spf_results: List[SPFResult], filename: str = None) -> Dict[str, Any]:
        """
        Generate statistics about SPF checks.

        Args:
            spf_results: List of SPFResult objects to analyze
            filename: Optional filename to save statistics as JSON

        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_domains': len(spf_results),
            'domains_with_spf': sum(1 for r in spf_results if r.spf_record),
            'domains_without_spf': sum(1 for r in spf_results if not r.spf_record),
            'total_issues': sum(len(r.issues) for r in spf_results),
            'total_dangerous_includes': sum(
                sum(1 for inc in r.all_includes if inc.get('dangerous', False))
                for r in spf_results
            ),
            'total_dangerous_ip_ranges': sum(
                sum(1 for ipr in r.all_ip_ranges if ipr.get('dangerous', False))
                for r in spf_results
            ),
            'total_dangerous_ips': sum(
                sum(1 for ip in r.all_ip_addresses if ip.get('dangerous', False))
                for r in spf_results
            ),
            'issues_by_severity': {
                'critical': sum(
                    sum(1 for i in r.issues if i.severity.value == 'critical')
                    for r in spf_results
                ),
                'high': sum(
                    sum(1 for i in r.issues if i.severity.value == 'high')
                    for r in spf_results
                ),
                'medium': sum(
                    sum(1 for i in r.issues if i.severity.value == 'medium')
                    for r in spf_results
                ),
                'low': sum(
                    sum(1 for i in r.issues if i.severity.value == 'low')
                    for r in spf_results
                )
            },
            'avg_lookup_count': sum(r.lookup_count for r in spf_results) / len(spf_results) if spf_results else 0
        }

        if filename:
            import json
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2)

        return stats
