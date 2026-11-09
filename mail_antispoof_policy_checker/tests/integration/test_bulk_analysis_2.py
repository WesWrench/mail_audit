"""
Test script for analyzing SPF records directly without DNS queries.
Analyzes a list of SPF records and exports results to JSON and Excel.
"""
# -*- coding: utf-8 -*-
import sys
import io
import os
import json
import pandas as pd
from datetime import datetime

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker
from lib.utils.maxmind_client import MaxMindClient

# SPF records to analyze
spf_records = [
    "v=spf1 include:mx.ovh.com -all",
    "v=spf1 include:spf.mailjet.com -all",
    "v=spf1 ip4:195.25.28.191 ip4:195.25.28.108 ip4:46.17.65.36 ip4:193.238.148.196 include:spf.sihm.fr include:pictime.fr include:spf-relay.coreye.net include:_spf.salesforce.com mx ~all",
    "v=spf1 ip4:84.96.72.121 ip4:84.96.93.153 ip4:84.96.93.161 ip4:84.96.93.162 ip4:90.83.169.19 ip4:46.16.45.155 a:mail.gfp2000.com/32 include:spf.mailjet.com include:spf.sihm.fr mx -all",
    "v=spf1 ip4:31.193.51.113 ip4:31.193.50.3 ip4:178.237.104.37 ip4:178.237.110.10  ip4:195.154.238.176/28 ip4:217.70.176.0/21 ip4:194.206.218.130 ip4:213.245.2.0/25 ip4:185.14.247.9 ip4:185.14.246.9 ip4:185.14.245.9 ip4:185.14.244.9 ip4:185.111.54.116  ip4:87.253.232.0/21 ip4:185.189.236.0/22 ip4:185.211.120.0/22 ip4:185.250.236.0/22 ip4:45.14.148.0/22  ip4:81.93.29.64/28 ip4:109.197.246.192/27  ip4:90.80.213.73 ip4:90.80.213.83 ip4:90.80.213.75 ip4:90.80.213.85 ip4:35.181.25.130  ip4:185.41.28.0/22 ip4:94.143.16.0/21 ip4:185.24.144.0/22 ip4:153.92.224.0/19 ip4:213.32.128.0/18 ip4:185.107.232.0/22 ip4:77.32.128.0/18 ip4:77.32.192.0/19 ip4:212.146.192.0/18 ip4:172.246.0.0/18 ip6:2001:4b98:c::/48 a:mailer.sihm.fr a:massmail.completel.net a:smtp-out.ivalua.fr a:mailinfra.oodrive.com  include:spf.tipimail.com include:spf.protection.outlook.com include:spf-0071fc01.pphosted.com  include:_spf.atlassian.net include:_spf.profils.org -all",
    "v=spf1 include:spf.mailjet.com ip4:84.96.72.121 ip4:84.96.93.153 ip4:84.96.93.161 ip4:84.96.93.162 ip4:90.83.169.19 ip4:46.16.45.155 include:spf.protection.outlook.com include:spf.sihm.fr include:spf.tipimail.com mx -all",
    "v=spf1 include:spf.mailjet.com ip4:84.96.72.121 ip4:84.96.93.153 ip4:84.96.93.161 ip4:84.96.93.162 ip4:90.83.169.19 ip4:46.16.45.155 include:spf.protection.outlook.com include:spf.sihm.fr include:spf.tipimail.com mx -all",
    "v=spf1 ip4:109.234.163.1 -all",
    "v=spf1 ip4:109.234.163.0/23 -all",
    "v=spf1 ip4:223.165.113.0 -all",
    "v=spf1 ip4:223.165.113.0/24 -all"
]

print("=" * 80)
print("Mail AntiSpoof Policy Checker - Direct SPF Analysis")
print("=" * 80)

# Initialize data loaders, MaxMind client, and SPF checker
print("\n[Initialization]")
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

# Initialize MaxMind client
maxmind_client = None
try:
    maxmind_client = MaxMindClient.from_environment()
    print("  MaxMind client initialized")
except ValueError as e:
    print(f"  MaxMind client not initialized: {e}")

spf_checker = SPFChecker(data_loaders=data_loaders, maxmind_client=maxmind_client)
print(f"  Loaded {len(data_loaders.dangerous_includes)} dangerous includes")
print(f"  Loaded {len(data_loaders.dangerous_ip_ranges)} dangerous IP ranges")
print(f"  Loaded {len(data_loaders.third_party_services)} third-party services")

print(f"\n[Analyzing {len(spf_records)} SPF records...]")
print("  Using checkdmarc for parsing")

# Storage for results
all_results = []
dangerous_includes_list = []
dangerous_ip_ranges_list = []
dangerous_ip_addresses_list = []
all_includes_list = []
all_ip_ranges_list = []
all_ip_addresses_list = []

# Analyze each SPF record
for i, spf_record in enumerate(spf_records, 1):
    print(f"\n[{i}/{len(spf_records)}] Analyzing SPF record #{i}")
    print(f"  Record: {spf_record[:100]}{'...' if len(spf_record) > 100 else ''}")

    record_id = f"SPF-{i:02d}"

    # Use SPFChecker to analyze the record
    spf_result = spf_checker.check_record(spf_record, record_id)

    # Extract dangerous includes
    dangerous_includes_found = [inc for inc in spf_result.all_includes if inc.get('dangerous', False)]
    safe_includes_found = [inc for inc in spf_result.all_includes if not inc.get('dangerous', False)]

    # Extract dangerous IP ranges
    dangerous_ip_ranges_found = [ipr for ipr in spf_result.all_ip_ranges if ipr.get('dangerous', False)]
    safe_ip_ranges_found = [ipr for ipr in spf_result.all_ip_ranges if not ipr.get('dangerous', False)]

    # Extract dangerous IP addresses
    dangerous_ip_addresses_found = [ipa for ipa in spf_result.all_ip_addresses if ipa.get('dangerous', False)]
    safe_ip_addresses_found = [ipa for ipa in spf_result.all_ip_addresses if not ipa.get('dangerous', False)]

    # Add to Excel lists
    for inc in dangerous_includes_found:
        dangerous_includes_list.append({
            'Record ID': record_id,
            'Include': inc['include'],
            'Service Type': inc.get('service_type', 'N/A'),
            'Service Name': inc.get('service_name', 'N/A'),
            'SPF Record': spf_record
        })

    for inc in spf_result.all_includes:
        all_includes_list.append({
            'Record ID': record_id,
            'Include': inc['include'],
            'Dangerous': 'Yes' if inc.get('dangerous', False) else 'No',
            'Service Type': inc.get('service_type', 'N/A'),
            'Service Name': inc.get('service_name', 'N/A'),
            'SPF Record': spf_record
        })

    for ipr in dangerous_ip_ranges_found:
        dangerous_ip_ranges_list.append({
            'Record ID': record_id,
            'IP Range': ipr['ip_range'],
            'Service Type': ipr.get('service_type', 'N/A'),
            'Service Name': ipr.get('service_name', 'N/A'),
            'SPF Record': spf_record
        })

    for ipr in spf_result.all_ip_ranges:
        all_ip_ranges_list.append({
            'Record ID': record_id,
            'IP Range': ipr['ip_range'],
            'Dangerous': 'Yes' if ipr.get('dangerous', False) else 'No',
            'SPF Record': spf_record
        })

    for ipa in dangerous_ip_addresses_found:
        dangerous_ip_addresses_list.append({
            'Record ID': record_id,
            'IP Address': ipa['ip'],
            'Service Type': ipa.get('service_type', 'N/A'),
            'Service Name': ipa.get('service_name', 'N/A'),
            'SPF Record': spf_record
        })

    for ipa in spf_result.all_ip_addresses:
        all_ip_addresses_list.append({
            'Record ID': record_id,
            'IP Address': ipa['ip'],
            'Dangerous': 'Yes' if ipa.get('dangerous', False) else 'No',
            'SPF Record': spf_record
        })

    # Display findings
    print(f"  Includes: {len(spf_result.all_includes)} total")
    if dangerous_includes_found:
        print(f"  DANGEROUS INCLUDES: {len(dangerous_includes_found)}")
        for inc in dangerous_includes_found:
            print(f"    - {inc['include']} ({inc.get('service_type', 'N/A')}: {inc.get('service_name', 'N/A')})")

    print(f"  IP Ranges: {len(spf_result.all_ip_ranges)} total")
    if dangerous_ip_ranges_found:
        print(f"  DANGEROUS IP RANGES: {len(dangerous_ip_ranges_found)}")
        for ipr in dangerous_ip_ranges_found:
            print(f"    - {ipr['ip_range']} ({ipr.get('service_type', 'N/A')}: {ipr.get('service_name', 'N/A')})")

    print(f"  IP Addresses: {len(spf_result.all_ip_addresses)} total")
    if dangerous_ip_addresses_found:
        print(f"  DANGEROUS IP ADDRESSES: {len(dangerous_ip_addresses_found)}")
        for ipa in dangerous_ip_addresses_found:
            print(f"    - {ipa['ip']} ({ipa.get('service_type', 'N/A')}: {ipa.get('service_name', 'N/A')})")

    print(f"  Issues detected: {len(spf_result.issues)}")
    print(f"  ALL qualifier: {spf_result.all_qualifier}")

    # Store result
    all_results.append({
        'record_id': record_id,
        'spf_record': spf_record,
        'includes': {
            'total': len(spf_result.all_includes),
            'dangerous': len(dangerous_includes_found),
            'safe': len(safe_includes_found),
            'details': dangerous_includes_found
        },
        'ip_ranges': {
            'total': len(spf_result.all_ip_ranges),
            'dangerous': len(dangerous_ip_ranges_found),
            'safe': len(safe_ip_ranges_found),
            'details': dangerous_ip_ranges_found
        },
        'ip_addresses': {
            'total': len(spf_result.all_ip_addresses),
            'dangerous': len(dangerous_ip_addresses_found),
            'safe': len(safe_ip_addresses_found),
            'details': dangerous_ip_addresses_found
        },
        'all_qualifier': spf_result.all_qualifier,
        'issues': [issue.to_dict() for issue in spf_result.issues]
    })

print("\n" + "=" * 80)
print("[Generating Outputs]")

# 1. JSON export
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
json_filename = f"./output/spf_analysis_{timestamp}.json"

with open(json_filename, 'w', encoding='utf-8') as f:
    json.dump(all_results, f, indent=2, ensure_ascii=False)

print(f"  JSON: {json_filename}")

# 2. Excel export
excel_filename = f"./output/spf_analysis_{timestamp}.xlsx"

with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
    # Summary sheet
    summary_data = []
    for result in all_results:
        summary_data.append({
            'Record ID': result['record_id'],
            'Total Includes': result['includes']['total'],
            'Dangerous Includes': result['includes']['dangerous'],
            'Total IP Ranges': result['ip_ranges']['total'],
            'Dangerous IP Ranges': result['ip_ranges']['dangerous'],
            'Total IP Addresses': result['ip_addresses']['total'],
            'Dangerous IP Addresses': result['ip_addresses']['dangerous'],
            'ALL Qualifier': result['all_qualifier'],
            'SPF Record': result['spf_record'][:100] + ('...' if len(result['spf_record']) > 100 else '')
        })

    df_summary = pd.DataFrame(summary_data)
    df_summary.to_excel(writer, sheet_name='Summary', index=False)
    print(f"  Excel - Summary: {len(summary_data)} records")

    # All Includes sheet
    if all_includes_list:
        df_all_includes = pd.DataFrame(all_includes_list)
        df_all_includes.to_excel(writer, sheet_name='All Includes', index=False)
        print(f"  Excel - All Includes: {len(all_includes_list)} entries")

    # Dangerous Includes sheet
    if dangerous_includes_list:
        df_dangerous_includes = pd.DataFrame(dangerous_includes_list)
        df_dangerous_includes.to_excel(writer, sheet_name='Dangerous Includes', index=False)
        print(f"  Excel - Dangerous Includes: {len(dangerous_includes_list)} entries")
    else:
        pd.DataFrame([{'Message': 'No dangerous includes found'}]).to_excel(writer, sheet_name='Dangerous Includes', index=False)
        print(f"  Excel - Dangerous Includes: None found")

    # All IP Ranges sheet
    if all_ip_ranges_list:
        df_all_ip_ranges = pd.DataFrame(all_ip_ranges_list)
        df_all_ip_ranges.to_excel(writer, sheet_name='All IP Ranges', index=False)
        print(f"  Excel - All IP Ranges: {len(all_ip_ranges_list)} entries")

    # Dangerous IP Ranges sheet
    if dangerous_ip_ranges_list:
        df_dangerous_ip_ranges = pd.DataFrame(dangerous_ip_ranges_list)
        df_dangerous_ip_ranges.to_excel(writer, sheet_name='Dangerous IP Ranges', index=False)
        print(f"  Excel - Dangerous IP Ranges: {len(dangerous_ip_ranges_list)} entries")
    else:
        pd.DataFrame([{'Message': 'No dangerous IP ranges found'}]).to_excel(writer, sheet_name='Dangerous IP Ranges', index=False)
        print(f"  Excel - Dangerous IP Ranges: None found")

    # All IP Addresses sheet
    if all_ip_addresses_list:
        df_all_ip_addresses = pd.DataFrame(all_ip_addresses_list)
        df_all_ip_addresses.to_excel(writer, sheet_name='All IP Addresses', index=False)
        print(f"  Excel - All IP Addresses: {len(all_ip_addresses_list)} entries")

    # Dangerous IP Addresses sheet
    if dangerous_ip_addresses_list:
        df_dangerous_ip_addresses = pd.DataFrame(dangerous_ip_addresses_list)
        df_dangerous_ip_addresses.to_excel(writer, sheet_name='Dangerous IP Addresses', index=False)
        print(f"  Excel - Dangerous IP Addresses: {len(dangerous_ip_addresses_list)} entries")
    else:
        pd.DataFrame([{'Message': 'No dangerous IP addresses found'}]).to_excel(writer, sheet_name='Dangerous IP Addresses', index=False)
        print(f"  Excel - Dangerous IP Addresses: None found")

print(f"  Excel: {excel_filename}")

# 3. Summary statistics
total_dangerous_includes = len(dangerous_includes_list)
total_dangerous_ip_ranges = len(dangerous_ip_ranges_list)
total_dangerous_ip_addresses = len(dangerous_ip_addresses_list)
total_includes = len(all_includes_list)
total_ip_ranges = len(all_ip_ranges_list)
total_ip_addresses = len(all_ip_addresses_list)

print("\n" + "=" * 80)
print("[Summary]")
print(f"  SPF Records analyzed: {len(spf_records)}")
print(f"  Total includes found: {total_includes}")
print(f"  Dangerous includes: {total_dangerous_includes}")
print(f"  Total IP ranges found: {total_ip_ranges}")
print(f"  Dangerous IP ranges: {total_dangerous_ip_ranges}")
print(f"  Total IP addresses found: {total_ip_addresses}")
print(f"  Dangerous IP addresses: {total_dangerous_ip_addresses}")
print("=" * 80)
print("\nDone!")
