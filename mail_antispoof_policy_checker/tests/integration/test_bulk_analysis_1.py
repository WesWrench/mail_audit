"""
Simple test script for bulk domain checking with JSON and Excel export.
"""
# -*- coding: utf-8 -*-
import sys
import io
import json
import pandas as pd
from datetime import datetime

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.checkers.spf_checker import SPFChecker
from lib.checkers.dmarc_checker import DMARCChecker
from lib.checkers.dkim_checker import DKIMChecker
from lib.data.loaders import DataLoaders

# Domains to check (from example_advanced_usage.py)
domains = [
    "alpha-asso.fr",
    "campagne-harmonie-mutuelle.fr",
    "cartonnageprevention.fr",
    "chorum.fr",
    "essentiel-sante-magazine.fr",
    "harmonieambulance.com",
    "harmonie-ambulance.com",
    "harmonie-ambulance.fr",
    "harmonieassuranceemprunteur.fr",
    "harmonie-boost.fr",
    "harmonie-fp.fr",
    "harmonie-medical-service.fr",
    "harmonie-mutuelle.fr",
    "harmoniemutuelle.net",
    "harmonie-mutuelle-ag.fr",
    "harmonie-mutuelle-italia.it",
    "harmonie-sante.fr",
    "kalivia-sante.fr",
    "kalixia.fr",
    "mon-coaching-pro.fr",
    "novaxes.fr",
    "prevadies.fr",
    "sihm.fr",
    "spheriavie.fr",
    "tp-harmonie.net",
    "groupe-vyv.fr",
    "vyv-conseil.fr",
    "vyv-es.fr"
]

print("=" * 80)
print("Mail AntiSpoof Policy Checker - Bulk Test")
print("=" * 80)

# Initialize data loaders
print("\n[Initialization]")
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()
print(f"  Loaded {len(data_loaders.dangerous_includes)} dangerous includes")
print(f"  Loaded {len(data_loaders.dangerous_ip_ranges)} dangerous IP ranges")

# Initialize checkers
spf_checker = SPFChecker(data_loaders=data_loaders)
dmarc_checker = DMARCChecker()
dkim_checker = DKIMChecker()

print(f"\n[Checking {len(domains)} domains...]")
print("  Note: DKIM checking disabled (too slow for bulk)")

# Storage for results
all_results = []
spf_issues_list = []
dmarc_issues_list = []
dkim_issues_list = []
dangerous_includes_list = []
dangerous_ip_ranges_list = []

for i, domain in enumerate(domains, 1):
    print(f"\n[{i}/{len(domains)}] Checking: {domain}")

    # Check SPF
    spf_result = spf_checker.check(domain)
    print(f"  SPF Issues: {len(spf_result.issues)}")

    # Show SPF record
    if spf_result.spf_record:
        print(f"  SPF Record: {spf_result.spf_record[:80]}{'...' if len(spf_result.spf_record) > 80 else ''}")

    # Show dangerous configurations
    dangerous_includes = [i for i in spf_result.all_includes if i.get('dangerous', False)]
    if dangerous_includes:
        print(f"  DANGEROUS INCLUDES:")
        for inc in dangerous_includes:
            print(f"    - {inc['include']} ({inc['service_type']}: {inc['service_name']})")
            print(f"      Path: {inc['path']}")

    dangerous_ranges = [r for r in spf_result.all_ip_ranges if r.get('dangerous', False)]
    if dangerous_ranges:
        print(f"  DANGEROUS IP RANGES:")
        for rng in dangerous_ranges:
            print(f"    - {rng['ip_range']}")
            if 'as_organization' in rng:
                print(f"      AS Org: {rng['as_organization']}")
            print(f"      Path: {rng['path']}")

    # Check DMARC
    dmarc_result = dmarc_checker.check(domain)
    print(f"  DMARC Issues: {len(dmarc_result.issues)}")
    if dmarc_result.dmarc_record:
        print(f"  DMARC Record: {dmarc_result.dmarc_record}")
    if dmarc_result.policy:
        print(f"  DMARC Policy: p={dmarc_result.policy}")

    # Skip DKIM for speed (uncomment if you want DKIM)
    # dkim_result = dkim_checker.check(domain)
    # print(f"  DKIM: {len(dkim_result.issues)} issues")

    # Store combined result
    result = {
        'domain': domain,
        'spf': spf_result.to_dict(),
        'dmarc': dmarc_result.to_dict(),
        # 'dkim': dkim_result.to_dict(),  # Uncomment if using DKIM
    }
    all_results.append(result)

    # Extract issues for Excel
    for issue in spf_result.issues:
        spf_issues_list.append({
            'Domain': domain,
            'SPF Record': spf_result.spf_record or 'N/A',
            'Code': issue.code,
            'Title': issue.title,
            'Severity': issue.severity.value,
            'Detail': issue.detail,
            'Resolution Path': ' -> '.join(issue.resolution_path) if issue.resolution_path else ''
        })

    # Extract dangerous includes for Excel
    for inc in spf_result.all_includes:
        if inc.get('dangerous', False):
            dangerous_includes_list.append({
                'Domain': domain,
                'Include': inc['include'],
                'Service Type': inc.get('service_type', 'N/A'),
                'Service Name': inc.get('service_name', 'N/A'),
                'Resolution Path': inc['path']
            })

    # Extract dangerous IP ranges for Excel
    for ipr in spf_result.all_ip_ranges:
        if ipr.get('dangerous', False):
            dangerous_ip_ranges_list.append({
                'Domain': domain,
                'IP Range': ipr['ip_range'],
                'Service Type': ipr.get('service_type', 'N/A'),
                'Service Name': ipr.get('service_name', 'N/A'),
                'AS Organization': ipr.get('as_organization', 'N/A'),
                'Resolution Path': ipr['path']
            })

    for issue in dmarc_result.issues:
        dmarc_issues_list.append({
            'Domain': domain,
            'DMARC Record': dmarc_result.dmarc_record or 'N/A',
            'Code': issue.code,
            'Title': issue.title,
            'Severity': issue.severity.value,
            'Detail': issue.detail
        })

    # Uncomment if using DKIM
    # selectors_found = ', '.join([s.selector for s in dkim_result.selectors_found]) if dkim_result.selectors_found else 'None'
    # for issue in dkim_result.issues:
    #     dkim_issues_list.append({
    #         'Domain': domain,
    #         'DKIM Selectors': selectors_found,
    #         'Code': issue.code,
    #         'Title': issue.title,
    #         'Severity': issue.severity.value,
    #         'Detail': issue.detail
    #     })

print("\n" + "=" * 80)
print("[Generating Outputs]")

# 1. Simple JSON export
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
json_filename = f"./output/bulk_results_{timestamp}.json"

with open(json_filename, 'w', encoding='utf-8') as f:
    json.dump(all_results, f, indent=2, ensure_ascii=False)

print(f"  JSON: {json_filename}")

# 2. Excel export with pandas
excel_filename = f"./output/bulk_results_{timestamp}.xlsx"

# Create Excel writer
with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
    # SPF sheet
    if spf_issues_list:
        df_spf = pd.DataFrame(spf_issues_list)
        df_spf.to_excel(writer, sheet_name='SPF Issues', index=False)
        print(f"  Excel - SPF: {len(spf_issues_list)} issues")
    else:
        # Create empty sheet
        pd.DataFrame([{'Domain': 'No issues found'}]).to_excel(writer, sheet_name='SPF Issues', index=False)
        print(f"  Excel - SPF: No issues")

    # DMARC sheet
    if dmarc_issues_list:
        df_dmarc = pd.DataFrame(dmarc_issues_list)
        df_dmarc.to_excel(writer, sheet_name='DMARC Issues', index=False)
        print(f"  Excel - DMARC: {len(dmarc_issues_list)} issues")
    else:
        pd.DataFrame([{'Domain': 'No issues found'}]).to_excel(writer, sheet_name='DMARC Issues', index=False)
        print(f"  Excel - DMARC: No issues")

    # DKIM sheet
    if dkim_issues_list:
        df_dkim = pd.DataFrame(dkim_issues_list)
        df_dkim.to_excel(writer, sheet_name='DKIM Issues', index=False)
        print(f"  Excel - DKIM: {len(dkim_issues_list)} issues")
    else:
        pd.DataFrame([{'Domain': 'No issues found'}]).to_excel(writer, sheet_name='DKIM Issues', index=False)
        print(f"  Excel - DKIM: No issues (not checked)")

    # Dangerous Includes sheet
    if dangerous_includes_list:
        df_dangerous_includes = pd.DataFrame(dangerous_includes_list)
        df_dangerous_includes.to_excel(writer, sheet_name='Dangerous Includes', index=False)
        print(f"  Excel - Dangerous Includes: {len(dangerous_includes_list)} entries")
    else:
        pd.DataFrame([{'Domain': 'No dangerous includes found'}]).to_excel(writer, sheet_name='Dangerous Includes', index=False)
        print(f"  Excel - Dangerous Includes: None found")

    # Dangerous IP Ranges sheet
    if dangerous_ip_ranges_list:
        df_dangerous_ip_ranges = pd.DataFrame(dangerous_ip_ranges_list)
        df_dangerous_ip_ranges.to_excel(writer, sheet_name='Dangerous IP Ranges', index=False)
        print(f"  Excel - Dangerous IP Ranges: {len(dangerous_ip_ranges_list)} entries")
    else:
        pd.DataFrame([{'Domain': 'No dangerous IP ranges found'}]).to_excel(writer, sheet_name='Dangerous IP Ranges', index=False)
        print(f"  Excel - Dangerous IP Ranges: None found")

print(f"  Excel: {excel_filename}")

# 3. Summary statistics
total_spf_issues = len(spf_issues_list)
total_dmarc_issues = len(dmarc_issues_list)
total_dkim_issues = len(dkim_issues_list)

critical_spf = sum(1 for i in spf_issues_list if i['Severity'] == 'critical')
critical_dmarc = sum(1 for i in dmarc_issues_list if i['Severity'] == 'critical')

print("\n" + "=" * 80)
print("[Summary]")
print(f"  Domains checked: {len(domains)}")
print(f"  Total SPF issues: {total_spf_issues} ({critical_spf} critical)")
print(f"  Total DMARC issues: {total_dmarc_issues} ({critical_dmarc} critical)")
print(f"  Total DKIM issues: {total_dkim_issues}")
print("=" * 80)
print("\nDone!")
