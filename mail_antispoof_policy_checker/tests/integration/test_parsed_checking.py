"""
Test script to demonstrate check_parsed() methods.
Shows how to use already parsed SPF/DMARC structures from checkdmarc.
"""
import json
from checkdmarc.spf import parse_spf_record
from checkdmarc.dmarc import parse_dmarc_record
from lib.checkers.spf_checker import SPFChecker
from lib.checkers.dmarc_checker import DMARCChecker
from lib.data.loaders import DataLoaders

print("=" * 80)
print("Testing check_parsed() Methods")
print("=" * 80)

# Initialize checkers
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

spf_checker = SPFChecker(data_loaders=data_loaders)
dmarc_checker = DMARCChecker()

# Test SPF with check_parsed()
print("\n" + "=" * 80)
print("1. SPF Analysis with check_parsed()")
print("=" * 80)

spf_record = "v=spf1 include:mx.ovh.com include:spf.mailjet.com -all"
print(f"\nOriginal SPF Record: {spf_record}")

# Step 1: Parse with checkdmarc
print("\n[Step 1] Parsing with checkdmarc.spf.parse_spf_record()...")
parsed_spf = parse_spf_record(spf_record, "example.com", parked=False, timeout=5.0)

print(f"Parsed structure keys: {list(parsed_spf.keys())}")
print(f"DNS lookups: {parsed_spf.get('dns_lookups', 0)}")
print(f"ALL qualifier: {parsed_spf['parsed']['all']}")

# Step 2: Analyze with check_parsed()
print("\n[Step 2] Analyzing with SPFChecker.check_parsed()...")
spf_result = spf_checker.check_parsed(parsed_spf, "example.com")

print(f"\nDomain: {spf_result.domain}")
print(f"SPF Record: {spf_result.spf_record}")
print(f"ALL Qualifier: {spf_result.all_qualifier}")
print(f"DNS Lookups: {spf_result.lookup_count}")
print(f"Issues: {len(spf_result.issues)}")

if spf_result.all_includes:
    print(f"\nIncludes found: {len(spf_result.all_includes)}")
    for inc in spf_result.all_includes:
        dangerous = "DANGEROUS" if inc.get('dangerous') else "safe"
        print(f"  - {inc['include']} ({dangerous})")
        if inc.get('dangerous'):
            print(f"    Service Type: {inc.get('service_type')}")
            print(f"    Service Name: {inc.get('service_name')}")

if spf_result.issues:
    print(f"\nIssues detected:")
    for issue in spf_result.issues:
        print(f"  - [{issue.severity.value}] {issue.title}")

# Test DMARC with check_parsed()
print("\n" + "=" * 80)
print("2. DMARC Analysis with check_parsed()")
print("=" * 80)

dmarc_record = "v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com; pct=100"
print(f"\nOriginal DMARC Record: {dmarc_record}")

# Step 1: Parse with checkdmarc
print("\n[Step 1] Parsing with checkdmarc.dmarc.parse_dmarc_record()...")
parsed_dmarc = parse_dmarc_record(dmarc_record, "example.com", include_tag_descriptions=False)

print(f"Parsed structure keys: {list(parsed_dmarc.keys())}")
print(f"Policy (p): {parsed_dmarc['tags']['p']['value']}")
print(f"Subdomain Policy (sp): {parsed_dmarc['tags']['sp']['value']}")

# Step 2: Analyze with check_parsed()
print("\n[Step 2] Analyzing with DMARCChecker.check_parsed()...")
dmarc_result = dmarc_checker.check_parsed(parsed_dmarc, "example.com")

print(f"\nDomain: {dmarc_result.domain}")
print(f"DMARC Record: {dmarc_result.dmarc_record}")
print(f"Policy: {dmarc_result.policy}")
print(f"Subdomain Policy: {dmarc_result.subdomain_policy}")
print(f"Issues: {len(dmarc_result.issues)}")

if dmarc_result.issues:
    print(f"\nIssues detected:")
    for issue in dmarc_result.issues:
        print(f"  - [{issue.severity.value}] {issue.title}")
        print(f"    {issue.detail}")

# Compare the 3 methods
print("\n" + "=" * 80)
print("3. Comparison of the 3 Methods")
print("=" * 80)

print("\nSPFChecker now offers 3 methods:")
print("  1. check(domain) - Query DNS for domain, parse, and analyze")
print("     Use when: You have a domain name")
print()
print("  2. check_record(spf_record) - Parse SPF string, resolve includes, and analyze")
print("     Use when: You have an SPF record string")
print()
print("  3. check_parsed(parsed_spf) - Analyze already parsed structure")
print("     Use when: You already have parsed SPF from checkdmarc")

print("\nDMARCChecker offers the same 3 methods:")
print("  1. check(domain)")
print("  2. check_record(dmarc_record)")
print("  3. check_parsed(parsed_dmarc)")

print("\n" + "=" * 80)
print("Benefits of check_parsed():")
print("=" * 80)
print("  - Reuse existing parsed structures (avoid re-parsing)")
print("  - Integrate with custom parsing pipelines")
print("  - Separate parsing from analysis logic")
print("  - Better performance when processing multiple records")

# Export combined result
print("\n" + "=" * 80)
print("4. JSON Export")
print("=" * 80)

combined_result = {
    'spf': spf_result.to_dict(),
    'dmarc': dmarc_result.to_dict()
}

with open('./output/test_check_parsed.json', 'w', encoding='utf-8') as f:
    json.dump(combined_result, f, indent=2, ensure_ascii=False)

print(f"\nJSON saved to: ./output/test_check_parsed.json")

print("\n" + "=" * 80)
print("Test completed successfully!")
print("=" * 80)
