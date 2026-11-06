"""
Test to demonstrate that parsed structures from checkdmarc are included in JSON output.
"""
import sys
import io
import json

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker
from lib.checkers.dmarc_checker import DMARCChecker

print("=" * 80)
print("Parsed Structures in JSON Export - Demonstration")
print("=" * 80)

# Initialize
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

spf_checker = SPFChecker(data_loaders=data_loaders)
dmarc_checker = DMARCChecker()

print("\n" + "=" * 80)
print("Test 1: SPF with includes (Mailjet)")
print("=" * 80)

spf_record = "v=spf1 include:spf.mailjet.com -all"
print(f"\nSPF Record: {spf_record}")

spf_result = spf_checker.check_record(spf_record, "mailjet-test")

print(f"\nResult:")
print(f"  Domain: {spf_result.domain}")
print(f"  Issues: {len(spf_result.issues)}")
print(f"  Includes: {len(spf_result.all_includes)}")
print(f"  IP Ranges: {len(spf_result.all_ip_ranges)}")

# Export to dict
result_dict = spf_result.to_dict()

print(f"\nJSON Output includes:")
print(f"  - parsed_spf: {result_dict.get('parsed_spf') is not None}")

if result_dict.get('parsed_spf'):
    parsed = result_dict['parsed_spf']
    print(f"  - dns_lookups: {parsed.get('dns_lookups')}")
    print(f"  - mechanisms: {len(parsed.get('parsed', {}).get('mechanisms', []))}")

    # Show the first include's parsed structure
    if 'parsed' in parsed and 'mechanisms' in parsed['parsed']:
        for mech in parsed['parsed']['mechanisms']:
            if mech.get('mechanism') == 'include':
                print(f"\n  Include '{mech['value']}' contains:")
                print(f"    - Record: {mech.get('record')}")
                print(f"    - DNS lookups: {mech.get('dns_lookups')}")
                if 'parsed' in mech:
                    nested_mechs = mech['parsed'].get('mechanisms', [])
                    print(f"    - Nested mechanisms: {len(nested_mechs)}")
                    for nm in nested_mechs[:3]:  # Show first 3
                        print(f"      • {nm.get('mechanism')}: {nm.get('value')}")
                    if len(nested_mechs) > 3:
                        print(f"      ... and {len(nested_mechs) - 3} more")

print("\n" + "=" * 80)
print("Test 2: DMARC Record")
print("=" * 80)

dmarc_record = "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; pct=100"
print(f"\nDMARC Record: {dmarc_record}")

dmarc_result = dmarc_checker.check_record(dmarc_record, "example.com")

print(f"\nResult:")
print(f"  Domain: {dmarc_result.domain}")
print(f"  Policy: {dmarc_result.policy}")
print(f"  Subdomain Policy: {dmarc_result.subdomain_policy}")
print(f"  Issues: {len(dmarc_result.issues)}")

# Export to dict
result_dict = dmarc_result.to_dict()

print(f"\nJSON Output includes:")
print(f"  - parsed_dmarc: {result_dict.get('parsed_dmarc') is not None}")

if result_dict.get('parsed_dmarc'):
    parsed = result_dict['parsed_dmarc']
    print(f"  - tags: {list(parsed.get('tags', {}).keys())}")
    print(f"  - warnings: {len(parsed.get('warnings', []))}")

    # Show all tags
    if 'tags' in parsed:
        print(f"\n  All DMARC tags:")
        for tag_name, tag_data in parsed['tags'].items():
            explicit = " (explicit)" if tag_data.get('explicit') else " (default)"
            print(f"    - {tag_name}: {tag_data.get('value')}{explicit}")

print("\n" + "=" * 80)
print("Test 3: JSON Export with both")
print("=" * 80)

combined = {
    'spf': spf_result.to_dict(),
    'dmarc': dmarc_result.to_dict()
}

# Save to file
output_file = './output/test_parsed_structures.json'
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(combined, f, indent=2, ensure_ascii=False)

print(f"\nSaved to: {output_file}")

# Calculate size
json_str = json.dumps(combined, indent=2)
print(f"JSON size: {len(json_str):,} characters")

# Show structure overview
print(f"\nStructure overview:")
print(f"  spf:")
print(f"    - Basic fields: domain, spf_record, issues, statistics, etc.")
print(f"    - Analysis: all_includes, all_ip_ranges, all_ip_addresses")
print(f"    - parsed_spf: Complete checkdmarc structure with:")
print(f"      • dns_lookups, void_dns_lookups")
print(f"      • parsed.mechanisms[] (recursive includes)")
print(f"      • parsed.all (qualifier)")
print(f"      • warnings[]")

print(f"\n  dmarc:")
print(f"    - Basic fields: domain, dmarc_record, policy, percentage, etc.")
print(f"    - parsed_dmarc: Complete checkdmarc structure with:")
print(f"      • tags (p, sp, pct, rua, ruf, aspf, adkim, etc.)")
print(f"      • Each tag has: value, explicit")
print(f"      • warnings[]")

print("\n" + "=" * 80)
print("Benefits")
print("=" * 80)
print("""
✓ Complete Data: All information from checkdmarc is preserved
✓ Recursive Structures: Includes are fully resolved with nested mechanisms
✓ Original + Analysis: Both raw parsed data and our analysis
✓ Reusability: Can re-import parsed structures for re-analysis
✓ Debugging: Full visibility into what checkdmarc parsed
✓ Extensibility: Can add custom processing without re-parsing
""")

print("=" * 80)
print("Done!")
print("=" * 80)
