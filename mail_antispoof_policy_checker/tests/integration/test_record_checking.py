"""
Test script to demonstrate check_record() methods for SPF, DMARC, and DKIM.
"""
import json
from lib.checkers.spf_checker import SPFChecker
from lib.checkers.dmarc_checker import DMARCChecker
from lib.checkers.dkim_checker import DKIMChecker
from lib.data.loaders import DataLoaders

print("=" * 80)
print("Testing check_record() Methods for SPF, DMARC, and DKIM")
print("=" * 80)

# Initialize checkers
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

spf_checker = SPFChecker(data_loaders=data_loaders)
dmarc_checker = DMARCChecker()
dkim_checker = DKIMChecker()

# Test SPF
print("\n" + "=" * 80)
print("1. SPF Record Analysis")
print("=" * 80)

spf_record = "v=spf1 include:spf.mailjet.com ip4:84.96.72.121 -all"
print(f"\nRecord: {spf_record}")

spf_result = spf_checker.check_record(spf_record, "test-spf-01")
print(f"\nDomain/ID: {spf_result.domain}")
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

if spf_result.all_ip_ranges:
    print(f"\nIP Ranges found: {len(spf_result.all_ip_ranges)}")
    for ipr in spf_result.all_ip_ranges:
        print(f"  - {ipr['ip_range']}")

# Test DMARC
print("\n" + "=" * 80)
print("2. DMARC Record Analysis")
print("=" * 80)

dmarc_record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
print(f"\nRecord: {dmarc_record}")

dmarc_result = dmarc_checker.check_record(dmarc_record, "test-dmarc-01")
print(f"\nDomain/ID: {dmarc_result.domain}")
print(f"DMARC Record: {dmarc_result.dmarc_record}")
print(f"Policy: {dmarc_result.policy}")
print(f"Subdomain Policy: {dmarc_result.subdomain_policy}")
print(f"Issues: {len(dmarc_result.issues)}")

if dmarc_result.issues:
    print("\nIssues detected:")
    for issue in dmarc_result.issues:
        print(f"  - [{issue.severity.value}] {issue.title}")
        print(f"    {issue.detail}")

# Test DKIM
print("\n" + "=" * 80)
print("3. DKIM Record Analysis")
print("=" * 80)

dkim_record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGMjj8MVaESl30KSPYdLaEreSYzvOVh15u9YKAmTLgk1ecr4BCRq3Vkg3Xa2QrEQWbIvQj4wkwAJLGzOBcHs8kDpQTHp2zLMHCPTJzcQDKgJL71c0MQQdTmFYtVLsJJcfLJG1E61xgjAHXeXxMq0xbCx5MlqOiukPU0r1XjlPbzwIDAQAB"
print(f"\nRecord: {dkim_record}")

dkim_result = dkim_checker.check_record(dkim_record, selector="selector1", record_id="test-dkim-01")
print(f"\nDomain/ID: {dkim_result.domain}")
print(f"Selectors tested: {dkim_result.selectors_tested}")
print(f"Selectors found: {len(dkim_result.selectors_found)}")
print(f"Issues: {len(dkim_result.issues)}")

if dkim_result.selectors_found:
    for selector_info in dkim_result.selectors_found:
        print(f"\nSelector: {selector_info.selector}")
        print(f"  Key Type: {selector_info.key_type}")
        print(f"  Key Size: {selector_info.key_size} bits")
        print(f"  Record: {selector_info.record[:80]}...")
        if selector_info.issues:
            print(f"  Issues:")
            for issue in selector_info.issues:
                print(f"    - [{issue.severity.value}] {issue.title}")

# Export results to JSON
print("\n" + "=" * 80)
print("4. JSON Export")
print("=" * 80)

combined_result = {
    'spf': spf_result.to_dict(),
    'dmarc': dmarc_result.to_dict(),
    'dkim': dkim_result.to_dict()
}

json_output = json.dumps(combined_result, indent=2)
print("\nCombined JSON result (first 500 chars):")
print(json_output[:500] + "...")

# Save to file
with open('./output/test_check_records.json', 'w', encoding='utf-8') as f:
    f.write(json_output)

print(f"\nFull JSON saved to: ./output/test_check_records.json")

print("\n" + "=" * 80)
print("Test completed successfully!")
print("=" * 80)
