"""
Test IP overlap detection with a real dangerous range example.
"""
import sys
import io

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker

print("=" * 80)
print("IP Range Overlap Detection - Real World Test")
print("=" * 80)

# Initialize
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

print(f"\nLoaded {len(data_loaders.dangerous_ip_ranges)} dangerous IP ranges:")
for dangerous_range in data_loaders.dangerous_ip_ranges:
    print(f"  - {dangerous_range.ip_range} ({dangerous_range.service_name})")

spf_checker = SPFChecker(data_loaders=data_loaders)

# Test cases with SPF records containing overlapping IP ranges
# Using the real dangerous range from the CSV: 192.168.1.0/24 (Test Service)
test_cases = [
    {
        'spf': 'v=spf1 ip4:192.168.1.0/24 -all',
        'description': 'Exact match with dangerous range'
    },
    {
        'spf': 'v=spf1 ip4:192.168.1.0/25 -all',
        'description': 'Subnet of dangerous range (192.168.1.0-127)'
    },
    {
        'spf': 'v=spf1 ip4:192.168.0.0/23 -all',
        'description': 'Contains dangerous range (192.168.0.0-192.168.1.255)'
    },
    {
        'spf': 'v=spf1 ip4:192.168.1.128/26 -all',
        'description': 'Partial overlap with dangerous range (192.168.1.128-191)'
    },
    {
        'spf': 'v=spf1 ip4:10.0.0.0/24 -all',
        'description': 'No overlap (completely different range)'
    },
    {
        'spf': 'v=spf1 ip4:192.168.0.0/16 -all',
        'description': 'Large range containing multiple dangerous ranges'
    }
]

for i, test in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"Test {i}: {test['description']}")
    print(f"{'='*80}")
    print(f"SPF Record: {test['spf']}")

    result = spf_checker.check_record(test['spf'], f"test-{i}")

    print(f"\nResult:")
    print(f"  Issues: {len(result.issues)}")
    print(f"  IP Ranges found: {len(result.all_ip_ranges)}")

    if result.all_ip_ranges:
        for ip_range in result.all_ip_ranges:
            print(f"\n  IP Range: {ip_range['ip_range']}")
            print(f"    Dangerous: {ip_range.get('dangerous', False)}")

            if ip_range.get('dangerous'):
                match_type = ip_range.get('match_type', 'unknown')
                print(f"    Match Type: {match_type}")

                if match_type == 'subnet':
                    print(f"    ✓ This range is a subnet of a dangerous range")

                elif match_type == 'contains_dangerous_subnet':
                    print(f"    ✓ This range contains dangerous subnet: {ip_range.get('dangerous_subnet')}")

                elif match_type == 'partial_overlap':
                    print(f"    ✓ Partial overlap detected!")
                    print(f"       Dangerous range: {ip_range.get('dangerous_range')}")
                    print(f"       Overlap start: {ip_range.get('overlap_start')}")
                    print(f"       Overlap end: {ip_range.get('overlap_end')}")
                    print(f"       Overlap count: {ip_range.get('overlap_count'):,} IPs")

                print(f"    Service Type: {ip_range.get('service_type', 'N/A')}")
                print(f"    Service Name: {ip_range.get('service_name', 'N/A')}")

    if result.issues:
        print(f"\n  Issues detected:")
        for issue in result.issues:
            print(f"    - [{issue.severity.value}] {issue.title}")

print("\n" + "=" * 80)
print("Test with Mailjet ranges (real SPF)")
print("=" * 80)

# Mailjet uses these ranges: 87.253.232.0/21, 185.189.236.0/22, etc.
mailjet_spf = "v=spf1 include:spf.mailjet.com -all"

print(f"\nSPF Record: {mailjet_spf}")
result = spf_checker.check_record(mailjet_spf, "mailjet-test")

print(f"\nMailjet resolved IP ranges ({len(result.all_ip_ranges)} total):")
for ip_range in result.all_ip_ranges[:10]:  # Show first 10
    dangerous = "DANGEROUS" if ip_range.get('dangerous') else "safe"
    print(f"  - {ip_range['ip_range']} ({dangerous})")
    if ip_range.get('dangerous'):
        match_type = ip_range.get('match_type', 'N/A')
        print(f"      Match type: {match_type}")
        if match_type == 'partial_overlap':
            print(f"      Overlap: {ip_range.get('overlap_start')} - {ip_range.get('overlap_end')}")

if len(result.all_ip_ranges) > 10:
    print(f"  ... and {len(result.all_ip_ranges) - 10} more")

print("\n" + "=" * 80)
print("Test completed!")
print("=" * 80)
