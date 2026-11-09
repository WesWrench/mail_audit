"""
Demonstration of IP overlap detection with the existing dangerous range.
Dangerous range: 109.234.163.0/24 (OS2Switch)
"""
import sys
import io

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker

print("=" * 80)
print("IP Range Overlap Detection - Demo")
print("=" * 80)

# Initialize
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

print(f"\nDangerous IP Range in database:")
for dangerous_range in data_loaders.dangerous_ip_ranges:
    print(f"  {dangerous_range.ip_range} - {dangerous_range.service_name} ({dangerous_range.type.value})")

spf_checker = SPFChecker(data_loaders=data_loaders)

print("\n" + "=" * 80)
print("Test Cases")
print("=" * 80)

# Test cases targeting the dangerous range 109.234.163.0/24
test_cases = [
    {
        'spf': 'v=spf1 ip4:109.234.163.0/24 -all',
        'description': '✓ Exact match (109.234.163.0 → 109.234.163.255)'
    },
    {
        'spf': 'v=spf1 ip4:109.234.163.0/25 -all',
        'description': '✓ Subnet (109.234.163.0 → 109.234.163.127, first half)'
    },
    {
        'spf': 'v=spf1 ip4:109.234.163.128/25 -all',
        'description': '✓ Subnet (109.234.163.128 → 109.234.163.255, second half)'
    },
    {
        'spf': 'v=spf1 ip4:109.234.0.0/16 -all',
        'description': '✓ Contains dangerous subnet (109.234.0.0 → 109.234.255.255)'
    },
    {
        'spf': 'v=spf1 ip4:109.234.162.0/23 -all',
        'description': '✓ Partial overlap (109.234.162.0-163.255, overlaps with 163.0-163.255)'
    },
    {
        'spf': 'v=spf1 ip4:109.234.163.192/26 -all',
        'description': '✓ Small subnet (109.234.163.192 → 109.234.163.255, last 64 IPs)'
    },
    {
        'spf': 'v=spf1 ip4:109.234.164.0/24 -all',
        'description': '✗ No overlap (adjacent but different range)'
    }
]

for i, test in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"Test {i}: {test['description']}")
    print(f"{'='*80}")
    print(f"SPF: {test['spf']}")

    result = spf_checker.check_record(test['spf'], f"test-{i}")

    if result.all_ip_ranges:
        for ip_range in result.all_ip_ranges:
            print(f"\nIP Range: {ip_range['ip_range']}")

            if ip_range.get('dangerous'):
                print(f"✓ DANGEROUS DETECTED!")
                match_type = ip_range.get('match_type', 'unknown')

                print(f"  Match Type: {match_type}")
                print(f"  Service Type: {ip_range.get('service_type')}")
                print(f"  Service Name: {ip_range.get('service_name')}")

                if match_type == 'subnet':
                    print(f"  → This range is a subnet of dangerous range")

                elif match_type == 'contains_dangerous_subnet':
                    print(f"  → This range CONTAINS dangerous subnet: {ip_range.get('dangerous_subnet')}")

                elif match_type == 'partial_overlap':
                    print(f"  → PARTIAL OVERLAP with: {ip_range.get('dangerous_range')}")
                    print(f"     Overlap start: {ip_range.get('overlap_start')}")
                    print(f"     Overlap end:   {ip_range.get('overlap_end')}")
                    print(f"     IPs affected:  {ip_range.get('overlap_count'):,} IPs")
            else:
                print(f"✗ Not dangerous (no overlap)")

    if result.issues:
        print(f"\nIssues:")
        for issue in result.issues:
            print(f"  [{issue.severity.value}] {issue.title}")

print("\n" + "=" * 80)
print("Summary")
print("=" * 80)
print("""
The overlap detection now supports 3 match types:

1. SUBNET: The SPF range is completely inside a dangerous range
   Example: SPF has 109.234.163.0/25, dangerous is 109.234.163.0/24

2. CONTAINS_DANGEROUS_SUBNET: The SPF range contains a dangerous range
   Example: SPF has 109.234.0.0/16, dangerous is 109.234.163.0/24

3. PARTIAL_OVERLAP: The ranges partially overlap (neither contains the other)
   Example: SPF has 109.234.162.0/23, dangerous is 109.234.163.0/24
   Overlap: 109.234.163.0 - 109.234.163.255 (256 IPs)

All exports (JSON, Excel) include:
- match_type
- overlap_start, overlap_end, overlap_count (for partial overlaps)
- dangerous_subnet, dangerous_range (context)
""")

print("=" * 80)
print("Done!")
print("=" * 80)
