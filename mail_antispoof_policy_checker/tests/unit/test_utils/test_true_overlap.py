"""
Test TRUE partial overlap (neither range is a subnet of the other).
Dangerous range: 109.234.163.0/24 (109.234.163.0 - 109.234.163.255)
"""
import sys
import io

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker
from lib.utils.ip_utils import IPUtils

print("=" * 80)
print("TRUE Partial Overlap Detection")
print("=" * 80)

# Initialize
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

print(f"\nDangerous range: 109.234.163.0/24")
print(f"  Start: 109.234.163.0")
print(f"  End:   109.234.163.255")

spf_checker = SPFChecker(data_loaders=data_loaders)
ip_utils = IPUtils()

print("\n" + "=" * 80)
print("Creating TRUE partial overlap scenarios")
print("=" * 80)

# For a TRUE partial overlap, we need a range that:
# - Overlaps with 109.234.163.0/24
# - Is NOT a subnet of 109.234.163.0/24
# - Does NOT contain 109.234.163.0/24

test_cases = [
    {
        'spf': 'v=spf1 ip4:109.234.163.128/23 -all',
        'description': 'Starts inside (163.128), extends beyond (164.127)',
        'expected_overlap': '109.234.163.128 - 109.234.163.255'
    },
    {
        'spf': 'v=spf1 ip4:109.234.162.128/23 -all',
        'description': 'Starts before (162.128), ends inside (163.127)',
        'expected_overlap': '109.234.163.0 - 109.234.163.127'
    },
    {
        'spf': 'v=spf1 ip4:109.234.163.64/25 -all',
        'description': 'Subset - should be detected as "subnet"',
        'expected_overlap': 'N/A (subnet)'
    }
]

for i, test in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"Test {i}: {test['description']}")
    print(f"{'='*80}")

    # Extract IP range from SPF
    spf_range = test['spf'].split('ip4:')[1].split()[0]
    print(f"SPF Range: {spf_range}")
    print(f"Expected overlap: {test['expected_overlap']}")

    # Check relationship with dangerous range
    dangerous_range = '109.234.163.0/24'
    is_subnet = ip_utils.is_range_in_range(spf_range, dangerous_range)
    contains_dangerous = ip_utils.is_range_in_range(dangerous_range, spf_range)
    overlap = ip_utils.get_range_overlap(spf_range, dangerous_range)

    print(f"\nRelationship analysis:")
    print(f"  SPF is subnet of dangerous? {is_subnet}")
    print(f"  SPF contains dangerous? {contains_dangerous}")
    print(f"  Overlap exists? {overlap is not None}")

    if overlap:
        print(f"  Overlap details:")
        print(f"    Start: {overlap['ip_start']}")
        print(f"    End:   {overlap['ip_end']}")
        print(f"    Count: {overlap['count']} IPs")

    # Test with SPFChecker
    print(f"\nSPFChecker result:")
    result = spf_checker.check_record(test['spf'], f"test-{i}")

    if result.all_ip_ranges:
        for ip_range in result.all_ip_ranges:
            if ip_range.get('dangerous'):
                match_type = ip_range.get('match_type')
                print(f"  ✓ DANGEROUS")
                print(f"  Match type: {match_type}")

                if match_type == 'partial_overlap':
                    print(f"  🎯 TRUE PARTIAL OVERLAP DETECTED!")
                    print(f"     Dangerous range: {ip_range.get('dangerous_range')}")
                    print(f"     Overlap: {ip_range.get('overlap_start')} - {ip_range.get('overlap_end')}")
                    print(f"     Count: {ip_range.get('overlap_count')} IPs")
                elif match_type == 'subnet':
                    print(f"  Detected as subnet of dangerous range")
                elif match_type == 'contains_dangerous_subnet':
                    print(f"  Detected as containing dangerous subnet: {ip_range.get('dangerous_subnet')}")
            else:
                print(f"  ✗ Not dangerous")

print("\n" + "=" * 80)
print("Analysis of why true partial overlap is rare:")
print("=" * 80)
print("""
For a TRUE partial overlap (neither is a subset of the other), you need:
- Two ranges that share some IPs
- But neither range is completely inside the other

This happens when:
1. Range starts BEFORE dangerous and ends INSIDE dangerous
   Example: 109.234.162.128/23 overlaps with 109.234.163.0/24
   (starts at 162.128, ends at 163.127)

2. Range starts INSIDE dangerous and extends BEYOND dangerous
   Example: 109.234.163.128/23 overlaps with 109.234.163.0/24
   (starts at 163.128, ends at 164.127)

However, CIDR notation makes this tricky because subnets must align
on power-of-2 boundaries!
""")

print("\n" + "=" * 80)
print("Done!")
print("=" * 80)
