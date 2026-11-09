"""
Test script to demonstrate IP range overlap detection.
Shows how the checker detects exact matches, subnets, and partial overlaps.
"""
import sys
import io

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.utils.ip_utils import IPUtils

print("=" * 80)
print("IP Range Overlap Detection - Test Cases")
print("=" * 80)

# Test cases
test_cases = [
    {
        'name': 'Exact Match',
        'range1': '192.168.1.0/24',
        'range2': '192.168.1.0/24',
        'expected': 'Complete overlap (identical ranges)'
    },
    {
        'name': 'Subnet (range1 ⊂ range2)',
        'range1': '192.168.1.0/25',
        'range2': '192.168.1.0/24',
        'expected': 'range1 is a subnet of range2'
    },
    {
        'name': 'Superset (range2 ⊂ range1)',
        'range1': '192.168.0.0/23',
        'range2': '192.168.1.0/24',
        'expected': 'range2 is a subnet of range1'
    },
    {
        'name': 'Partial Overlap',
        'range1': '192.168.1.128/25',
        'range2': '192.168.1.64/26',
        'expected': 'Partial overlap (neither contains the other)'
    },
    {
        'name': 'Adjacent (no overlap)',
        'range1': '192.168.1.0/25',
        'range2': '192.168.1.128/25',
        'expected': 'No overlap (adjacent ranges)'
    },
    {
        'name': 'No Overlap',
        'range1': '192.168.1.0/24',
        'range2': '10.0.0.0/8',
        'expected': 'No overlap'
    },
    {
        'name': 'Real World Example 1',
        'range1': '87.253.232.0/21',  # Mailjet range
        'range2': '87.253.0.0/16',    # Larger range containing it
        'expected': 'range1 is a subnet of range2'
    },
    {
        'name': 'Real World Example 2',
        'range1': '185.189.236.0/22',  # Mailjet
        'range2': '185.189.237.0/24',  # Overlapping range
        'expected': 'Partial overlap'
    }
]

ip_utils = IPUtils()

for i, test in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"Test Case {i}: {test['name']}")
    print(f"{'='*80}")
    print(f"Range 1: {test['range1']}")
    print(f"Range 2: {test['range2']}")
    print(f"Expected: {test['expected']}")
    print()

    # Check if they overlap
    overlaps = ip_utils.ranges_overlap(test['range1'], test['range2'])
    print(f"Overlaps: {overlaps}")

    if overlaps:
        # Get overlap details
        overlap_info = ip_utils.get_range_overlap(test['range1'], test['range2'])
        if overlap_info:
            print(f"\nOverlap Details:")
            print(f"  Start IP: {overlap_info['ip_start']}")
            print(f"  End IP:   {overlap_info['ip_end']}")
            print(f"  Count:    {overlap_info['count']:,} IPs")

        # Check relationship
        range1_in_range2 = ip_utils.is_range_in_range(test['range1'], test['range2'])
        range2_in_range1 = ip_utils.is_range_in_range(test['range2'], test['range1'])

        print(f"\nRelationship:")
        if range1_in_range2 and range2_in_range1:
            print(f"  ✓ Identical ranges")
        elif range1_in_range2:
            print(f"  ✓ Range 1 is a SUBNET of Range 2")
        elif range2_in_range1:
            print(f"  ✓ Range 2 is a SUBNET of Range 1")
        else:
            print(f"  ✓ PARTIAL OVERLAP (neither is a subnet of the other)")
    else:
        print("\n✗ No overlap detected")

print("\n" + "=" * 80)
print("Testing with SPFChecker")
print("=" * 80)

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker

# Add a dangerous range for testing
print("\nAdding test dangerous range: 192.168.1.0/24")

data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

# Create test SPF records with different overlap scenarios
test_spf_records = [
    ("v=spf1 ip4:192.168.1.0/25 -all", "Subnet of dangerous range"),
    ("v=spf1 ip4:192.168.0.0/23 -all", "Contains dangerous range"),
    ("v=spf1 ip4:192.168.1.128/25 -all", "Partial overlap with dangerous range"),
    ("v=spf1 ip4:10.0.0.0/24 -all", "No overlap with dangerous range"),
]

spf_checker = SPFChecker(data_loaders=data_loaders)

print("\n" + "=" * 80)
print("Note: These tests would detect overlaps if 192.168.1.0/24 was in the")
print("dangerous IP ranges CSV file. Currently only checking against actual data.")
print("=" * 80)

for spf_record, description in test_spf_records:
    print(f"\n{'='*80}")
    print(f"SPF Record: {spf_record}")
    print(f"Description: {description}")
    print(f"{'='*80}")

    result = spf_checker.check_record(spf_record, "test-overlap")

    if result.all_ip_ranges:
        for ip_range in result.all_ip_ranges:
            print(f"\nIP Range: {ip_range['ip_range']}")
            print(f"Dangerous: {ip_range.get('dangerous', False)}")

            if ip_range.get('dangerous'):
                match_type = ip_range.get('match_type', 'unknown')
                print(f"Match Type: {match_type}")

                if match_type == 'subnet':
                    print(f"  → This range is a subnet of a dangerous range")
                elif match_type == 'contains_dangerous_subnet':
                    print(f"  → This range contains dangerous subnet: {ip_range.get('dangerous_subnet')}")
                elif match_type == 'partial_overlap':
                    print(f"  → Partial overlap with: {ip_range.get('dangerous_range')}")
                    print(f"  → Overlap: {ip_range.get('overlap_start')} - {ip_range.get('overlap_end')}")
                    print(f"  → Overlap count: {ip_range.get('overlap_count'):,} IPs")

                print(f"Service Type: {ip_range.get('service_type', 'N/A')}")
                print(f"Service Name: {ip_range.get('service_name', 'N/A')}")

print("\n" + "=" * 80)
print("Test completed!")
print("=" * 80)
