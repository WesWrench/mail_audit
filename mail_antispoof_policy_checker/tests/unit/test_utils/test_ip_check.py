"""Test IP checking"""
import sys
import io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker

data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

print("Dangerous IP ranges loaded:")
for dr in data_loaders.dangerous_ip_ranges:
    print(f"  - {dr.ip_range} ({dr.service_name})")

spf_checker = SPFChecker(data_loaders=data_loaders)

# Test with a single IP in the dangerous range
spf_record = "v=spf1 ip4:109.234.163.1 -all"
print(f"\nTesting: {spf_record}")

result = spf_checker.check_record(spf_record, "test-ip")

print(f"\nResult:")
print(f"  Issues: {len(result.issues)}")
print(f"  IP Addresses: {len(result.all_ip_addresses)}")
print(f"  IP Ranges: {len(result.all_ip_ranges)}")

if result.all_ip_addresses:
    for ip_addr in result.all_ip_addresses:
        print(f"\n  IP: {ip_addr['ip']}")
        print(f"    Dangerous: {ip_addr.get('dangerous', False)}")
        if ip_addr.get('dangerous'):
            print(f"    Service: {ip_addr.get('service_name')}")

if result.all_ip_ranges:
    for ip_range in result.all_ip_ranges:
        print(f"\n  Range: {ip_range['ip_range']}")
        print(f"    Dangerous: {ip_range.get('dangerous', False)}")

if result.issues:
    print(f"\n  Issues:")
    for issue in result.issues:
        print(f"    - {issue.title}")
