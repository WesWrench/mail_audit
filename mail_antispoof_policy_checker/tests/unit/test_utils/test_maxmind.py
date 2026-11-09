"""Test MaxMind AS organization detection"""
import sys
import io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.data.loaders import DataLoaders
from lib.checkers.spf_checker import SPFChecker
from lib.utils.maxmind_client import MaxMindClient

print("=" * 80)
print("MaxMind AS Organization Test")
print("=" * 80)

# Initialize
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

# Initialize MaxMind client
maxmind_client = None
try:
    maxmind_client = MaxMindClient.from_environment()
    print("\n✓ MaxMind client initialized")
except ValueError as e:
    print(f"\n✗ MaxMind client not initialized: {e}")
    print("\nPlease set MAXMIND_LICENSE_KEY environment variable")
    sys.exit(1)

# Test IP lookup
test_ip = "223.165.113.0"
print(f"\n[Testing IP: {test_ip}]")

ip_info = maxmind_client.get_ip_information(test_ip)
print(f"\nMaxMind Information:")
print(f"  AS Organization: {ip_info.get('as_organization')}")
print(f"  Country: {ip_info.get('country_name')} ({ip_info.get('country_iso_code')})")
print(f"  City: {ip_info.get('city_name')}")
print(f"  Network: {ip_info.get('network')}")

# Check if AS organization is in third-party services
as_org = ip_info.get('as_organization')
if as_org:
    print(f"\n[Checking third-party services for: {as_org}]")
    service_matches = data_loaders.find_third_party_service(as_org)

    if service_matches:
        print(f"✓ DANGEROUS - Found {len(service_matches)} match(es):")
        for match in service_matches:
            print(f"  - Type: {match.type.value}")
            print(f"    Service: {match.service_name}")
            print(f"    AS Org: {match.as_organization}")
    else:
        print("✗ Not found in third-party services")
else:
    print("\n✗ No AS organization found")

# Now test with SPF checker
print("\n" + "=" * 80)
print("[Testing with SPF Checker]")
print("=" * 80)

spf_checker = SPFChecker(data_loaders=data_loaders, maxmind_client=maxmind_client)
spf_record = f"v=spf1 ip4:{test_ip} -all"

print(f"\nSPF Record: {spf_record}")
result = spf_checker.check_record(spf_record, "test-maxmind")

print(f"\nResult:")
print(f"  Issues: {len(result.issues)}")
print(f"  IP Addresses: {len(result.all_ip_addresses)}")

if result.all_ip_addresses:
    for ip_addr in result.all_ip_addresses:
        print(f"\n  IP: {ip_addr['ip']}")
        print(f"    Dangerous: {ip_addr.get('dangerous', False)}")
        if ip_addr.get('dangerous'):
            print(f"    AS Organization: {ip_addr.get('as_organization')}")
            print(f"    Service Type: {ip_addr.get('service_type')}")
            print(f"    Service Name: {ip_addr.get('service_name')}")

if result.issues:
    print(f"\n  Issues:")
    for issue in result.issues:
        print(f"    - [{issue.severity.value.upper()}] {issue.title}")
        print(f"      {issue.description}")

print("\n" + "=" * 80)
print("Done!")
print("=" * 80)
