"""Test JSON export with service_type and service_name"""
import json
from lib.checkers.spf_checker import SPFChecker
from lib.data.loaders import DataLoaders

# Initialize
loaders = DataLoaders(data_dir="./data")
loaders.load_all()
checker = SPFChecker(data_loaders=loaders)

# Test domain with known dangerous include
test_domain = "harmonie-mutuelle.fr"

print(f"Testing domain: {test_domain}")
result = checker.check(test_domain)

# Convert to dict
result_dict = result.to_dict()

# Print all_includes to verify service_type and service_name are present
print("\n=== All Includes in JSON ===")
for inc in result_dict.get('all_includes', []):
    print(f"Include: {inc.get('include')}")
    print(f"  Dangerous: {inc.get('dangerous')}")
    if inc.get('dangerous'):
        print(f"  Service Type: {inc.get('service_type')}")
        print(f"  Service Name: {inc.get('service_name')}")
    print(f"  Path: {inc.get('path')}")
    print()

# Print all_ip_ranges to verify service_type and service_name are present
print("\n=== All IP Ranges in JSON ===")
for ipr in result_dict.get('all_ip_ranges', []):
    print(f"IP Range: {ipr.get('ip_range')}")
    print(f"  Dangerous: {ipr.get('dangerous')}")
    if ipr.get('dangerous'):
        print(f"  Service Type: {ipr.get('service_type')}")
        print(f"  Service Name: {ipr.get('service_name')}")
    print(f"  Path: {ipr.get('path')}")
    print()

# Save to file for inspection
with open('./output/test_export.json', 'w', encoding='utf-8') as f:
    json.dump(result_dict, f, indent=2, ensure_ascii=False)

print("\nJSON exported to ./output/test_export.json")
