"""Test with a domain that should have dangerous includes"""
import json
from lib.checkers.spf_checker import SPFChecker
from lib.data.loaders import DataLoaders

# Initialize
loaders = DataLoaders(data_dir="./data")
loaders.load_all()

print("Dangerous includes in database:")
for inc in loaders.dangerous_includes[:3]:
    print(f"  - {inc.include} ({inc.type.value}: {inc.service_name})")

# Create a test by checking what domains use these includes
# Let's manually create a test case
from lib.models.spf_result import SPFResult

# Create a mock result
result = SPFResult(domain="test.example.com")
result.spf_record = "v=spf1 include:spf.mailjet.com -all"

# Manually add a dangerous include like the checker would
result.all_includes.append({
    'include': 'spf.mailjet.com',
    'path': 'test.example.com -> include:spf.mailjet.com',
    'dangerous': True,
    'service_type': 'Email Delivery Service',
    'service_name': 'Mailjet'
})

# Also add a safe include
result.all_includes.append({
    'include': 'spf.google.com',
    'path': 'test.example.com -> include:spf.google.com',
    'dangerous': False
})

# Convert to dict
result_dict = result.to_dict()

print("\n=== Test Result ===")
print(json.dumps(result_dict, indent=2, ensure_ascii=False))

# Verify the structure
print("\n=== Verification ===")
for inc in result_dict['all_includes']:
    print(f"Include: {inc['include']}")
    print(f"  Dangerous: {inc.get('dangerous', False)}")
    if inc.get('dangerous'):
        print(f"  Service Type: {inc.get('service_type', 'MISSING')}")
        print(f"  Service Name: {inc.get('service_name', 'MISSING')}")
    print()
