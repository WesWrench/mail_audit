"""Test CSV loading with new structure"""
from lib.data.loaders import DataLoaders

# Initialize loaders
loaders = DataLoaders(data_dir="./data")
loaders.load_all()

print("=== Dangerous SPF Includes ===")
for item in loaders.dangerous_includes:
    print(f"Include: {item.include}")
    print(f"  Type: {item.type.value}")
    print(f"  Service Name: {item.service_name}")
    print()

print("=== Dangerous IP Ranges ===")
for item in loaders.dangerous_ip_ranges:
    print(f"IP Range: {item.ip_range}")
    print(f"  Type: {item.type.value}")
    print(f"  Service Name: {item.service_name}")
    print()

print("=== Third Party Services ===")
for item in loaders.third_party_services:
    print(f"AS Organization: {item.as_organization}")
    print(f"  Type: {item.type.value}")
    print(f"  Service Name: {item.service_name}")
    print()

print(f"\nTotal includes: {len(loaders.dangerous_includes)}")
print(f"Total IP ranges: {len(loaders.dangerous_ip_ranges)}")
print(f"Total third party services: {len(loaders.third_party_services)}")
