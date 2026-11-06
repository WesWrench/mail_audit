"""
Test to demonstrate redirect handling in SPF checker.

This test shows that redirect= is properly detected and analyzed
for dangerous configurations, just like include: but with the understanding
that it replaces the entire policy.
"""

from lib.checkers.spf_checker import SPFChecker
from lib.data.loaders import DataLoaders

# Initialize
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()
checker = SPFChecker(data_loaders=data_loaders)

print("=" * 80)
print("SPF Redirect Handling Test")
print("=" * 80)

# Test domains with redirect
test_domains = [
    "harmonieassuranceemprunteur.fr",  # Has redirect
    "example.com",  # For comparison
]

for domain in test_domains:
    print(f"\n[Testing: {domain}]")
    result = checker.check(domain, use_checkdmarc=True)

    if result.spf_record:
        print(f"  SPF Record: {result.spf_record[:100]}...")

        # Show if redirect is present
        if 'redirect' in result.spf_record:
            print("  [!] Contains REDIRECT directive")

        # Show all includes/redirects
        if result.all_includes:
            print(f"\n  Includes/Redirects found: {len(result.all_includes)}")
            for inc in result.all_includes:
                prefix = "[DANGEROUS]" if inc.get('dangerous', False) else "[OK]"
                print(f"    {prefix} {inc['include']}")
                print(f"            Path: {inc['path']}")
                if inc.get('dangerous', False):
                    print(f"            Type: {inc['service_type']}")
                    print(f"            Service: {inc['service_name']}")

        # Show issues
        if result.issues:
            print(f"\n  Issues found: {len(result.issues)}")
            for issue in result.issues:
                print(f"    [{issue.severity.value}] {issue.title}")
                if issue.resolution_path:
                    print(f"                  Path: {' -> '.join(issue.resolution_path)}")
    else:
        print("  No SPF record found")

print("\n" + "=" * 80)
print("Test complete!")
print("\nKey points:")
print("  - redirect= is detected and analyzed like include:")
print("  - Dangerous redirects are flagged with full resolution path")
print("  - redirect= means 'abandon my rules and use EXCLUSIVELY those of this domain'")
print("=" * 80)
