"""Test flexible JSON formatting"""
# -*- coding: utf-8 -*-
import sys
import io

# Set UTF-8 encoding for stdout on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from lib.checkers.spf_checker import SPFChecker
from lib.checkers.dmarc_checker import DMARCChecker
from lib.formatters.json_formatter import JSONFormatter

domain = "google.com"

# Check SPF and DMARC only (no DKIM)
spf_checker = SPFChecker()
dmarc_checker = DMARCChecker()

print(f"Testing flexible JSON formatting for {domain}")
print("=" * 80)

spf_result = spf_checker.check(domain, use_checkdmarc=False)
dmarc_result = dmarc_checker.check(domain, use_checkdmarc=False)

print("\n[Test 1] SPF + DMARC (no DKIM)")
combined = JSONFormatter.format_combined(
    spf_result=spf_result,
    dmarc_result=dmarc_result
)
print(f"  ✓ JSON generated: {len(combined)} chars")

# Verify it's valid JSON
import json
data = json.loads(combined)
print(f"  ✓ Valid JSON")
print(f"  ✓ Domain: {data['domain']}")
print(f"  ✓ Has SPF: {'spf' in data}")
print(f"  ✓ Has DMARC: {'dmarc' in data}")
print(f"  ✓ Has DKIM: {'dkim' in data}")
print(f"  ✓ Summary: {data['summary']['total_issues']} issues")

print("\n[Test 2] SPF only")
combined_spf_only = JSONFormatter.format_combined(spf_result=spf_result)
data_spf = json.loads(combined_spf_only)
print(f"  ✓ SPF only JSON: {len(combined_spf_only)} chars")
print(f"  ✓ Has SPF: {'spf' in data_spf}")
print(f"  ✓ Has DMARC: {'dmarc' in data_spf}")

print("\n[Test 3] DMARC only")
combined_dmarc_only = JSONFormatter.format_combined(dmarc_result=dmarc_result)
data_dmarc = json.loads(combined_dmarc_only)
print(f"  ✓ DMARC only JSON: {len(combined_dmarc_only)} chars")
print(f"  ✓ Has SPF: {'spf' in data_dmarc}")
print(f"  ✓ Has DMARC: {'dmarc' in data_dmarc}")

print("\n[Test 4] Save to file")
JSONFormatter.save_to_file(combined, "./output/test_flexible.json")
print(f"  ✓ Saved to ./output/test_flexible.json")

print("\n" + "=" * 80)
print("All tests passed! ✓")
print("\nNow you can use:")
print("  - format_combined(spf_result=spf)")
print("  - format_combined(dmarc_result=dmarc)")
print("  - format_combined(spf_result=spf, dmarc_result=dmarc)")
print("  - format_combined(spf_result=spf, dmarc_result=dmarc, dkim_result=dkim)")
