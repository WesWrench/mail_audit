"""Test checkdmarc.spf.parse_spf_record"""
from checkdmarc.spf import parse_spf_record
import json

spf_record = "v=spf1 include:mx.ovh.com -all"
domain = "test.example.com"

print(f"Parsing: {spf_record}")
print(f"Domain: {domain}\n")

try:
    result = parse_spf_record(spf_record, domain, parked=False, timeout=5.0)
    print("Result:")
    print(json.dumps(result, indent=2, default=str))

    print("\n\nParsed keys:")
    for key in result.keys():
        print(f"  - {key}")

    if 'parsed' in result:
        print("\n\nParsed mechanisms:")
        for key in result['parsed'].keys():
            print(f"  - {key}: {result['parsed'][key]}")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
