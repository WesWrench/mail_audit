"""
Quick test to verify the library implementation.
"""

from lib.checkers.spf_checker import SPFChecker
from lib.checkers.dmarc_checker import DMARCChecker
from lib.checkers.dkim_checker import DKIMChecker
from lib.formatters.json_formatter import JSONFormatter
from lib.data.loaders import DataLoaders


def test_data_loaders():
    """Test that data loaders can load CSV files"""
    print("[TEST] Loading data files...")
    loaders = DataLoaders(data_dir="./data")
    loaders.load_all()

    print(f"  ✓ Loaded {len(loaders.dangerous_includes)} dangerous includes")
    print(f"  ✓ Loaded {len(loaders.dangerous_ip_ranges)} dangerous IP ranges")
    print(f"  ✓ Loaded {len(loaders.third_party_services)} third-party services")

    # Test finding a dangerous include
    test_include = "spf.mailjet.com"
    matches = loaders.find_dangerous_include(test_include)
    if matches:
        print(f"  ✓ Found dangerous include '{test_include}': {matches[0].service_name}")
    else:
        print(f"  ⚠ Could not find test include '{test_include}'")

    return True


def test_spf_checker():
    """Test SPF checker"""
    print("\n[TEST] Testing SPF Checker...")
    checker = SPFChecker()

    # Test with a well-known domain
    domain = "google.com"
    result = checker.check(domain, use_checkdmarc=True)

    print(f"  ✓ Checked SPF for {domain}")
    print(f"  ✓ SPF Record found: {result.spf_record is not None}")
    print(f"  ✓ Issues found: {len(result.issues)}")
    print(f"  ✓ Lookup count: {result.lookup_count}")

    return True


def test_dmarc_checker():
    """Test DMARC checker"""
    print("\n[TEST] Testing DMARC Checker...")
    checker = DMARCChecker()

    # Test with a well-known domain
    domain = "google.com"
    result = checker.check(domain, use_checkdmarc=True)

    print(f"  ✓ Checked DMARC for {domain}")
    print(f"  ✓ DMARC Record found: {result.dmarc_record is not None}")
    if result.policy:
        print(f"  ✓ Policy: {result.policy}")
    print(f"  ✓ Issues found: {len(result.issues)}")

    return True


def test_dkim_checker():
    """Test DKIM checker"""
    print("\n[TEST] Testing DKIM Checker...")
    checker = DKIMChecker()

    # Test with a well-known domain
    domain = "google.com"
    result = checker.check(domain)

    print(f"  ✓ Checked DKIM for {domain}")
    print(f"  ✓ Selectors tested: {len(result.selectors_tested)}")
    print(f"  ✓ Selectors found: {len(result.selectors_found)}")

    for selector_info in result.selectors_found:
        print(f"    - {selector_info.selector}: {selector_info.key_size} bits")

    return True


def test_json_formatter():
    """Test JSON formatter"""
    print("\n[TEST] Testing JSON Formatter...")

    spf_checker = SPFChecker()
    dmarc_checker = DMARCChecker()
    dkim_checker = DKIMChecker()

    domain = "example.com"
    spf_result = spf_checker.check(domain, use_checkdmarc=False)
    dmarc_result = dmarc_checker.check(domain, use_checkdmarc=False)
    dkim_result = dkim_checker.check(domain)

    # Test JSON formatting
    json_output = JSONFormatter.format_combined(spf_result, dmarc_result, dkim_result)
    print(f"  ✓ Generated combined JSON output ({len(json_output)} chars)")

    # Test that it's valid JSON
    import json
    parsed = json.loads(json_output)
    print(f"  ✓ JSON is valid")
    print(f"  ✓ Domain in output: {parsed['domain']}")

    return True


def main():
    print("=" * 80)
    print("Mail AntiSpoof Policy Checker - Implementation Test")
    print("=" * 80)

    tests = [
        ("Data Loaders", test_data_loaders),
        ("SPF Checker", test_spf_checker),
        ("DMARC Checker", test_dmarc_checker),
        ("DKIM Checker", test_dkim_checker),
        ("JSON Formatter", test_json_formatter)
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result, None))
        except Exception as e:
            results.append((test_name, False, str(e)))

    print("\n" + "=" * 80)
    print("Test Results:")
    print("=" * 80)

    passed = 0
    failed = 0

    for test_name, result, error in results:
        if result:
            print(f"  ✓ {test_name}: PASSED")
            passed += 1
        else:
            print(f"  ✗ {test_name}: FAILED")
            if error:
                print(f"    Error: {error}")
            failed += 1

    print("\n" + "=" * 80)
    print(f"Total: {passed} passed, {failed} failed")
    print("=" * 80)

    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
