# Test Suite Organization

This directory contains all tests for the Mail AntiSpoof Policy Checker project.

## Directory Structure

```
tests/
├── unit/                          # Unit tests for individual components
│   ├── test_data/                 # Data loader tests
│   │   └── test_loaders.py        # CSV loading tests
│   ├── test_checkers/             # Checker component tests
│   │   ├── test_checkers.py       # SPF/DMARC/DKIM checker tests
│   │   ├── test_cname_checker.py  # CNAME chain check (simulated DNS, offline)
│   │   └── test_dangerous_domain.py # Dangerous domain detection tests
│   ├── test_utils/                # Utility function tests
│   │   ├── test_maxmind.py        # MaxMind integration tests
│   │   ├── test_ip_overlap.py     # IP overlap detection tests
│   │   ├── test_ip_overlap_real.py
│   │   ├── test_overlap_demo.py
│   │   ├── test_true_overlap.py
│   │   ├── test_partial_overlap_final.py
│   │   └── test_ip_check.py       # IP validation tests
│   └── test_analyzers/            # Analyzer tests
├── integration/                   # Integration tests
│   ├── test_bulk_analysis_1.py    # Bulk SPF analysis (test.py)
│   ├── test_bulk_analysis_2.py    # Bulk SPF analysis with MaxMind (test2.py)
│   ├── test_record_checking.py    # DNS record checking
│   ├── test_parsed_checking.py    # Parsed record checking
│   ├── test_spf.py                # SPF-specific tests
│   ├── test_redirect.py           # SPF redirect tests
│   ├── test_parse_spf.py          # SPF parsing tests
│   ├── test_parsed_output.py      # Parsed output format tests
│   ├── test_flexible_json.py      # JSON flexibility tests
│   ├── test_json_export.py        # JSON export tests
│   └── test_main_cli.py           # CLI tool tests
└── fixtures/                      # Test fixtures and sample data

## Running Tests

### Run all tests
```bash
python -m pytest tests/
```

### Run unit tests only
```bash
python -m pytest tests/unit/
```

### Run integration tests only
```bash
python -m pytest tests/integration/
```

### Run specific test file
```bash
python tests/unit/test_data/test_loaders.py
```

## Test Categories

### Unit Tests
- Test individual functions and classes in isolation
- Mock external dependencies (DNS, MaxMind, etc.)
- Fast execution

### Integration Tests
- Test multiple components working together
- May make real DNS queries (depending on test)
- Test end-to-end workflows

## Notes

- Most tests can be run directly with `python test_file.py`
- Some tests may require environment variables (e.g., `MAXMIND_LICENSE_KEY`)
- Integration tests may require internet connectivity for DNS queries
