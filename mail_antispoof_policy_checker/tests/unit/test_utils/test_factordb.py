"""factordb.com client: HTML parsing and lookup logic, offline.

The fixtures in tests/fixtures/factordb/ are real factordb pages (2026-11), indexed by
URL in index.json; a fake ``fetch`` serves them instead of HTTP.
"""
import json
from pathlib import Path

import pytest

from lib.utils.factordb import (
    FactorDBClient, parse_factors, parse_notes, parse_status, parse_value,
    STATUS_COMPOSITE, STATUS_FACTOR_KNOWN, STATUS_FULLY_FACTORED, STATUS_PRIME,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "factordb"
INDEX = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))
NUMBERS = {k: int(v) for k, v in INDEX["numbers"].items()}
RSA100_P = 37975227936943673922808872755445627854565536638199
RSA100_Q = 40094690950920881030683735292761468389214899724061


def _page(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def _fetcher(calls=None, override=None):
    def fetch(url):
        if calls is not None:
            calls.append(url)
        if override and url in override:
            return override[url]
        name = INDEX["pages"].get(url)
        return (200, _page(name)) if name else (404, "")
    return fetch


def _client(**kw):
    return FactorDBClient(min_interval=0, **kw)


# ----------------------------------------------------------------- parsing

@pytest.mark.parametrize("name,status", [
    ("ff_rsa100.html", STATUS_FULLY_FACTORED),
    ("cf_3x_rsa2048.html", STATUS_FACTOR_KNOWN),
    ("c_rsa2048.html", STATUS_COMPOSITE),
    ("p_oakley.html", STATUS_PRIME),
])
def test_parse_status(name, status):
    assert parse_status(_page(name)) == status


def test_parse_factors_full_and_abbreviated():
    assert [d for _, d in parse_factors(_page("ff_rsa100.html"))] == [str(RSA100_P), str(RSA100_Q)]
    # Small factor linked by "?query=3", long cofactor abbreviated ("2519590847…57")
    factors = parse_factors(_page("cf_3x_rsa2048.html"))
    assert factors[0] == ("3", "3")
    assert factors[1][1] is None


@pytest.mark.parametrize("name,starts", [
    ("p_logjam.html", "Interesting number. The second most common 512-bit export DH prime"),
    ("p_oakley.html", "Interesting number. 768-bit Oakley Group 1 (RFC 2409, 1998)"),
    ("c_rsa2048.html", "Interesting number. RSA-2048,"),
    ("ff_rsa100.html", "Interesting number. First RSA Challenge number to fall"),
])
def test_parse_notes(name, starts):
    [note] = parse_notes(_page(name))
    assert note.startswith(starts) and "<" not in note


def test_page_without_note():
    assert parse_notes(_page("cf_3x_rsa2048.html")) == []


def test_lookup_keeps_the_note():
    r = _client(fetch=_fetcher()).lookup(NUMBERS["logjam_prime"])
    assert r.status == "P" and r.notes[0].startswith("Interesting number.")
    assert r.to_dict()["notes"] == r.notes


def test_parse_value_of_a_full_page():
    name = next(n for n in INDEX["pages"].values() if n.startswith("id_"))
    assert parse_value(_page(name)) == NUMBERS["rsa2048"]


# ------------------------------------------------------------------ lookup

def test_fully_factored_number():
    r = _client(fetch=_fetcher()).lookup(NUMBERS["rsa100"])
    assert (r.status, r.factors, r.factor_known) == ("FF", [RSA100_P, RSA100_Q], True)


def test_abbreviated_factor_is_fetched_by_id_and_verified():
    calls = []
    r = _client(fetch=_fetcher(calls)).lookup(3 * NUMBERS["rsa2048"])
    assert r.status == "CF"
    assert r.factors == [3, NUMBERS["rsa2048"]]
    assert any("id=" in u and "full=1" in u for u in calls)


def test_composite_without_known_factor():
    r = _client(fetch=_fetcher()).lookup(NUMBERS["rsa2048"])
    assert (r.status, r.factor_known) == ("C", False)


def test_prime():
    r = _client(fetch=_fetcher()).lookup(NUMBERS["oakley_prime"])
    assert (r.status, r.is_prime, r.factor_known) == ("P", True, False)


def test_factor_not_dividing_n_is_dropped():
    # A page listing factors of another number must never produce a finding.
    n = NUMBERS["rsa100"] + 2
    url = FactorDBClient().query_url(n)
    r = _client(fetch=_fetcher(override={url: (200, _page("ff_rsa100.html"))})).lookup(n)
    assert r.status == "FF" and r.factors == []


def test_results_are_cached():
    calls = []
    c = _client(fetch=_fetcher(calls))
    c.lookup(NUMBERS["rsa100"])
    c.lookup(NUMBERS["rsa100"])
    assert len(calls) == 1


def test_rate_limit_stops_all_further_lookups():
    calls = []
    c = _client(fetch=lambda url: (calls.append(url), (429, ""))[1])
    first = c.lookup(NUMBERS["rsa100"])
    second = c.lookup(NUMBERS["rsa2048"])
    assert (first.status, second.status) == ("skipped", "skipped")
    assert len(calls) == 1 and "429" in c.disabled_reason


def test_network_error_is_reported_not_raised_nor_cached():
    calls = []

    def boom(url):
        calls.append(url)
        raise ConnectionError("down")
    c = _client(fetch=boom)
    assert c.lookup(15).status == "error"
    assert c.lookup(15).status == "error"
    assert len(calls) == 2


def test_to_dict_has_no_factor_values():
    d = _client(fetch=_fetcher()).lookup(NUMBERS["rsa100"]).to_dict()
    assert d["factor_digits"] == [50, 50] and "factors" not in d
