"""CNAME chain checker for DKIM / DMARC / SPF lookup names.

Detects aliases (CNAME) at the names where receivers look up authentication
TXT records — ``<selector>._domainkey.<domain>``, ``_dmarc.<domain>`` and
``<domain>`` itself — and classifies the chain (recorded as evidence in
``cname_checks``, never raised as an issue on its own):

- broken reference (final target NXDOMAIN, chain preserved)
- missing record (target exists but publishes no relevant TXT)
- resolution loop / max depth exceeded
- indeterminate (SERVFAIL / TIMEOUT / REFUSED — never read as "absent")

SPF ``include:`` / ``redirect=`` targets are NOT covered here; they belong
to the existing "Unregistered domains in SPF" control.

Registration status of failing targets is resolved afterwards, in bulk, by
:mod:`unregistered_domain_checker` (same DomainAvailabilityChecker pipeline as
the SPF include check).  Until then ``registration.state`` is
``not_verified``.  Only that step raises issues — the spoofing risk is that
someone registers the target domain and publishes the TXT of their choice.
"""

import uuid
from typing import Callable, Dict, List, Optional, Tuple

from ..models.cname_result import (
    CNAMECheck,
    ANOMALY_OK, ANOMALY_BROKEN_REFERENCE, ANOMALY_MISSING_RECORD,
    ANOMALY_RESOLUTION_LOOP, ANOMALY_MAX_DEPTH_EXCEEDED, ANOMALY_INDETERMINATE,
    ANOMALY_CHECK_ERROR,
    WILDCARD_EXPLICIT, WILDCARD_PROBABLE, WILDCARD_OTHER_TARGET,
    WILDCARD_INCONCLUSIVE, WILDCARD_INDETERMINATE,
    REG_NOT_APPLICABLE, REG_NOT_VERIFIED, REG_REGISTERED, REG_RESERVED,
    REG_PRIVATE_SUFFIX, REG_UNKNOWN,
)
from ..utils.cname_chain import (
    CNAMEChain, CNAMEChainResolver, DEFAULT_MAX_DEPTH,
    TERMINAL_NXDOMAIN, TERMINAL_LOOP, TERMINAL_MAX_DEPTH,
    TERMINAL_INDETERMINATE,
)
from ..utils.dns_utils import (
    DNSUtils, DNSQueryOutcome, INDETERMINATE_STATUSES, STATUS_NOERROR, STATUS_NODATA,
)

DEFAULT_WILDCARD_PROBES = 3

RelevanceFunc = Callable[[str], bool]


def is_spf_record(txt: str) -> bool:
    """Same matching rule as DNSUtils.get_spf_record ('v=spf1 ' prefix)."""
    value = txt.replace('"', '').strip()
    return value.lower() == 'v=spf1' or value.lower().startswith('v=spf1 ')


def is_dmarc_record(txt: str) -> bool:
    """Same matching rule as DNSUtils.get_dmarc_record ('v=DMARC1' prefix)."""
    return txt.replace('"', '').strip().upper().startswith('V=DMARC1')


class CNAMEChecker:
    """Detects broken / suspicious CNAME chains at authentication lookup names.

    Args:
        dns_utils: DNSUtils used for the queries (its ``query_classified``)
        max_depth: Maximum number of CNAME links followed
        wildcard_probes: Number of random sibling names probed per DKIM parent
                         (minimum 3)
        query: Optional ``query(name, rdtype) -> DNSQueryOutcome`` overriding
               ``dns_utils.query_classified`` (used by tests)
    """

    def __init__(
        self,
        dns_utils: Optional[DNSUtils] = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        wildcard_probes: int = DEFAULT_WILDCARD_PROBES,
        query: Optional[Callable[[str, str], DNSQueryOutcome]] = None,
    ):
        if query is None:
            if dns_utils is None:
                dns_utils = DNSUtils()
            query = dns_utils.query_classified
        self.query = query
        self.resolver = CNAMEChainResolver(query, max_depth=max_depth)
        self.wildcard_probes = max(DEFAULT_WILDCARD_PROBES, wildcard_probes)

    # ------------------------------------------------------------------ #
    # Detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def needs_chain_check(outcome: DNSQueryOutcome) -> bool:
        """True if a TXT lookup outcome warrants a CNAME chain walk.

        Either a CNAME was observed in the answer section, or the lookup was
        indeterminate (resolvers answer SERVFAIL on CNAME loops, which hides
        the alias from the TXT query).
        """
        return bool(outcome.cname_chain) or outcome.indeterminate

    def check_name(
        self,
        protocol: str,
        name: str,
        is_relevant: RelevanceFunc,
        selector: Optional[str] = None,
        txt_outcome: Optional[DNSQueryOutcome] = None,
    ) -> Optional[CNAMECheck]:
        """Check the CNAME chain at *name*.

        Returns ``None`` when *name* carries no CNAME (including when the
        source name itself is absent: that is not an obsolete alias).

        Args:
            protocol: 'SPF', 'DMARC' or 'DKIM'
            name: Lookup name (e.g. '_dmarc.example.com')
            is_relevant: Predicate telling whether a TXT string is a record of
                         *protocol* (content validity is left to the existing
                         protocol checkers)
            selector: DKIM selector, if any
            txt_outcome: TXT outcome already fetched for *name* (avoids a
                         second query)
        """
        if txt_outcome is None:
            txt_outcome = self.query(name, 'TXT')
        if not self.needs_chain_check(txt_outcome):
            return None

        chain = self.resolver.resolve(name)
        if not chain.has_cname:
            if not txt_outcome.cname_chain:
                return None  # no alias at the source name
            # The walk could not confirm an alias that the TXT answer showed:
            # keep the observed chain rather than losing it.
            chain = CNAMEChain.from_observed(txt_outcome)

        return self._classify(protocol, name, selector, chain, txt_outcome, is_relevant)

    def _classify(
        self,
        protocol: str,
        name: str,
        selector: Optional[str],
        chain: CNAMEChain,
        txt_outcome: DNSQueryOutcome,
        is_relevant: RelevanceFunc,
    ) -> CNAMECheck:
        check = CNAMECheck(
            protocol=protocol,
            queried_name=chain.source,
            selector=selector,
            chain=list(chain.chain),
            hops=[hop.to_dict() for hop in chain.hops],
            txt_status=chain.txt_status,
        )
        observed = [chain.source] + [t for _, t in txt_outcome.cname_chain] if txt_outcome.cname_chain else []
        if chain.from_observation:
            check.evidence.append(
                "CNAME chain taken from the TXT answer section; hop-by-hop walk could not confirm it"
            )
        elif observed:
            check.evidence.append(f"TXT answer section showed: {' -> '.join(observed)} ({txt_outcome.status})")
            if observed != chain.chain[:len(observed)]:
                check.evidence.append("TXT answer chain differs from hop-by-hop walk")
        else:
            check.evidence.append(f"TXT lookup was {txt_outcome.status}; CNAME found by direct CNAME query")

        if chain.terminal == TERMINAL_LOOP:
            check.anomaly = ANOMALY_RESOLUTION_LOOP
            check.failing_target = chain.failing_name
            check.dns_status = "LOOP"
            check.evidence.append(f"'{chain.failing_name}' already appears earlier in the chain")
        elif chain.terminal == TERMINAL_MAX_DEPTH:
            check.anomaly = ANOMALY_MAX_DEPTH_EXCEEDED
            check.failing_target = chain.failing_name
            check.dns_status = "MAX_DEPTH"
            check.confidence = "medium"
            check.evidence.append(f"more than {self.resolver.max_depth} CNAME links followed")
        elif chain.terminal == TERMINAL_INDETERMINATE:
            check.anomaly = ANOMALY_INDETERMINATE
            check.failing_target = chain.failing_name
            check.dns_status = chain.hops[-1].status if chain.hops else txt_outcome.status
            check.confidence = "low"
        elif chain.terminal == TERMINAL_NXDOMAIN:
            check.anomaly = ANOMALY_BROKEN_REFERENCE
            check.failing_target = chain.final_name
            check.dns_status = "NXDOMAIN"
            # Confirmed both by the walk and by the TXT answer → high confidence
            confirmed = not chain.from_observation and txt_outcome.status == "NXDOMAIN"
            check.confidence = "high" if confirmed else "medium"
        else:  # TERMINAL_EXISTS — report the TXT lookup status at the final target
            check.dns_status = chain.txt_status or (chain.hops[-1].status if chain.hops else STATUS_NOERROR)
            if chain.txt_status in INDETERMINATE_STATUSES:
                check.anomaly = ANOMALY_INDETERMINATE
                check.failing_target = chain.final_name
                check.dns_status = chain.txt_status
                check.confidence = "low"
            else:
                relevant = [r for r in chain.txt_records if is_relevant(r)]
                check.relevant_record_found = bool(relevant)
                if relevant:
                    check.anomaly = ANOMALY_OK
                else:
                    check.anomaly = ANOMALY_MISSING_RECORD
                    check.failing_target = chain.final_name
                    check.dns_status = chain.txt_status or STATUS_NODATA
                    check.evidence.append(
                        f"final target answered {chain.txt_status} with "
                        f"{len(chain.txt_records)} TXT record(s), none relevant to {protocol}"
                    )

        self._set_registration(check)
        return check

    @staticmethod
    def _set_registration(check: CNAMECheck) -> None:
        """Initial registration state of the failing target (before bulk check)."""
        if check.anomaly == ANOMALY_MISSING_RECORD:
            # The target answered NOERROR/NODATA: its zone is delegated.
            check.registration = {"state": REG_REGISTERED, "source": "dns_resolution"}
            return
        if check.anomaly not in (ANOMALY_BROKEN_REFERENCE, ANOMALY_INDETERMINATE) or not check.failing_target:
            check.registration = {"state": REG_NOT_APPLICABLE}
            return

        # Imported lazily: the module pulls in the WHOIS/RDAP stack at import time
        from .unregistered_domain_checker import (
            classify_registrable_domain, SUFFIX_PRIVATE, SUFFIX_RESERVED, SUFFIX_UNKNOWN,
        )
        info = classify_registrable_domain(check.failing_target)
        check.registrable_domain = info.get("registrable_domain")
        check.suffix_type = info.get("suffix_type")
        if check.suffix_type == SUFFIX_RESERVED:
            check.registration = {"state": REG_RESERVED, "source": "special_use_names",
                                  "reason": f"'{info.get('reserved')}' is reserved and cannot be registered"}
        elif check.suffix_type == SUFFIX_UNKNOWN:
            check.registration = {"state": REG_UNKNOWN, "source": "public_suffix_list",
                                  "reason": "no public suffix match"}
        elif check.suffix_type == SUFFIX_PRIVATE:
            check.registration = {
                "state": REG_PRIVATE_SUFFIX, "source": "public_suffix_list",
                "reason": (f"target is under the private (hosted) suffix '{info.get('private_suffix')}': "
                           f"claimability depends on the provider, not on a registrar — verify manually"),
            }
            check.registrable_domain = None  # registrar check on the platform apex is meaningless
        else:
            check.registration = {"state": REG_NOT_VERIFIED}

    # ------------------------------------------------------------------ #
    # DKIM wildcard probing
    # ------------------------------------------------------------------ #

    def probe_wildcard(self, parent: str) -> List[CNAMEChain]:
        """Resolve ``random-<uuid>.<parent>`` names (closest-encloser rules are
        applied by the authoritative server, not simulated here)."""
        return [
            self.resolver.resolve(f"random-{uuid.uuid4().hex}.{parent}", lookup_txt=False)
            for _ in range(self.wildcard_probes)
        ]

    @staticmethod
    def assess_wildcard(check: CNAMECheck, probes: List[CNAMEChain]) -> Dict[str, object]:
        """Compare a selector's chain with random sibling probes."""
        selector_targets = tuple(check.chain[1:])
        probe_info = [
            {"name": p.source, "chain": p.chain, "terminal": p.terminal}
            for p in probes
        ]
        if any(p.terminal == TERMINAL_INDETERMINATE and not p.has_cname for p in probes):
            status = WILDCARD_INDETERMINATE
        elif all(p.has_cname for p in probes):
            if all(tuple(p.targets) == selector_targets for p in probes):
                status = WILDCARD_PROBABLE
            elif len({tuple(p.targets) for p in probes}) == 1:
                status = WILDCARD_OTHER_TARGET
            else:
                status = WILDCARD_INCONCLUSIVE
        elif not any(p.has_cname for p in probes):
            status = WILDCARD_EXPLICIT
        else:
            status = WILDCARD_INCONCLUSIVE
        return {"status": status, "parent": check.parent, "probes": probe_info}

    def check_dkim_selectors(
        self,
        candidates: List[Tuple[str, str, DNSQueryOutcome]],
        is_relevant: RelevanceFunc,
    ) -> List[CNAMECheck]:
        """Check the CNAME chains of DKIM selectors and assess wildcards.

        Args:
            candidates: ``(selector, lookup_name, txt_outcome)`` for every
                        selector whose TXT lookup needs a chain walk
            is_relevant: DKIM record predicate

        Wildcard probes are issued once per DNS parent (``_domainkey.<domain>``,
        or ``<label>._domainkey.<domain>`` for multi-label selectors).  A
        CNAME on the parent itself is never treated as a wildcard: it does not
        apply to descendants.
        """
        checks: List[CNAMECheck] = []
        for selector, name, outcome in candidates:
            try:
                check = self.check_name('DKIM', name, is_relevant, selector=selector, txt_outcome=outcome)
            except Exception as e:
                check = self.error_check('DKIM', name, e, selector=selector)
            if check:
                checks.append(check)

        probes_by_parent: Dict[str, List[CNAMEChain]] = {}
        for check in checks:
            if check.anomaly == ANOMALY_CHECK_ERROR:
                continue
            if check.parent not in probes_by_parent:
                probes_by_parent[check.parent] = self.probe_wildcard(check.parent)
            check.wildcard = self.assess_wildcard(check, probes_by_parent[check.parent])
            if check.wildcard["status"] == WILDCARD_PROBABLE:
                check.evidence.append(
                    f"{len(probes_by_parent[check.parent])} random names under '{check.parent}' "
                    f"return the same CNAME chain: wildcard probable (an explicit record is not excluded)"
                )
        return checks

    # ------------------------------------------------------------------ #
    # Attachment
    # ------------------------------------------------------------------ #

    @staticmethod
    def error_check(protocol: str, name: str, error: Exception, selector: Optional[str] = None) -> CNAMECheck:
        return CNAMECheck(
            protocol=protocol, queried_name=name.rstrip('.').lower(), selector=selector,
            anomaly=ANOMALY_CHECK_ERROR, confidence="low",
            evidence=[f"{type(error).__name__}: {error}"],
        )

    def check_and_attach(self, result, protocol: str, name: str, is_relevant: RelevanceFunc) -> None:
        """Run :meth:`check_name` for SPF / DMARC and attach the check to *result*.

        No issue is raised here: DNS anomalies alone are not a spoofing risk.
        Issues are only added by the registration check
        (:func:`unregistered_domain_checker.apply_cname_registration_results`)
        when the target's registrable domain is (potentially) unregistered.

        Never raises: an unexpected error is stored as a ``check_error`` entry
        so the main protocol result is preserved.
        """
        try:
            check = self.check_name(protocol, name, is_relevant)
        except Exception as e:
            check = self.error_check(protocol, name, e)
        if check is not None:
            result.cname_checks.append(check)
