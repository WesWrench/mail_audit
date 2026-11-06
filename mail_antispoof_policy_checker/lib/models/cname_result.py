"""CNAME chain check result model (DKIM / DMARC / SPF lookup names)"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

# Anomaly categories
ANOMALY_OK                 = "ok"                   # chain resolves to a relevant TXT record
ANOMALY_BROKEN_REFERENCE   = "broken_reference"     # final target is NXDOMAIN
ANOMALY_MISSING_RECORD     = "missing_record"       # target exists, no relevant TXT
ANOMALY_RESOLUTION_LOOP    = "resolution_loop"      # CNAME loop
ANOMALY_MAX_DEPTH_EXCEEDED = "max_depth_exceeded"   # chain longer than the configured limit
ANOMALY_INDETERMINATE      = "indeterminate"        # SERVFAIL / TIMEOUT / REFUSED
ANOMALY_CHECK_ERROR        = "check_error"          # unexpected exception in the check itself

# Wildcard assessment (DKIM selectors only)
WILDCARD_NOT_APPLICABLE = "not_applicable"
WILDCARD_EXPLICIT       = "explicit"                # random siblings are not aliased
WILDCARD_PROBABLE       = "wildcard_probable"       # random siblings return the same chain
WILDCARD_OTHER_TARGET   = "wildcard_other_target"   # siblings aliased, but to a different chain
WILDCARD_INCONCLUSIVE   = "inconclusive"            # mixed probe results
WILDCARD_INDETERMINATE  = "indeterminate"           # probes hit SERVFAIL / TIMEOUT / REFUSED

# Registration state of the failing target's registrable domain
REG_NOT_APPLICABLE          = "not_applicable"            # nothing failed / no target to check
REG_NOT_VERIFIED            = "not_verified"              # check skipped or unavailable
REG_REGISTERED              = "registered"                # registered, but the target name is absent
REG_UNREGISTERED            = "unregistered"              # availability checker says available
REG_POTENTIALLY_UNREGISTERED = "potentially_unregistered"  # no NS, registration could not be confirmed
REG_RESERVED                = "reserved"                  # reserved / special-use name, not registrable
REG_PRIVATE_SUFFIX          = "private_suffix"            # under a PSL private (hosted) suffix
REG_UNKNOWN                 = "unknown"                   # no public suffix match


@dataclass
class CNAMECheck:
    """CNAME chain observed at a DKIM / DMARC / SPF lookup name."""

    protocol: str                      # 'SPF', 'DMARC' or 'DKIM'
    queried_name: str                  # e.g. 'selector1._domainkey.example.com'
    selector: Optional[str] = None     # DKIM only
    chain: List[str] = field(default_factory=list)
    hops: List[Dict[str, Any]] = field(default_factory=list)
    anomaly: str = ANOMALY_OK
    failing_target: Optional[str] = None
    dns_status: Optional[str] = None   # DNS status of the final/failing name
    txt_status: Optional[str] = None
    relevant_record_found: bool = False
    wildcard: Dict[str, Any] = field(default_factory=lambda: {'status': WILDCARD_NOT_APPLICABLE})
    registrable_domain: Optional[str] = None
    suffix_type: Optional[str] = None
    registration: Dict[str, Any] = field(default_factory=lambda: {'state': REG_NOT_APPLICABLE})
    confidence: str = "high"
    evidence: List[str] = field(default_factory=list)

    @property
    def parent(self) -> str:
        """DNS parent of the queried name (wildcard probes are issued at this level)."""
        return self.queried_name.split('.', 1)[1] if '.' in self.queried_name else self.queried_name

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'protocol': self.protocol,
            'queried_name': self.queried_name,
            'chain': self.chain,
            'hops': self.hops,
            'anomaly': self.anomaly,
            'failing_target': self.failing_target,
            'dns_status': self.dns_status,
            'txt_status': self.txt_status,
            'relevant_record_found': self.relevant_record_found,
            'wildcard': self.wildcard,
            'registrable_domain': self.registrable_domain,
            'suffix_type': self.suffix_type,
            'registration': self.registration,
            'confidence': self.confidence,
            'evidence': self.evidence,
        }
        if self.selector is not None:
            result['selector'] = self.selector
        return result
