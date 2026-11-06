"""Hop-by-hop CNAME chain resolution.

Follows a CNAME chain one link at a time (qtype=CNAME, so the recursive
resolver does not follow it for us), records the DNS status of every hop,
detects loops and enforces a maximum depth, then looks up the TXT RRset at
the final target.

The query function is injectable so that tests can feed deterministic,
simulated DNS answers.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .dns_utils import (
    DNSQueryOutcome,
    INDETERMINATE_STATUSES,
    STATUS_NODATA,
    STATUS_NOERROR,
    STATUS_NXDOMAIN,
    _normalize_name,
)

# Terminal state of a chain walk
TERMINAL_EXISTS        = "exists"          # final name exists (NOERROR / NODATA)
TERMINAL_NXDOMAIN      = "nxdomain"        # final name does not exist
TERMINAL_LOOP          = "loop"            # a target points back into the chain
TERMINAL_MAX_DEPTH     = "max_depth"       # more than max_depth CNAMEs followed
TERMINAL_INDETERMINATE = "indeterminate"   # SERVFAIL / TIMEOUT / REFUSED / error

DEFAULT_MAX_DEPTH = 10

QueryFunc = Callable[[str, str], DNSQueryOutcome]


@dataclass
class CNAMEHop:
    """One CNAME lookup in the chain."""

    name: str
    status: str
    target: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        result = {'name': self.name, 'status': self.status}
        if self.target:
            result['target'] = self.target
        if self.error:
            result['error'] = self.error
        return result


@dataclass
class CNAMEChain:
    """Result of walking the CNAME chain that starts at ``source``."""

    source: str
    chain: List[str] = field(default_factory=list)      # [source, target1, target2, ...]
    hops: List[CNAMEHop] = field(default_factory=list)
    terminal: str = TERMINAL_INDETERMINATE
    final_name: Optional[str] = None
    txt_status: Optional[str] = None
    txt_records: List[str] = field(default_factory=list)
    from_observation: bool = False   # rebuilt from a TXT answer section, not walked hop by hop

    @property
    def has_cname(self) -> bool:
        return len(self.chain) > 1

    @property
    def targets(self) -> List[str]:
        return self.chain[1:]

    @property
    def failing_name(self) -> Optional[str]:
        """Name at which resolution stopped abnormally (None when it did not)."""
        if self.terminal in (TERMINAL_NXDOMAIN, TERMINAL_INDETERMINATE):
            return self.final_name
        if self.terminal in (TERMINAL_LOOP, TERMINAL_MAX_DEPTH):
            return self.chain[-1] if self.chain else None
        return None

    @classmethod
    def from_observed(cls, outcome: DNSQueryOutcome) -> 'CNAMEChain':
        """Rebuild a chain from the CNAME links seen in a TXT answer section.

        Used when the hop-by-hop walk could not confirm an alias that was
        nevertheless observed (e.g. a transient failure on the CNAME query):
        an observed CNAME is never discarded.
        """
        source = _normalize_name(outcome.name)
        chain = [source] + [target for _, target in outcome.cname_chain]
        hops = [CNAMEHop(owner, STATUS_NOERROR, target) for owner, target in outcome.cname_chain]
        if outcome.status == STATUS_NXDOMAIN:
            terminal = TERMINAL_NXDOMAIN
        elif outcome.status in (STATUS_NOERROR, STATUS_NODATA):
            terminal = TERMINAL_EXISTS
        else:
            terminal = TERMINAL_INDETERMINATE
        return cls(
            source=source,
            chain=chain,
            hops=hops,
            terminal=terminal,
            final_name=chain[-1],
            txt_status=outcome.status,
            txt_records=list(outcome.records),
            from_observation=True,
        )

    def to_dict(self) -> dict:
        return {
            'chain': self.chain,
            'hops': [hop.to_dict() for hop in self.hops],
            'terminal': self.terminal,
            'final_name': self.final_name,
            'txt_status': self.txt_status,
        }


class CNAMEChainResolver:
    """Walks CNAME chains one hop at a time.

    Args:
        query: ``query(name, rdtype) -> DNSQueryOutcome`` (typically
               :meth:`DNSUtils.query_classified`)
        max_depth: Maximum number of CNAME links to follow before declaring
                   the chain too deep
    """

    def __init__(self, query: QueryFunc, max_depth: int = DEFAULT_MAX_DEPTH):
        self.query = query
        self.max_depth = max(1, max_depth)

    def resolve(self, name: str, lookup_txt: bool = True) -> CNAMEChain:
        """Follow the CNAME chain of *name* and (optionally) fetch TXT at its end."""
        current = _normalize_name(name)
        result = CNAMEChain(source=current, chain=[current])
        visited = {current}

        while True:
            outcome = self.query(current, 'CNAME')

            if outcome.status == STATUS_NOERROR and outcome.records:
                target = _normalize_name(outcome.records[0])
                result.hops.append(CNAMEHop(current, outcome.status, target))
                result.chain.append(target)
                if target in visited:
                    result.terminal = TERMINAL_LOOP
                    break
                if len(result.hops) > self.max_depth:
                    result.terminal = TERMINAL_MAX_DEPTH
                    break
                visited.add(target)
                current = target
                continue

            # No further CNAME at `current`: this is the end of the chain
            result.hops.append(CNAMEHop(current, outcome.status, error=outcome.error))
            if outcome.status == STATUS_NXDOMAIN:
                result.terminal = TERMINAL_NXDOMAIN
            elif outcome.status in INDETERMINATE_STATUSES:
                result.terminal = TERMINAL_INDETERMINATE
            else:
                result.terminal = TERMINAL_EXISTS
            break

        result.final_name = current
        if result.terminal == TERMINAL_NXDOMAIN:
            result.txt_status = STATUS_NXDOMAIN
        elif result.terminal == TERMINAL_EXISTS and lookup_txt:
            txt = self.query(current, 'TXT')
            result.txt_status = txt.status
            result.txt_records = list(txt.records)
        return result
