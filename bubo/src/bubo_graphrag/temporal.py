"""Build affiliation timelines from dated assertions.

The corpus never states when an affiliation began or ended. It states that a person was
credited under an employer in a document published on a date. Everything here follows
from taking that literally:

  * An affiliation is an interval with OPEN bounds, marked by the earliest and latest
    date it is attested. `boundsKnown` is false on every one.
  * A change between two attested states yields a loss and a gain sharing an
    UNCERTAINTY WINDOW -- `notBefore` the last evidence for the old state, `notAfter`
    the first evidence for the new one. `inferred` is true; no date is invented.
  * Absence of a stated employer is NOT evidence of leaving one. Sarah Novotny is
    credited under GenLab once and with no employer in four later documents; that
    yields one interval and no change event, because nothing says she left.

State precedence within a single date matters: Josiah Hagen appears twice in
zero-trust-for-ai-systems, once with no employer and once as 'indepedent'. The
informative claim wins.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import IntEnum

from .resolve.identity import OrgAssertion, Person

INDEPENDENT = "(independent)"


class Informativeness(IntEnum):
    """How much a single assertion tells us. Higher wins within one date."""

    UNSTATED = 0        # no employer named; not a claim about affiliation
    INDEPENDENT = 1     # explicitly credited without an employer
    NAMED = 2           # an organization is named


@dataclass
class AffiliationSpan:
    """One attested affiliation state, over an interval with open bounds."""

    state: str                      # canonical organization name, or INDEPENDENT
    earliest_evidence: dt.date
    latest_evidence: dt.date
    publication_ids: list[str] = field(default_factory=list)
    bounds_known: bool = False

    @property
    def is_independent(self) -> bool:
        return self.state == INDEPENDENT


@dataclass
class AffiliationChange:
    """An inferred transition between two attested states."""

    from_state: str
    to_state: str
    not_before: dt.date             # last evidence for from_state
    not_after: dt.date              # first evidence for to_state
    inferred: bool = True

    @property
    def window_days(self) -> int:
        return (self.not_after - self.not_before).days


@dataclass
class Timeline:
    person_id: str
    spans: list[AffiliationSpan] = field(default_factory=list)
    changes: list[AffiliationChange] = field(default_factory=list)
    # Dates where the person is credited but no employer is stated. Retained so a
    # consumer can see the gaps rather than reading the spans as continuous.
    unstated_dates: list[dt.date] = field(default_factory=list)


def _classify(assertion: OrgAssertion) -> tuple[Informativeness, str | None]:
    if assertion.organization:
        return Informativeness.NAMED, assertion.organization
    if assertion.is_independent:
        return Informativeness.INDEPENDENT, INDEPENDENT
    return Informativeness.UNSTATED, None


def build_timeline(person: Person) -> Timeline:
    """Collapse a person's dated organization assertions into spans and changes."""
    timeline = Timeline(person_id=person.id)

    # One state per date, taking the most informative claim. Only credit-line
    # assertions drive the timeline; domain-derived evidence corroborates but does not
    # establish affiliation on its own, since an address may outlive the job.
    per_date: dict[dt.date, tuple[Informativeness, str | None, str]] = {}
    for assertion in person.org_evidence:
        date = assertion.assertion_date
        if not isinstance(date, dt.date):
            continue
        rank, state = _classify(assertion)
        if assertion.source != "credit-line":
            # Corroboration only: never upgrades an unstated date to a named one.
            continue
        current = per_date.get(date)
        if current is None or rank > current[0]:
            per_date[date] = (rank, state, assertion.publication_id)

    ordered = sorted(per_date.items())
    timeline.unstated_dates = [
        d for d, (rank, _, _) in ordered if rank == Informativeness.UNSTATED
    ]

    attested = [
        (d, state, pub) for d, (rank, state, pub) in ordered
        if rank != Informativeness.UNSTATED and state is not None
    ]

    # Consecutive runs of one state become one span.
    for date, state, pub in attested:
        if timeline.spans and timeline.spans[-1].state == state:
            span = timeline.spans[-1]
            span.latest_evidence = max(span.latest_evidence, date)
            span.earliest_evidence = min(span.earliest_evidence, date)
            if pub not in span.publication_ids:
                span.publication_ids.append(pub)
        else:
            timeline.spans.append(AffiliationSpan(
                state=state, earliest_evidence=date, latest_evidence=date,
                publication_ids=[pub]))

    for previous, following in zip(timeline.spans, timeline.spans[1:]):
        timeline.changes.append(AffiliationChange(
            from_state=previous.state,
            to_state=following.state,
            not_before=previous.latest_evidence,
            not_after=following.earliest_evidence,
        ))

    return timeline


def affiliation_at(timeline: Timeline, when: dt.date) -> AffiliationSpan | None:
    """The span attested at a date, or None.

    Returns a span only when `when` falls within its attested evidence range. It
    deliberately does not extrapolate: asking where someone worked between two
    attested states has no answer in this data, and guessing would be worse than
    saying so.
    """
    for span in timeline.spans:
        if span.earliest_evidence <= when <= span.latest_evidence:
            return span
    return None


def describe(timeline: Timeline, display_name: str) -> str:
    """Human-readable timeline, with the uncertainty made explicit."""
    if not timeline.spans:
        return f"{display_name}: no employer stated in any credit."
    lines = [f"{display_name}:"]
    for span in timeline.spans:
        window = (f"{span.earliest_evidence}" if span.earliest_evidence == span.latest_evidence
                  else f"{span.earliest_evidence} to {span.latest_evidence}")
        label = "independent" if span.is_independent else span.state
        lines.append(f"  {label} — attested {window} "
                     f"({', '.join(span.publication_ids)})")
    for change in timeline.changes:
        frm = "independent" if change.from_state == INDEPENDENT else change.from_state
        to = "independent" if change.to_state == INDEPENDENT else change.to_state
        lines.append(f"  change {frm} -> {to}: sometime after {change.not_before} "
                     f"and by {change.not_after} ({change.window_days} day window, inferred)")
    if timeline.unstated_dates:
        dates = ", ".join(str(d) for d in timeline.unstated_dates)
        lines.append(f"  credited with no employer stated on: {dates}")
    return "\n".join(lines)
