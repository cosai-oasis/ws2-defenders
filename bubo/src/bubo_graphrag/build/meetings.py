"""Build the maillist named graph from CoSAI's list archives: meetings, and the governance
calls with their approval links.

Separate from build/graph.py, and emitted into its own named graph, because the
provenance is different in ways a consumer must be able to act on: the publication
catalog is deterministic from pinned registries, while this is derived from list mail
whose coverage is whatever was fetched. Keeping them apart means this source can be
rebuilt or dropped alone, and that every meeting assertion can be traced to the message
that announced it.

What is deliberately *not* here: attendance. No attendee data exists in the source
(see ingest/maillist.py), so there are no cosaic:AttendanceRole instances. A meeting
carries a cosaic:MeetingSummary pointer flagged cosaic:accessRestricted instead, which
says a record exists and where, and leaves attendance unasserted rather than implying
nobody came.

The input is the directory ingest/groupsio.py writes, one mbox per list; a single
mbox also works. It is not committed -- an archive carries every member's address --
so fetch it first with your own groups.io key.

Run:  python -m bubo_graphrag.ingest.groupsio
      python -m bubo_graphrag.build.meetings [mbox-or-dir]
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from rdflib import Graph, Literal, Namespace, RDF, RDFS, URIRef, XSD

from ..ingest.maillist import (MailParse, mbox_paths, parse_mboxes, seed_series,
                               series_labels)
from ..paths import MAIL, ONTOLOGY

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
OBO = Namespace("http://purl.obolibrary.org/obo/")

MAILLIST_TTL = ONTOLOGY / "maillist.ttl"
# One mbox per list, written by ingest/groupsio.py. A single mbox also works --
# `mbox_paths` accepts either -- so a manual archive download needs no ceremony.
DEFAULT_SOURCE = MAIL

# The mail parser names groups by repository; the publication graph names them by key,
# as a workstream (cosaic:ws-ws1), a governing body (cosaic:gov-tsc) or a committee
# (cosaic:com-marketing). Mapping here keeps meetings attached to the *same* nodes the
# publication graph declares, rather than creating a parallel set. Both spellings are
# keys: a curated series carries the registry's short key, an uncurated one the
# repository name from mail-lists.yaml.
CONVENERS = {
    "tsc": "gov-tsc",
    "pgb": "gov-pgb",
    "marketing": "com-marketing",
    "ws1": "ws-ws1",
    "ws2": "ws-ws2",
    "ws3": "ws-ws3",
    "ws4": "ws-ws4",
    "ws1-supply-chain": "ws-ws1",
    "ws2-defenders": "ws-ws2",
    "ws3-ai-risk-governance": "ws-ws3",
    "ws4-secure-design-agentic-systems": "ws-ws4",
}

# A SIG is recognized by its name, not by its list: SIGs announce on their parent
# workstream's list, so List-Id gives the workstream and the name gives the SIG.
_SIG = re.compile(r"\bSIG\b", re.I)


def _slug(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")[:80]


class MeetingsBuilder:
    """Emits only what list mail establishes.

    A named graph must not re-assert a triple another graph already owns. The union
    default graph is a *multiset* union, so a triple present in two graphs yields two
    solutions and silently doubles every row of any query that joins through it --
    observed as 9 rows where 7 were expected, from one duplicated
    `cosaic:ws-ws2 a cosaic:Workstream`. Shared IRIs are therefore referenced, never
    re-declared: the workstream nodes and the temporal instants that the publication
    catalog already defines are pointed at, and only instants this source introduces
    are declared here.
    """

    def __init__(self, existing_instants: frozenset[str] = frozenset()) -> None:
        self.g = Graph()
        self.g.bind("cosaic", COSAIC)
        self.g.bind("obo", OBO)
        self._instants: set[str] = set()
        self._existing_instants = existing_instants
        # (workstream, day) -> meetings, for attaching summaries. Keyed on the list a
        # message arrived on rather than on the meeting name, because the two never
        # agree: a notice says "CoSAI WS2 regular meeting, bi-weekly" while its summary
        # says "WS2 bi-weekly meeting records". Matching on names linked 0 of 26.
        self._by_workstream_day: dict[tuple[str, str], list[URIRef]] = {}
        self.unlinked_summaries: list[str] = []

    # --- shared nodes ------------------------------------------------------------

    def instant(self, value: str) -> URIRef:
        """A zero-dimensional temporal region, reusing the publication convention."""
        day = value[:10]
        node = COSAIC[f"instant-{day}"]
        if day not in self._instants and day not in self._existing_instants:
            self._instants.add(day)
            # cosaic:Instant, not obo:BFO_0000148 directly: the publications graph
            # uses the former for the same kind of node, and two spellings for one
            # concept would split every temporal query.
            self.g.add((node, RDF.type, COSAIC.Instant))
            self.g.add((node, COSAIC.date, Literal(day, datatype=XSD.date)))
        return node

    def convener(self, workstream: str | None, series_name: str,
                 kind: str | None = None) -> URIRef | None:
        """The workstream, governing body, committee or SIG a series belongs to.

        A SIG gets its own Group of Agents node, `part of` its parent group, because its
        scope is narrower than the parent and a workstream runs several at once. A
        curated `kind` decides whether a series is a SIG's; the name is only the
        fallback for an uncurated series. By name alone neither the Telemetry SIG,
        which announces as "WS2 Defenders – Telemetry", nor "WS4 Multimodal Agentic
        Security" would be a SIG.
        """
        local = CONVENERS.get(workstream or "")
        if local is None:
            return None
        # Referenced only. The publications graph owns the group's type and label;
        # re-asserting either here would duplicate a triple across graphs.
        workstream_node = COSAIC[local]
        is_sig = kind == "sig" if kind else bool(_SIG.search(series_name))
        if not is_sig:
            return workstream_node
        sig_node = COSAIC[f"sig-{_slug(series_name)}"]
        self.g.add((sig_node, RDF.type, COSAIC.SpecialInterestGroup))
        self.g.add((sig_node, RDFS.label, Literal(series_name, lang="en")))
        self.g.add((sig_node, OBO.BFO_0000050, workstream_node))      # part of
        return sig_node

    # --- series ------------------------------------------------------------------

    def add_series(self, series: list[dict]) -> dict[str, URIRef]:
        nodes: dict[str, URIRef] = {}
        conveners: dict[str, URIRef] = {}
        for group in series:
            node = COSAIC[f"series-{group['id']}"]
            nodes[group["id"]] = node
            label = series_labels().get(group["id"], group["name_variants"][0])
            self.g.add((node, RDF.type, COSAIC.MeetingSeries))
            self.g.add((node, RDFS.label, Literal(label, lang="en")))
            for variant in group["name_variants"]:
                self.g.add((node, COSAIC.seriesNameVariant, Literal(variant)))
            for uid in group["ics_uids"]:
                self.g.add((node, COSAIC.icsUid, Literal(uid)))
            if group["cadence"]:
                self.g.add((node, COSAIC.cadence, Literal(group["cadence"])))
            if group["list"]:
                self.g.add((node, COSAIC.sourceList, Literal(group["list"])))
            convener = self.convener(group["workstream"], label, group.get("kind"))
            if convener is not None:
                conveners[group["id"]] = convener
                self.g.add((node, COSAIC.convenedBy, convener))
                self.g.add((node, COSAIC.announcedOn, convener))
        self._add_curated_status(series, conveners)
        return nodes

    def _add_curated_status(self, series: list[dict], conveners: dict[str, URIRef]) -> None:
        """Status and succession, stated by a curator and asserted on SIG nodes only.

        Only a SIG node is owned by this graph. A workstream's or governing body's
        status would belong to the publications graph, which declares that node.
        """
        for group in series:
            convener = conveners.get(group["id"])
            if convener is None or (convener, RDF.type,
                                    COSAIC.SpecialInterestGroup) not in self.g:
                continue
            if group.get("status"):
                self.g.add((convener, COSAIC.activityStatus, Literal(group["status"])))
                self.g.add((convener, COSAIC.statusAsOf,
                            Literal(str(group["status_as_of"]), datatype=XSD.date)))
            successor = conveners.get(group.get("succeeded_by") or "")
            if successor is not None:
                self.g.add((convener, COSAIC.succeededBy, successor))

    # --- occurrences -------------------------------------------------------------

    def add_occurrences(self, parse: MailParse, series_nodes: dict[str, URIRef]) -> int:
        """One Meeting per series-and-day, with cancellations as separate events.

        Deduplicated on (series, day): two messages can announce the same occurrence --
        a calendar notice and a follow-up -- and each would otherwise become a distinct
        meeting on the same day.
        """
        from ..ingest.maillist import _series_key

        seen: dict[tuple[str, str], URIRef] = {}
        # One value per meeting. A meeting one notice announces and another calls off is
        # one meeting and one separate MeetingCancellation; its canceled flag says only
        # whether such an event cancels it, so it never carries both true and false.
        canceled: dict[URIRef, bool] = {}
        cancellations = 0
        for occurrence in parse.occurrences:
            if not occurrence.starts_at:
                continue
            key = _series_key(occurrence.series_name)
            day = occurrence.starts_at[:10]
            node = seen.get((key, day))
            if node is None:
                node = seen[(key, day)] = COSAIC[f"meeting-{key}-{day}"]
                self.g.add((node, RDF.type, COSAIC.Meeting))
                self.g.add((node, RDFS.label,
                            Literal(f"{occurrence.series_name}, {day}", lang="en")))
                self.g.add((node, OBO.BFO_0000199, self.instant(day)))   # occupies
                if key in series_nodes:
                    self.g.add((node, COSAIC.inSeries, series_nodes[key]))
                if occurrence.starts_at and len(occurrence.starts_at) > 10:
                    self.g.add((node, COSAIC.startsAt,
                                Literal(occurrence.starts_at, datatype=XSD.dateTime)))
                if occurrence.ends_at:
                    self.g.add((node, COSAIC.endsAt,
                                Literal(occurrence.ends_at, datatype=XSD.dateTime)))
                self.g.add((node, COSAIC.dateEvidence, Literal(occurrence.evidence)))
                self.g.add((node, COSAIC.sourceMessageId,
                            Literal(occurrence.source_message_id)))
            if occurrence.workstream:
                self._by_workstream_day.setdefault(
                    (occurrence.workstream, day), []).append(node)
            canceled[node] = canceled.get(node, False) or occurrence.canceled
            if occurrence.canceled:
                cancellations += 1
                event = COSAIC[f"cancel-{key}-{day}"]
                self.g.add((event, RDF.type, COSAIC.MeetingCancellation))
                self.g.add((event, COSAIC.cancels, node))
                self.g.add((event, OBO.BFO_0000199, self.instant(day)))
                self.g.add((event, COSAIC.sourceMessageId,
                            Literal(occurrence.source_message_id)))
        for node, value in canceled.items():
            self.g.add((node, COSAIC.canceled, Literal(value)))
        return cancellations

    # --- summaries, governance, coverage -----------------------------------------

    def add_summaries(self, parse: MailParse) -> None:
        """Record that a meeting record exists, and attach it where that is unambiguous.

        Attached on (workstream, day), not on the meeting name: see
        `_by_workstream_day`. Where a workstream held more than one meeting that day
        the summary is left unattached and reported, because picking one would be a
        guess -- and a summary attributed to the wrong meeting is worse than an
        unattached one.
        """
        from ..ingest.maillist import _series_key

        for index, summary in enumerate(parse.summaries):
            node = COSAIC[f"summary-{_series_key(summary.series_name)}-{index:03d}"]
            self.g.add((node, RDF.type, COSAIC.MeetingSummary))
            self.g.add((node, RDFS.label,
                        Literal(f"Summary: {summary.series_name}", lang="en")))
            self.g.add((node, COSAIC.accessRestricted,
                        Literal(summary.access_restricted)))
            self.g.add((node, COSAIC.sourceMessageId,
                        Literal(summary.source_message_id)))
            if summary.list_name:
                self.g.add((node, COSAIC.sourceList, Literal(summary.list_name)))
            for url in summary.urls:
                self.g.add((node, COSAIC.sourceUrl, URIRef(url)))
            if not summary.meeting_date:
                self.unlinked_summaries.append(f"{summary.series_name}: no date")
                continue
            self.g.add((node, COSAIC.assertedAt, self.instant(summary.meeting_date)))
            candidates = self._by_workstream_day.get(
                (summary.workstream or "", summary.meeting_date), [])
            if len(candidates) == 1:
                self.g.add((candidates[0], COSAIC.summarizedBy, node))
            else:
                self.unlinked_summaries.append(
                    f"{summary.meeting_date} {summary.series_name!r}: "
                    f"{len(candidates)} candidate meetings on that day")

    def add_governance(self, parse: MailParse) -> None:
        for index, event in enumerate(parse.governance):
            node = COSAIC[f"govevent-{index:03d}"]
            self.g.add((node, RDF.type, COSAIC.GovernanceEvent))
            self.g.add((node, RDFS.label, Literal(event.subject, lang="en")))
            self.g.add((node, COSAIC.sourceList, Literal(event.list_name)))
            self.g.add((node, COSAIC.sourceMessageId, Literal(event.source_message_id)))
            if event.occurred_at:
                self.g.add((node, OBO.BFO_0000199, self.instant(event.occurred_at)))
            convener = self.convener(event.workstream, "")
            if convener is not None:
                self.g.add((node, COSAIC.announcedOn, convener))

    def add_calls(self, parse: MailParse, curation: dict | None = None) -> int:
        """Each governance call as one node, its messages part of it, and the curated
        links from a call to the works it seeks approval of.

        The call is the thread ingest/approvals.py groups -- subject key and deciding
        body -- so a TSC and a PGB call on one paper are two nodes with their own dates.
        Links come only from registry/approvals.yaml; a call nobody has curated still
        appears, with its stage and dates, and links to nothing.
        """
        from ..ingest import approvals as A

        curated = (curation or {}).get("threads") or {}
        role_property = {"new": COSAIC.callsToApproveNew,
                         "revision": COSAIC.callsToApproveRevision,
                         "addition": COSAIC.callsToApproveAddition}
        calls: dict[tuple[str, str | None], URIRef] = {}
        for thread in A.threads(parse):
            node = COSAIC[f"govcall-{(thread.body or 'relay').lower()}-{_slug(thread.key)}"]
            if node in calls.values():
                raise ValueError(f"two calls reduce to one IRI: {node}")
            calls[(thread.key, thread.body)] = node
            self.g.add((node, RDF.type, COSAIC.GovernanceCall))
            self.g.add((node, RDFS.label, Literal(thread.subject, lang="en")))
            self.g.add((node, COSAIC.callStage, Literal(thread.stage)))
            if thread.opened:
                self.g.add((node, COSAIC.openedOn, Literal(thread.opened, datatype=XSD.date)))
            if thread.deadline:
                self.g.add((node, COSAIC.objectionDeadline,
                            Literal(thread.deadline, datatype=XSD.date)))
            if thread.closed:
                self.g.add((node, COSAIC.closedOn, Literal(thread.closed, datatype=XSD.date)))
            if thread.states_tsc_approval:
                self.g.add((node, COSAIC.restatesTscApproval, Literal(True)))
            for body in sorted(thread.bodies):
                # Referenced only: the publications graph declares the governing bodies.
                self.g.add((node, COSAIC.decidedBy, COSAIC[f"gov-{body.lower()}"]))
            entry = curated.get(thread.key)
            if not entry:
                continue
            self.g.add((node, COSAIC.subjectMatter, Literal(entry["subject_matter"])))
            for title in [link["title"] for link in entry.get("unregistered") or []] + \
                    list(entry.get("blogs") or []):
                self.g.add((node, COSAIC.concernsTitle, Literal(title)))
            if entry["subject_matter"] != "publication":
                continue
            for link in entry.get("works") or []:
                work = COSAIC[f"pub-{link['id']}"]
                if thread.stage == "review-period":
                    self.g.add((node, COSAIC.callsToReview, work))
                    continue
                self.g.add((node, role_property[link["as"]], work))
                if link["as"] == "addition":
                    self.g.add((work, COSAIC.isAdditionTo, COSAIC[f"pub-{link['to']}"]))
        for index, event in enumerate(parse.governance):
            call = calls.get((A.thread_key(event.subject), A.deciding_body(event)))
            if call is not None:
                self.g.add((COSAIC[f"govevent-{index:03d}"], COSAIC.partOfCall, call))
        return len(calls)

    def add_coverage(self, parse: MailParse) -> None:
        """What the source is known to cover.

        Without this the graph would imply that a week with no meeting had none, when
        the fetched archive simply may not reach that far. Outside the window, absence is not
        evidence -- the same rule the affiliation model applies to open bounds.
        """
        for list_name, window in sorted(parse.coverage.items()):
            node = COSAIC[f"coverage-{list_name}"]
            self.g.add((node, RDF.type, COSAIC.CoverageWindow))
            self.g.add((node, RDFS.label,
                        Literal(f"{list_name}: {window['earliest']}..{window['latest']}",
                                lang="en")))
            self.g.add((node, COSAIC.sourceList, Literal(list_name)))
            self.g.add((node, COSAIC.earliestMessage,
                        Literal(window["earliest"], datatype=XSD.date)))
            self.g.add((node, COSAIC.latestMessage,
                        Literal(window["latest"], datatype=XSD.date)))
            self.g.add((node, COSAIC.boundsKnown, Literal(False)))


def existing_instants() -> frozenset[str]:
    """Days another graph already declares as temporal instants.

    The publication catalog, the citations graph and the website graph all declare
    instants, and a day any of them owns must be referenced here, never re-declared.
    """
    from ..paths import CATALOG_TTL

    owned = Graph()
    for path in (CATALOG_TTL, ONTOLOGY / "citations.ttl", ONTOLOGY / "website.ttl"):
        if path.exists():
            owned.parse(path, format="turtle")
    return frozenset(str(value) for value in owned.objects(None, COSAIC.date))


def curated_only_series(series: list[dict]) -> list[dict]:
    """Registry series the mail has no occurrence of.

    A curated series is a series whether or not a notice for it survives in the lists:
    WS3's Agentic Coding Threat Modeling Sync posts meeting records but no occurrence
    notices, and the calendar schedules it weekly. Without its node, the calendar graph
    would have nothing to link its entries to.
    """
    from ..paths import load_registry

    present = {group["id"] for group in series}
    out = []
    for entry in load_registry("meeting-series")["meeting_series"]:
        if entry["id"] in present:
            continue
        out.append({
            "id": entry["id"], "ics_uids": [], "workstream": entry.get("workstream"),
            "list": (entry.get("lists") or [None])[0],
            "name_variants": entry.get("name_variants") or [entry["label"]],
            "cadence": entry.get("cadence"), "occurrences": 0, "cancellations": 0,
            "kind": entry.get("kind"),
            **{key: entry[key] for key in ("status", "status_as_of", "succeeded_by")
               if entry.get(key)},
        })
    return out


def build(source: Path, *, curated_only: bool = False,
          approval_curation: dict | None = None
          ) -> tuple[Graph, MailParse, list[dict], list[str]]:
    """The maillist graph from the mail at `source`. With `curated_only`, also every
    registry series that mail has no occurrence of -- what the real build wants, and
    what a test of a handful of messages must not get. `approval_curation` is
    registry/approvals.yaml, whose links are added to the calls it names."""
    parse = parse_mboxes(mbox_paths(source))
    series = seed_series(parse)
    if curated_only:
        series += curated_only_series(series)
    builder = MeetingsBuilder(existing_instants())
    nodes = builder.add_series(series)
    builder.add_occurrences(parse, nodes)
    builder.add_summaries(parse)
    builder.add_governance(parse)
    builder.add_calls(parse, approval_curation)
    builder.add_coverage(parse)
    return builder.g, parse, series, builder.unlinked_summaries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", default=str(DEFAULT_SOURCE),
                        metavar="MBOX_OR_DIR",
                        help=f"an mbox, or a directory of them (default: {MAIL})")
    parser.add_argument("--no-store", action="store_true",
                        help="write maillist.ttl only, skip reloading the store")
    args = parser.parse_args(argv)

    source = Path(args.source)
    if not source.exists() or not mbox_paths(source):
        parser.error(
            f"no mbox at {source}. This graph is optional and its input is not "
            "committed -- the archives hold member addresses. Fetch them with your "
            "own groups.io key:\n    python -m bubo_graphrag.ingest.groupsio")

    from ..paths import load_registry
    graph, parse, series, unlinked = build(source, curated_only=True,
                                           approval_curation=load_registry("approvals"))
    MAILLIST_TTL.write_text(
        "# GENERATED by `python -m bubo_graphrag.build.meetings` -- do not hand-edit.\n"
        "# Derived from the groups.io list archives; not committed. Coverage is partial:\n"
        "# outside each cosaic:CoverageWindow, absence of a meeting is not evidence.\n\n"
        + graph.serialize(format="turtle"), encoding="utf-8")
    print(f"{len(graph)} triples -> {MAILLIST_TTL}")
    print(f"  {len(series)} series, {len(parse.occurrences)} occurrences, "
          f"{len(parse.summaries)} summaries, {len(parse.governance)} governance events")
    linked = len(parse.summaries) - len(unlinked)
    print(f"  summaries attached to a meeting: {linked}/{len(parse.summaries)}")
    for note in unlinked:
        print(f"    unattached: {note}")

    if not args.no_store:
        from ..store import load_store
        print(f"  store reloaded: {load_store()} quads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
