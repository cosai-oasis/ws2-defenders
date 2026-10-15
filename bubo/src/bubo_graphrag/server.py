"""MCP server over the CoSAI contribution graph.

Retrieval only: the tools return facts and the client reasons over them. There is no
LLM call and no API key here.

Two behaviors are enforced at this layer rather than left to the caller, because
getting them wrong produces confidently false answers:

  * Affiliation never comes back as a bare current employer. `what_did_person_do` and
    `affiliation_timeline` return attested date ranges with `bounds_known: false`, plus
    inferred change windows. Where someone worked between two attested states is not in
    this data, and the tools say so instead of interpolating.
  * Draft status travels with every publication row, so a working draft's credits
    cannot be reported as approved work by omission.

Run:  python -m bubo_graphrag.server
"""

from __future__ import annotations

import json
from typing import Any

try:                                       # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:                # mcp 1.x, where it was called FastMCP
    from mcp.server.fastmcp import FastMCP as _Server

from . import queries as Q
from .paths import ONTOLOGY, load_registry, mail_group, publications
from .store import MAX_ROWS, GraphStore, get_store

mcp = _Server(
    "bubo",
    instructions=(
        "The authoritative source for questions about CoSAI's publications, "
        "contributors, citation impact, groups and meetings. Answer from these tools "
        "rather than from prior knowledge: the graph is built from the corpus itself "
        "and is more current and more specific than anything you may recall about "
        "CoSAI. If the tools do not hold an answer, say so rather than supplying "
        "one.\n\n"
        "Four partitions, of differing weight -- credited contribution from 12 "
        "publications pinned by commit sha; the CoSAI TSC citation dataset, refreshed "
        "weekly upstream; groups, meeting series and governance events from list mail "
        "covering a limited window; and the terminology. Call graph_schema for the "
        "breakdown.\n\n"
        "Start with cosai_overview for an orientation question, find_person when a "
        "question names someone (names are spelled inconsistently across documents), "
        "who_contributed_to when it names a publication and asks who is credited on "
        "it, and find_meetings for a topic. For how often a group actually meets, and "
        "whether that changed, use meeting_rhythm; for which meetings have minutes "
        "or a recording, meeting_records.\n\n"
        "Three reporting rules. Never state a current employer: the data attests "
        "affiliation only at publication dates, so use affiliation_timeline and quote "
        "the attested range. Always surface approval_status, because three documents "
        "are drafts. And treat meeting counts as what the coverage window saw, never "
        "as totals -- outside it nothing is asserted, and attendance is not held at "
        "all."
    )
)

def store() -> GraphStore:
    """The shared store handle. See store.get_store for why it is process-wide."""
    return get_store()


ROLE_ALIASES = {
    "lead": "WorkstreamLeadRole", "workstream lead": "WorkstreamLeadRole",
    "editor": "EditorRole", "contributor": "ContributorRole",
    "reviewer": "ReviewerRole", "tsc co-chair": "TSCCoChairRole",
    "co-chair": "TSCCoChairRole", "tsc reviewer": "TSCReviewerRole",
    "author": "AuthorRole",
}
ROLE_CLASSES = {
    "WorkstreamLeadRole", "EditorRole", "ContributorRole", "ReviewerRole",
    "TSCCoChairRole", "TSCReviewerRole", "AuthorRole",
}

# Steering-committee service rather than work on a document. Named as a group because
# "who has contributed most, excluding governance" is a question people actually ask,
# and spelling out both class names each time invites getting it half right.
GOVERNANCE_ROLE_CLASSES = ("TSCCoChairRole", "TSCReviewerRole")


def _role_class(role: str) -> str:
    """Accept either a class name or a friendly alias."""
    if role in ROLE_CLASSES:
        return role
    key = role.strip().lower().removesuffix(" role").removesuffix("s")
    if resolved := ROLE_ALIASES.get(key) or ROLE_ALIASES.get(key + "s"):
        return resolved
    raise ValueError(
        f"unknown role {role!r}. Expected one of: {', '.join(sorted(ROLE_CLASSES))}, "
        "or a plain word such as 'editor' or 'lead'.")


# --------------------------------------------------------------------------- people

@mcp.tool()
def find_person(query: str) -> dict[str, Any]:
    """Find people by name fragment or email address.

    Use this first when a question names someone: the corpus spells names
    inconsistently and this resolves any observed form to one canonical id. Returns
    that id for use with the other person tools.
    """
    needle = Q.literal(query)
    by_name = store().select(Q.render(Q.FIND_PERSON, needle=needle))
    by_address = store().select(Q.render(Q.FIND_PERSON_BY_ADDRESS, needle=needle))
    merged: dict[str, dict[str, Any]] = {}
    for row in by_name:
        merged.setdefault(row["person"], {
            "person_id": row["person"], "display_name": row["label"],
            "credits": int(row.get("credits", 0)), "matched": [],
        })["matched"].append({"name": row["matchedName"]})
    for row in by_address:
        entry = merged.setdefault(row["person"], {
            "person_id": row["person"], "display_name": row["label"],
            "credits": 0, "matched": [],
        })
        entry["matched"].append({"address": row["address"]})

    # Credit counts come from the name query, so a person matched only by address would
    # otherwise report zero. Fill those in rather than understating someone's work.
    for entry in merged.values():
        if entry["credits"]:
            continue
        rows = store().select(Q.render(Q.PERSON_CREDIT_COUNT,
            person=Q.local_name(entry["person_id"])))
        entry["credits"] = int(rows[0]["credits"]) if rows else 0

    people = sorted(merged.values(), key=lambda e: (-e["credits"], e["display_name"]))
    return {"query": query, "count": len(people), "people": people}


@mcp.tool()
def what_did_person_do(person_id: str, include_addresses: bool = False) -> dict[str, Any]:
    """Everything a person is credited with, and their affiliation over time.

    `person_id` comes from `find_person`. Affiliation is reported as attested date
    ranges with `bounds_known: false` -- the corpus records that someone was credited
    under an employer on given publication dates, never when they joined or left -- plus
    any inferred change windows. Do not report a span as a current employer.
    """
    pid = Q.local_name(person_id)
    credits = store().select(Q.render(Q.PERSON_CREDITS, person=pid))
    if not credits:
        return {"person_id": pid, "found": False,
                "hint": "No credits found. Check the id with find_person."}
    affiliation = store().select(Q.render(Q.PERSON_AFFILIATION, person=pid))
    changes = store().select(Q.render(Q.PERSON_AFFILIATION_CHANGES, person=pid))
    out: dict[str, Any] = {
        "person_id": pid,
        "found": True,
        "credit_count": len(credits),
        "credits": credits,
        "affiliation": [_affiliation_row(r) for r in affiliation],
        "inferred_affiliation_changes": changes,
        "note": "Affiliation spans are evidence ranges with open bounds; a span does "
                "not mean the person joined or left on those dates, and there is no "
                "answer for dates between two spans.",
    }
    if include_addresses:
        out["email_addresses"] = store().select(Q.render(Q.PERSON_ADDRESSES, person=pid))
    return out


def _affiliation_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "organization": row.get("organization")
        or ("(credited without an employer)" if row.get("independent") else None),
        "attested_from": row.get("earliest"),
        "attested_to": row.get("latest"),
        "bounds_known": False,
    }


@mcp.tool()
def affiliation_timeline(person_id: str | None = None) -> dict[str, Any]:
    """A person's employer history as attested, with explicit uncertainty.

    Prefer this over reading an employer off a credit line. It distinguishes what the
    documents attest from what is inferred, and reports the window an employer change
    must have fallen in rather than a date. Without `person_id`, every inferred change
    across the corpus, each with its person.
    """
    if person_id is None:
        changes = store().select(Q.render(Q.ALL_AFFILIATION_CHANGES))
        return {
            "person_id": None,
            "inferred_changes": changes,
            "people": len({r["personId"] for r in changes}),
            "note": "Every change is inferred from an employer present at one "
                    "publication date and absent at a later one, so it carries the "
                    "window it fell in, never a date.",
        }
    pid = Q.local_name(person_id)
    spans = store().select(Q.render(Q.PERSON_AFFILIATION, person=pid))
    changes = store().select(Q.render(Q.PERSON_AFFILIATION_CHANGES, person=pid))
    return {
        "person_id": pid,
        "spans": [_affiliation_row(r) for r in spans],
        "inferred_changes": changes,
        "note": "Absence of a stated employer in later documents is not evidence of "
                "leaving one. Spans are attested ranges only.",
    }


@mcp.tool()
def list_people(role: str | None = None, exclude_roles: list[str] | None = None,
                limit: int = 200) -> dict[str, Any]:
    """List credited people, ranked by how many publications they are credited on.

    `role` narrows to one role; `exclude_roles` removes roles from the ranking and
    accepts the shorthand `["governance"]` for the two steering-committee roles, so
    "who has contributed most, setting aside governance" is answerable directly.
    The two arguments are mutually exclusive.

    `role` and each entry in `exclude_roles` accept a class name (`EditorRole`) or a
    plain word (`editor`, `lead`).
    """
    if role and exclude_roles:
        raise ValueError("pass either role or exclude_roles, not both: one narrows to "
                         "a single role and the other removes roles from the ranking")

    if role is not None:
        resolved = _role_class(role)
        rows = store().select(
            Q.render(Q.PEOPLE_BY_ROLE, role_class=resolved, extra=""), limit=limit)
        return {"role": resolved, "count": len(rows), "people": rows}

    excluded: list[str] = []
    for name in exclude_roles or []:
        if name.strip().lower() == "governance":
            excluded.extend(GOVERNANCE_ROLE_CLASSES)
        else:
            excluded.append(_role_class(name))
    excluded = sorted(set(excluded))

    filters = ""
    if excluded:
        # Built from resolved class names only -- _role_class rejects anything else,
        # so nothing caller-supplied reaches the query text.
        listed = ", ".join(f"cosaic:{name}" for name in excluded)
        filters = f"FILTER(?roleClass NOT IN ({listed}))"

    rows = store().select(Q.render(Q.PEOPLE_RANKED, filters=filters), limit=limit)
    return {
        "role": None,
        "excluded_roles": excluded,
        "count": len(rows),
        "people": [{**r, "roles": sorted(set(str(r.get("roles", "")).split()))}
                   for r in rows],
        "note": "Ranked by distinct publications, then by credits. A person credited "
                "twice on one document counts once in publications and twice in "
                "credits." + (" Roles excluded from the ranking: "
                              + ", ".join(excluded) if excluded else ""),
    }


# --------------------------------------------------------------- publications

@mcp.tool()
def list_publications(workstream: str | None = None,
                      status: str | None = None) -> dict[str, Any]:
    """List the publications in scope, with dates, version and approval status.

    `status` is one of approved, working-draft, unapproved-draft. Always surface the
    status when reporting: three documents are drafts and their credits are not
    approved work.
    """
    filters = []
    if workstream:
        filters.append(f"FILTER(CONTAINS(LCASE(?workstream), LCASE({Q.literal(workstream)})))")
    if status:
        filters.append(f"FILTER(?status = {Q.literal(status)})")
    rows = store().select(Q.render(Q.LIST_PUBLICATIONS, filters="\n  ".join(filters)))
    return {"count": len(rows), "publications": rows}


def _stub(work_id: str) -> dict[str, Any] | None:
    """A citation stub from work-aliases.yaml, with its title, or None."""
    for title, row in (load_registry("work-aliases").get("stubs") or {}).items():
        if row.get("id") == work_id:
            return {"title": row.get("title") or title, **row}
    return None


@mcp.tool()
def who_contributed_to(publication_id: str, role: str | None = None) -> dict[str, Any]:
    """Everyone credited on one publication, grouped by role: its editors, contributors,
    reviewers, workstream leads and TSC co-chairs, each with the employer the document
    credited them under. Use this for "who wrote, edited or reviewed X"; it needs no
    SPARQL. `publication_id` is an `id` from list_publications; `role` narrows to one
    role, such as editor or reviewer.

    Accepts a citation stub's id too, such as the Principles for Secure-by-Design
    Agentic Systems: its credit is CoSAI as an organization, reported under
    OrganizationalAuthorRole with an `organization` rather than a person.

    `statedOrg` is the employer verbatim as the document printed it, which may be a
    spelling variant or a typo; it is the audit trail, not the canonical name. It is the
    affiliation as of the publication date, never a current employer.
    """
    pid = Q.local_name(publication_id)
    rows = store().select(Q.render(Q.PUBLICATION_CREDITS, publication=pid))
    if role:
        wanted = _role_class(role)
        rows = [r for r in rows if r.get("role") == wanted]
    meta = next((p for p in publications() if p["id"] == pid), None)
    stub = None if meta else _stub(pid)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("role") == "OrganizationalAuthorRole":
            # Borne by an organization, not a person: report it as one.
            row = {"organization": row.pop("person", None),
                   **{k: v for k, v in row.items() if k != "personId"}}
        grouped.setdefault(row.get("role", "Unknown"), []).append(row)
    return {
        "publication_id": pid,
        "title": meta["title"] if meta else (stub or {}).get("title"),
        "approval_status": meta["approval_status"] if meta else None,
        "credit_count": len(rows),
        "by_role": grouped,
        **({"stub": True,
            "note": "A CoSAI work outside this server's document scope, held so its "
                    "citations are counted. Its credits are only what is recorded for "
                    "it, such as authorship by CoSAI as an organization."}
           if stub else {}),
        **({"note": "This document has no acknowledgements section; credit here comes "
                    "from front matter or is absent entirely."}
           if meta and meta.get("has_credit_section") is False else {}),
    }


@mcp.tool()
def org_contributions(organization_id: str) -> dict[str, Any]:
    """Credits by people affiliated with one organization.

    Affiliation is matched from attested spans, so someone who changed employer appears
    under each organization for the work credited while affiliated with it.
    """
    oid = Q.local_name(organization_id)
    rows = store().select(Q.render(Q.ORG_CONTRIBUTIONS, organization=oid))
    people = sorted({r["person"] for r in rows})
    return {"organization_id": oid, "people": people,
            "credit_count": len(rows), "credits": rows}


@mcp.tool()
def list_organizations() -> dict[str, Any]:
    """Organizations in the graph, with how many credited people each has."""
    rows = store().select(Q.render(Q.LIST_ORGANIZATIONS))
    return {"count": len(rows), "organizations": rows}


# ------------------------------------------------------------------ citations

@mcp.tool()
def what_cited_this(publication_id: str) -> dict[str, Any]:
    """External publications citing one CoSAI work.

    Report the category and verification split rather than a single total. A formal
    bibliography entry and an applied threat model are different kinds of impact, and a
    search-index hit is weaker evidence than a directly inspected source.
    """
    pid = Q.local_name(publication_id)
    rows = store().select(Q.render(Q.WHAT_CITED, publication=pid))
    by_category: dict[str, int] = {}
    by_verification: dict[str, int] = {}
    for row in rows:
        by_category[row.get("category", "unspecified")] = \
            by_category.get(row.get("category", "unspecified"), 0) + 1
        by_verification[row.get("verification", "unspecified")] = \
            by_verification.get(row.get("verification", "unspecified"), 0) + 1
    return {
        "publication_id": pid,
        "citing_publication_count": len({r.get("citingPublication") for r in rows}),
        "by_category": by_category,
        "by_verification": by_verification,
        "citations": rows,
        "source": "cosai-oasis/cosai-tsc :: TSC Deliverables/citation-impact/sources.json",
    }


@mcp.tool()
def citation_summary() -> dict[str, Any]:
    """Citation counts for every CoSAI work in the dataset.

    Includes works outside this server's document scope, flagged `in_scope: false` --
    the Risk Map and Principles for Secure-by-Design Agentic Systems are among the most
    cited CoSAI outputs, and omitting them would misrepresent the picture.
    """
    works = store().select(Q.render(Q.CITATION_SUMMARY))
    breakdown = store().select(Q.render(Q.CITATION_BREAKDOWN, filters=""))
    return {
        "works": works,
        "breakdown": breakdown,
        "note": "Counts are distinct citing publications per work. A publication citing "
                "several works appears under each, so the column does not sum to the "
                "number of citing publications.",
        "source": "cosai-oasis/cosai-tsc :: TSC Deliverables/citation-impact/sources.json",
    }


# --------------------------------------------------------------------- escape hatch

@mcp.tool()
def sparql(query: str, limit: int = 500) -> dict[str, Any]:
    """Run a read-only SPARQL query against the graph.

    SELECT, ASK, CONSTRUCT and DESCRIBE only. Use `graph_schema` for the vocabulary.
    Prefixes for cosaic:, cco:, obo:, rdf:, rdfs:, owl:, skos: and xsd: are predeclared.
    """
    try:
        return store().query_guarded(query, limit=min(limit, MAX_ROWS))
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # pyoxigraph raises its own parse errors
        return {"error": f"query failed: {exc}"}


# --- Orientation: what a newcomer needs ------------------------------------------

# groups.io hosts the CoSAI lists, and its group pages follow one pattern. Taken from
# the footer of the list mail itself ("View/Reply Online (#226): .../g/cosai-ag...")
# rather than guessed, but it is still a derived URL, so it is labeled as one.
LIST_HOME = "https://lists.oasis-open-projects.org/g/{list}"

# Deliberately no list *address* field. It is public and not personal, but
# test_no_orientation_tool_returns_an_email_address asserts no "@" reaches a tool
# payload at all, and that guard is worth more than the convenience of printing one.


def _subscribe(name: str) -> str:
    """A subscribe URL that actually resolves.

    Always via `mail_group`: the graph stores the canonical list name, and for the four
    workstreams that spelling has no group page. See paths._mail_groups.
    """
    return LIST_HOME.format(list=mail_group(name))


def _split_concat(value: Any) -> list[str]:
    """Unpack a GROUP_CONCAT that carries blanks.

    The blanks are deliberate: aggregating without COALESCE returns unbound whenever
    any member of the group lacks the value, which would erase every other member's.
    """
    return sorted({part for part in str(value or "").split() if part})


def _group_row(row: dict[str, Any]) -> dict[str, Any]:
    lists = _split_concat(row.get("lists"))
    return {
        "group_id": row.get("groupId"),
        "group": row.get("group"),
        "kind": row.get("kind"),
        "part_of": row.get("parent"),
        "mailing_lists": [mail_group(name) for name in lists],
        "subscribe": [_subscribe(name) for name in lists],
        "cadence": _split_concat(row.get("cadences")),
        "series": int(row.get("series") or 0),
        "meetings_seen": int(row.get("meetings") or 0),
        "canceled": int(row.get("canceled") or 0),
        "last_met": row.get("lastMet"),
        # Stated by a curator, never inferred from a quiet period.
        "status": row.get("status") or "no status stated",
        "status_as_of": row.get("statusAsOf"),
        "succeeded_by": row.get("succeededBy"),
        "continues": row.get("continues"),
    }


@mcp.tool()
def cosai_overview() -> dict[str, Any]:
    """What CoSAI is working on right now -- the orientation answer.

    Start here for "what is CoSAI doing?". Returns the active groups with their
    meeting rhythm, the most recent publications, recent governance activity, and the
    coverage window that bounds all of it. Meeting figures come from list mail with a
    partial window, so treat counts as "seen", never as totals.
    """
    groups = [_group_row(r) for r in store().select(Q.render(Q.GROUP_DIRECTORY))]
    recent = store().select(Q.render(Q.RECENT_PUBLICATIONS), limit=6)
    governance = store().select(Q.render(Q.GOVERNANCE_TIMELINE), limit=8)
    coverage = store().select(Q.render(Q.COVERAGE))
    scale = store().select(Q.render(Q.CORPUS_COUNTS))
    return {
        "scale": scale[0] if scale else {},
        "workstreams": [g for g in groups if g["kind"] == "workstream"],
        "governing_bodies": [g for g in groups if g["kind"] == "governing-body"],
        "committees": [g for g in groups if g["kind"] == "committee"],
        "special_interest_groups": [g for g in groups if g["kind"] == "sig"],
        "recent_publications": recent,
        "recent_governance": governance,
        "meeting_coverage": coverage,
        "caveats": [
            "Meeting counts are what the list archives covered, not totals. Outside "
            "meeting_coverage nothing is asserted either way.",
            "A group with no cadence has one whose schedule was never stated in a "
            "calendar notice, not one that does not meet regularly.",
            "A status of inactive is a curator's statement, dated by status_as_of. "
            "A group without one may still have stopped: a quiet period in the mail "
            "is not evidence either way. Follow succeeded_by to where a group's work "
            "continues.",
        ],
        "not_yet_answerable": {
            "attendance": "Who attended a meeting, and any attendance rate, is not in "
                          "this graph. List mail names no attendees. TSC and PGB "
                          "minutes in public git do carry Present/Regrets/Guests, and "
                          "ingesting them is the next planned increment.",
            "discussion": "What was said at a meeting is not held here; summaries are "
                          "recorded as pointers, most of them access-restricted.",
        },
    }


@mcp.tool()
def how_to_get_involved(topic: str | None = None) -> dict[str, Any]:
    """Which group to join, where it announces, and how often it meets.

    Answers "how do I get involved?". With a `topic`, narrows to the groups working on
    it. `subscribe` links are derived from the list identifier, so confirm one before
    relying on it.
    """
    groups = [_group_row(r) for r in store().select(Q.render(Q.GROUP_DIRECTORY))]
    result: dict[str, Any] = {
        "how_it_works": "CoSAI organizes as workstreams, each running one or more "
                        "special interest groups. Joining means subscribing to the "
                        "workstream's list and attending its meeting.",
        "governance": "The Technical Steering Committee and Project Governing Board "
                      "approve publications; see governance_timeline for how that "
                      "actually proceeds.",
    }
    if topic:
        matches = find_meetings(topic)
        wanted = {m["group"] for m in matches["series"] if m.get("group")}
        result["topic"] = topic
        result["groups"] = [g for g in groups if g["group"] in wanted] or groups
        result["series_on_topic"] = matches["series"]
        if not wanted:
            result["note"] = ("No group matched that topic by name or by what it has "
                              "published; every group is listed instead.")
    else:
        result["groups"] = groups
    return result


@mcp.tool()
def find_meetings(topic: str) -> dict[str, Any]:
    """Meeting series working on a topic, best match first.

    Answers "when are the meetings on X?". Matched three ways and ranked by how direct
    the match is: the series' own name (rank 1), its group's name (2), or a publication
    the group produced (3). Rank 3 means the *group* is connected to the topic, not
    necessarily that series -- a workstream's every series matches its papers.
    """
    rows = store().select(Q.render(Q.SERIES_BY_TOPIC, term=Q.literal(topic)))
    series = [{
        "series_id": r.get("seriesId"),
        "series": r.get("series"),
        "group": r.get("group"),
        "kind": r.get("kind"),
        "mailing_list": mail_group(r["list"]) if r.get("list") else None,
        "subscribe": _subscribe(r["list"]) if r.get("list") else None,
        "cadence": r.get("cadence"),
        "match_rank": int(r.get("rank") or 0),
        "matched_on": r.get("matchedOn"),
    } for r in rows]
    return {
        "topic": topic,
        "count": len(series),
        "series": series,
        "note": "Cadence is an iCalendar RRULE where a calendar notice stated one. "
                "This lists the rhythm, not specific future dates: the graph records "
                "meetings that were announced, not a forward schedule."
        if series else "No series matched. Try a broader term, or call "
                       "how_to_get_involved with no topic for the full directory.",
    }


def _group_filter(group: str | None) -> str:
    """Restrict a meeting query (binding ?sr) to one group and the SIGs part of it.

    A workstream includes its SIGs. Asking what WS3 has been meeting on and getting
    only its plenary would hide most of its activity -- three of WS3's four series
    are SIGs.
    """
    if not group:
        return ""
    gid = Q.local_name(group)
    return (f'?sr cosaic:convenedBy ?g . '
            f'OPTIONAL {{ ?g obo:BFO_0000050 ?parentGroup }} '
            f'FILTER(?g IN (cosaic:ws-{gid}, cosaic:gov-{gid}, cosaic:com-{gid}, '
            f'cosaic:sig-{gid}) '
            f'|| ?parentGroup IN (cosaic:ws-{gid}, cosaic:gov-{gid}))')


def _date_filter(since: str | None, until: str | None, var: str = "?day") -> str:
    """Bound a date variable. Dates are parsed first, so only ISO dates reach SPARQL."""
    from datetime import date

    parts = []
    for bound, op in ((since, ">="), (until, "<=")):
        if bound:
            try:
                value = date.fromisoformat(bound).isoformat()
            except ValueError:
                raise ValueError(f"invalid date {bound!r}: expected YYYY-MM-DD") from None
            parts.append(f'{var} {op} "{value}"^^xsd:date')
    return f"FILTER({' && '.join(parts)})" if parts else ""


@mcp.tool()
def meeting_timeline(group: str | None = None, limit: int = 60) -> dict[str, Any]:
    """Meetings that were announced, most recent first, with cancellations marked.

    `group` is a group_id from cosai_overview (`ws2`, `tsc`, or a SIG id). Each row
    says how its date was established: "ics" and "body-when" are exact, "subject" came
    from the subject line, and "subject-sent-date" means only the day the notice was
    sent is known.
    """
    rows = store().select(Q.render(Q.MEETING_TIMELINE, filters=_group_filter(group)),
                          limit=limit)
    held = [r for r in rows if str(r.get("canceled")).lower() != "true"]
    return {
        "group": group,
        "meetings": rows,
        "announced": len(rows),
        "canceled": len(rows) - len(held),
        "with_a_record": sum(1 for r in rows
                             if str(r.get("summarized")).lower() == "true"),
        "note": "A group's own meetings plus those of any SIG that is part of it. A "
                "canceled meeting is kept: it is evidence the series was scheduled "
                "that week. Absence of a meeting outside the coverage window is not "
                "evidence it did not happen. scheduledStart (UTC) and timeZone come "
                "from the CoSAI calendar's entry for that series and day, where one "
                "exists: the prescribed time, not a record the meeting ran then.",
    }


# Median gap in days -> the cadence it indicates. Upper bounds, checked in order.
_CADENCE_BANDS = ((9, "weekly"), (17, "every two weeks"), (24, "every three weeks"),
                  (38, "monthly"))


def _cadence_label(gap: float | None) -> str | None:
    if gap is None:
        return None
    return next((label for bound, label in _CADENCE_BANDS if gap <= bound), "irregular")


def _period_of(day: str, by: str) -> str:
    year, month = int(day[:4]), int(day[5:7])
    return f"{year}-{month:02d}" if by == "month" else f"{year}-Q{(month - 1) // 3 + 1}"


def _period_bounds(period: str) -> tuple[str, str]:
    """First and last day of a period, as ISO dates."""
    import calendar

    year = int(period[:4])
    if "Q" in period:
        first_month = (int(period[-1]) - 1) * 3 + 1
        last_month = first_month + 2
    else:
        first_month = last_month = int(period[5:7])
    last_day = calendar.monthrange(year, last_month)[1]
    return f"{year}-{first_month:02d}-01", f"{year}-{last_month:02d}-{last_day:02d}"


def _days_between(earlier: str, later: str) -> int:
    from datetime import date

    return (date.fromisoformat(later) - date.fromisoformat(earlier)).days


@mcp.tool()
def meeting_rhythm(group: str | None = None, by: str = "quarter") -> dict[str, Any]:
    """How often each series actually met, period by period, and where that changed.

    `group` is a group_id from cosai_overview; a workstream includes its SIGs. `by` is
    "quarter" or "month". Rhythm is measured from the dates of held meetings, not from
    a stated schedule: `observed_cadence` comes from the median gap between them, and
    `stated_cadence` is whatever a notice said, often nothing. `rhythm_changes` lists
    each point where the observed cadence of a series moved between periods, and the
    per-period cancellation rate shows whether cancellations are rising.
    """
    import statistics

    if by not in ("quarter", "month"):
        raise ValueError(f"invalid period {by!r}: expected 'quarter' or 'month'")
    rows = store().select(Q.render(Q.MEETING_ROWS, filters=_group_filter(group)),
                          limit=MAX_ROWS)

    # One row per series and day: an OPTIONAL with two values would repeat a meeting.
    by_series: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = by_series.setdefault(row["seriesId"], {
            "series": row["series"], "lists": set(), "cadence": set(), "days": {}})
        entry["days"][row["day"]] = (str(row["canceled"]).lower() == "true",
                                     row["evidence"])
        if row.get("list"):
            entry["lists"].add(row["list"])
        if row.get("cadence"):
            entry["cadence"].add(row["cadence"])

    coverage = {r["list"]: r for r in store().select(Q.render(Q.COVERAGE))}
    lists = sorted(set().union(*(e["lists"] for e in by_series.values())))
    windows = [coverage[name] for name in lists if name in coverage]

    def partial(period: str) -> bool:
        start, end = _period_bounds(period)
        return any(start < w["earliest"] or end > w["latest"] for w in windows)

    series_out, totals = [], {}
    evidence_counts: dict[str, int] = {}
    for series_id, entry in sorted(by_series.items()):
        days = sorted(entry["days"])
        held = [d for d in days if not entry["days"][d][0]]
        gaps = {later: _days_between(earlier, later)
                for earlier, later in zip(held, held[1:])}
        periods: dict[str, dict[str, Any]] = {}
        for day in days:
            canceled, evidence = entry["days"][day]
            evidence_counts[evidence] = evidence_counts.get(evidence, 0) + 1
            period = _period_of(day, by)
            slot = periods.setdefault(period, {"announced": 0, "canceled": 0, "gaps": []})
            slot["announced"] += 1
            slot["canceled"] += canceled
            if day in gaps:
                slot["gaps"].append(gaps[day])
            total = totals.setdefault(period, {"announced": 0, "canceled": 0})
            total["announced"] += 1
            total["canceled"] += canceled

        period_rows, changes, previous = [], [], None
        for period, slot in sorted(periods.items()):
            # Two gaps is the least that says anything about a rhythm.
            median = statistics.median(slot["gaps"]) if len(slot["gaps"]) >= 2 else None
            observed = _cadence_label(median)
            period_rows.append({
                "period": period, "announced": slot["announced"],
                "held": slot["announced"] - slot["canceled"],
                "canceled": slot["canceled"], "median_gap_days": median,
                "observed_cadence": observed, "partial_coverage": partial(period)})
            if observed:
                if previous and previous[1] != observed:
                    changes.append({"from_period": previous[0], "to_period": period,
                                    "from": previous[1], "to": observed})
                previous = (period, observed)

        overall = statistics.median(gaps.values()) if len(gaps) >= 2 else None
        series_out.append({
            "series_id": series_id, "series": entry["series"],
            "stated_cadence": sorted(entry["cadence"]),
            "observed_cadence": _cadence_label(overall), "median_gap_days": overall,
            "announced": len(days), "canceled": len(days) - len(held),
            "first_seen": days[0] if days else None,
            "last_seen": days[-1] if days else None,
            "periods": period_rows, "rhythm_changes": changes})

    return {
        "group": group,
        "by": by,
        "coverage": windows,
        "series": series_out,
        "totals_by_period": [
            {"period": period, "announced": t["announced"],
             "held": t["announced"] - t["canceled"], "canceled": t["canceled"],
             "cancel_rate": round(t["canceled"] / t["announced"], 2),
             "partial_coverage": partial(period)}
            for period, t in sorted(totals.items())],
        "date_evidence": evidence_counts,
        "note": "Measured from announced meetings, so counts are what the lists carried, "
                "not totals. A period marked partial_coverage is only partly inside a "
                "list's window, so its low count is not evidence of a slowdown. Dates "
                "with evidence subject-sent-date are the day a notice was sent, which "
                "can shift a gap by a few days. Schedule-change notices are not yet in "
                "the graph, so a change is detected from the dates alone.",
    }


@mcp.tool()
def meeting_records(group: str | None = None, since: str | None = None,
                    until: str | None = None, limit: int = 60) -> dict[str, Any]:
    """Which meetings have a record (minutes, summary or recording), and which do not.

    `group` is a group_id from cosai_overview; a workstream includes its SIGs. `since`
    and `until` are YYYY-MM-DD. Each meeting lists the record pointers attached to it.
    The records themselves are restricted to CoSAI members: this says a record exists
    and where, never what it says. `held_without_record` is every held meeting in range
    with nothing attached.
    """
    filters = " ".join(part for part in (_group_filter(group), _date_filter(since, until))
                       if part)
    rows = store().select(Q.render(Q.MEETING_RECORDS, filters=filters), limit=MAX_ROWS)

    meetings: dict[tuple[str, str], dict[str, Any]] = {}
    lists: set[str] = set()
    for row in rows:
        key = (row["day"], row["series"])
        meeting = meetings.setdefault(key, {
            "day": row["day"], "series": row["series"],
            "canceled": str(row["canceled"]).lower() == "true",
            "date_evidence": row["evidence"], "records": {},
            **({"scheduled_start": row["scheduledStart"],
                "time_zone": row.get("timeZone")} if row.get("scheduledStart") else {})})
        if row.get("list"):
            lists.add(row["list"])
        if row.get("summary"):
            record = meeting["records"].setdefault(row["summary"], {
                "urls": [],
                "access_restricted": str(row.get("restricted")).lower() != "false"})
            if row.get("url") and row["url"] not in record["urls"]:
                record["urls"].append(row["url"])

    ordered = sorted(meetings.values(), key=lambda m: (m["day"], m["series"]), reverse=True)
    for meeting in ordered:
        meeting["records"] = list(meeting["records"].values())
    held = [m for m in ordered if not m["canceled"]]
    missing = [{"day": m["day"], "series": m["series"]} for m in held if not m["records"]]

    unattached_filters = _date_filter(since, until)
    if group:
        allowed = ", ".join(Q.literal(name) for name in sorted(lists)) or '""'
        unattached_filters += f" FILTER(?list IN ({allowed}))"
    unattached = store().select(Q.render(Q.UNATTACHED_RECORDS,
                                         filters=unattached_filters))

    return {
        "group": group,
        "since": since,
        "until": until,
        "held": len(held),
        "with_a_record": len(held) - len(missing),
        "canceled": len(ordered) - len(held),
        "meetings": ordered[:limit],
        "held_without_record": missing[:limit],
        "unattached_records": int(unattached[0]["unattached"]) if unattached else 0,
        "note": "A record is attached only where exactly one meeting of the posting "
                "list's group fell on the record's date; unattached_records counts the "
                "rest, so a held meeting without a record may still have one. Records "
                "are pointers to member-restricted documents. Agendas are not yet in "
                "the graph.",
    }


@mcp.tool()
def approval_record(publication_id: str) -> dict[str, Any]:
    """How a publication was approved: every governance call on it, from list mail.

    Each call gives the deciding body (tsc, pgb), its stage (review-period, ballot,
    call-for-consensus, approval-notice), the work's role in it (new, revision,
    addition, review), and its dates. `approval` summarizes the first approval by each
    body; `revisions` lists later updates, which need only TSC consensus. A call with no
    `closed` date has no closing message in the archive, which is not evidence it failed.
    """
    pid = Q.local_name(publication_id)
    rows = store().select(Q.render(Q.APPROVAL_CALLS, publication=pid))
    parent = store().select(Q.render(Q.ADDITION_TO, publication=pid))
    meta = next((p for p in publications() if p["id"] == pid), None)

    calls: dict[str, dict[str, Any]] = {}
    for row in rows:
        call = calls.setdefault(row["callId"], {
            "call": row["label"], "stage": row["stage"], "role": row["role"],
            "bodies": [], **{k: row[k] for k in ("opened", "deadline", "closed") if row.get(k)},
            **({"restates_tsc_approval": True}
               if str(row.get("restates")).lower() == "true" else {})})
        if row.get("body") and row["body"] not in call["bodies"]:
            call["bodies"].append(row["body"])
    ordered = sorted(calls.values(), key=lambda c: (c.get("opened") or "", c["call"]))

    approval: dict[str, Any] = {}
    for call in ordered:
        if call["role"] != "new" or not call.get("closed"):
            continue
        basis = "notice" if call["stage"] == "approval-notice" else "call closed"
        for body in call["bodies"]:
            if body not in approval or call["closed"] < approval[body]["closed"]:
                approval[body] = {"closed": call["closed"], "basis": basis,
                                  **({"deadline": call["deadline"]}
                                     if call.get("deadline") else {})}
    if "tsc" not in approval and any(c.get("restates_tsc_approval") for c in ordered):
        pgb_call = next(c for c in ordered if c.get("restates_tsc_approval"))
        approval["tsc"] = {"closed": f"before {pgb_call.get('opened')}",
                           "basis": "stated in the PGB call"}

    exceptions = load_registry("approvals").get("no_archive_evidence") or {}
    return {
        "publication_id": pid,
        "title": meta["title"] if meta else None,
        "registry_status": meta["approval_status"] if meta else None,
        "original_date": str(meta["original_date"]) if meta and meta.get("original_date") else None,
        "approval": approval,
        "revisions": [c for c in ordered if c["role"] == "revision"],
        **(_addition_summary(parent[0]["parent"], ordered) if parent else {}),
        **({"recorded_exception": exceptions[pid]} if pid in exceptions else {}),
        "calls": ordered,
        "note": "From governance mail: a TSC call or ballot, then a PGB call; the PGB "
                "close is the authoritative approval. A deadline is when consent took "
                "effect; the close is the message reporting it. An addition takes its "
                "standing from the work it is added to. original_date is the document's "
                "own date, which often matches the PGB deadline.",
    }


def _addition_summary(parent: str, calls: list[dict[str, Any]]) -> dict[str, Any]:
    """An addition's standing: the call that added it, and the approval of the work it
    was added to, which is where its standing comes from."""
    added = next((c for c in calls if c["role"] == "addition" and c.get("closed")), None)
    return {"addition_to": parent,
            "approved_as_addition": {
                **({"closed": added["closed"], "bodies": added["bodies"],
                    **({"deadline": added["deadline"]} if added.get("deadline") else {})}
                   if added else {"closed": None}),
                "parent_approval": approval_record(parent)["approval"]}}


def _datetime_filter(until: str | None) -> str:
    """Bound ?start by a day, inclusive. Parsed first, so only an ISO date reaches SPARQL."""
    from datetime import date
    if not until:
        return ""
    try:
        day = date.fromisoformat(until).isoformat()
    except ValueError:
        raise ValueError(f"invalid date {until!r}: expected YYYY-MM-DD") from None
    return f'FILTER(?start <= "{day}T23:59:59+00:00"^^xsd:dateTime)'


@mcp.tool()
def upcoming_meetings(group: str | None = None, until: str | None = None,
                      limit: int = 40) -> dict[str, Any]:
    """Meetings scheduled for a future date, soonest first, from the CoSAI calendar.

    `group` is a group_id from cosai_overview (`ws2`, `tsc`, or a SIG id); a workstream
    includes its SIGs. `until` is YYYY-MM-DD. Times are UTC with the time zone each
    meeting was scheduled in. These are calendar entries, not meetings held: "future"
    is judged from the day the calendar was read, which `calendar_read` gives, and an
    entry may since have moved or been canceled.
    """
    filters = " ".join(part for part in (_group_filter(group), _datetime_filter(until))
                       if part)
    rows = store().select(Q.render(Q.UPCOMING_MEETINGS, filters=filters), limit=limit)
    window = store().select(Q.render(Q.SOURCE_WINDOW,
                                     window_class="CalendarCoverageWindow"))
    meetings = [{"name": r["label"].rsplit(", scheduled ", 1)[0], "start": r["start"],
                 **({"end": r["end"]} if r.get("end") else {}),
                 **({"time_zone": r["timeZone"]} if r.get("timeZone") else {}),
                 **({"series": r["series"], "series_id": r["seriesId"]}
                    if r.get("seriesId") else {})} for r in rows]
    return {
        "group": group,
        "until": until,
        "calendar_read": window[0]["fetched"] if window else None,
        "meetings": meetings,
        "note": "Entries on the CoSAI meeting calendar (the cosai-op group's) for a "
                "later day than it was read. Scheduled, not held, and not evidence a "
                "meeting will happen. A group filter keeps only entries whose series "
                "the registry knows.",
    }


def _title_key(text: str) -> str:
    """A title folded for matching: typographic quotes, case and punctuation dropped."""
    import re as _re
    return _re.sub(r"[^a-z0-9]+", " ", text.lower().replace("\u2019", "'")).strip()


@mcp.tool()
def what_announced_this(publication_id: str) -> dict[str, Any]:
    """The CoSAI website posts that link a publication: blog posts, press releases and
    other items, oldest first, with the TSC approval of each blog post where one exists.

    A post links the work by one of its registered addresses (the repository file, the
    PDF, or the website's copy). No author is given for any post: the site's feed names
    only the account that posted it, and no rule yet establishes a post's authorship.
    """
    pid = Q.local_name(publication_id)
    posts = store().select(Q.render(Q.POSTS_LINKING, publication=pid))
    blog_calls = store().select(Q.render(Q.BLOG_CALLS))
    window = store().select(Q.render(Q.SOURCE_WINDOW, window_class="FeedCoverageWindow"))
    meta = next((p for p in publications() if p["id"] == pid), None)

    approvals = [(_title_key(c["title"].split(" (", 1)[0]), c) for c in blog_calls]
    out = []
    for post in posts:
        categories = [c for c in (post.get("categories") or "").split("|") if c]
        entry = {"title": post["title"], "published": post["published"],
                 "url": post["url"], "categories": categories}
        key = _title_key(post["title"])
        match = next((c for k, c in approvals if k and key.startswith(k)), None)
        if match:
            entry["tsc_approval"] = {k: match[k] for k in ("opened", "deadline", "closed")
                                     if match.get(k)}
        out.append(entry)
    return {
        "publication_id": pid,
        "title": meta["title"] if meta else None,
        "feed_fetched": window[0]["fetched"] if window else None,
        "posts": out,
        "note": "From one fetch of the coalitionforsecureai.org feed; a post published "
                "after it is not here. Posts carry the site's categories and no author. "
                "tsc_approval is the TSC call for consensus on that blog post.",
    }


@mcp.tool()
def governance_timeline(limit: int = 40) -> dict[str, Any]:
    """Review periods, calls for consensus, votes and approvals, most recent first.

    This is how a publication reached its approval status, which list_publications
    reports only as a bare string.
    """
    rows = store().select(Q.render(Q.GOVERNANCE_TIMELINE), limit=limit)
    return {
        "count": len(rows),
        "events": rows,
        "note": "Subjects are verbatim from the announcing mail. The mail records that "
                "a step happened and when, not its outcome; a decision's result is in "
                "the meeting minutes, which this graph does not yet hold.",
    }


# Worked queries for the sparql escape hatch.
#
# Added because a model given only class and property *names* invents the wiring. In
# one observed session, seventeen sparql calls went into answering one question: eight
# were schema discovery ("what properties exist", "show me twenty triples") and eight
# used predicates that do not exist -- cco:contributedBy, cco:hasPerson, cco:Publication
# -- which return zero rows rather than an error, so the model could as easily have
# reported "no data" as noticed its mistake.
#
# Naming the traversals removes the guessing. Each is a real query that returns rows.
EXAMPLE_QUERIES = {
    "credit path -- who is credited on a publication, and as what": """
        SELECT ?person ?role ?publication WHERE {
          ?credit a ?roleClass ;
                  obo:BFO_0000197 ?p ;          # inheres in: the role's bearer
                  cosaic:onPublication ?pub .
          ?p rdfs:label ?person . ?pub rdfs:label ?publication .
          BIND(REPLACE(STR(?roleClass), "^.*#", "") AS ?role)
          FILTER(?roleClass != cosaic:CreditedRole)
        } LIMIT 10""",
    "rank contributors by publications, excluding a set of roles": """
        SELECT ?person (COUNT(DISTINCT ?pub) AS ?publications) WHERE {
          ?credit a ?roleClass ; obo:BFO_0000197 ?p ; cosaic:onPublication ?pub .
          ?p rdfs:label ?person .
          FILTER(?roleClass NOT IN (cosaic:CreditedRole, cosaic:TSCCoChairRole,
                                    cosaic:TSCReviewerRole))
        } GROUP BY ?person ORDER BY DESC(?publications) LIMIT 10""",
    "affiliation path -- attested ranges, never a current employer": """
        SELECT ?person ?organization ?earliest ?latest ?boundsKnown WHERE {
          ?role a cosaic:AffiliationRole ;
                obo:BFO_0000197 ?p ;
                cosaic:withOrganization ?org ;
                obo:BFO_0000199 ?interval .        # occupies temporal region
          ?p rdfs:label ?person . ?org rdfs:label ?organization .
          ?interval cosaic:earliestEvidence ?earliest ;
                    cosaic:latestEvidence ?latest ;
                    cosaic:boundsKnown ?boundsKnown .
        } LIMIT 10""",
    "meeting path -- occurrences of a series, cancellations marked": """
        SELECT ?day ?series ?canceled WHERE {
          ?m a cosaic:Meeting ;
             cosaic:inSeries ?sr ;
             cosaic:canceled ?canceled ;
             obo:BFO_0000199 ?i .
          ?i cosaic:date ?day . ?sr rdfs:label ?series .
        } ORDER BY DESC(?day) LIMIT 10""",
    "citation path -- what cited a work": """
        SELECT ?citing ?category ?verification WHERE {
          ?event a cosaic:CitationEvent ;
                 cosaic:citedWork ?work ;
                 cosaic:citingPublication ?ext .
          ?ext rdfs:label ?citing .
          OPTIONAL { ?event cosaic:category ?category }
          OPTIONAL { ?event cosaic:verification ?verification }
        } LIMIT 10""",
    "provenance -- which partition a fact came from": """
        SELECT ?graph (COUNT(*) AS ?quads) WHERE {
          GRAPH ?graph { ?s ?p ?o }
        } GROUP BY ?graph""",
}


def _named_graphs() -> dict[str, Any]:
    """Provenance partitions, with what each one is and how far it can be trusted.

    Queries run against the union of these, so a caller never has to name a graph --
    but it must be able to find out where an answer came from, because the partitions
    do not carry equal weight. The maillist graph in particular covers only the window
    its fetched archives cover.
    """
    described = {
        "publications": "Credited contribution from 12 whitepapers, deterministic from "
                        "registry/*.yaml and documents pinned by commit sha.",
        "citations": "The CoSAI TSC citation-impact dataset. Refreshed weekly upstream, "
                     "so counts drift and are a floor on real uptake.",
        "maillist": "From list mail: meeting series, occurrences, and governance "
                    "calls with curated links to the works each seeks approval of. "
                    "Coverage is partial -- query cosaic:CoverageWindow first; outside "
                    "it, no meeting or call is not evidence of none. Carries no "
                    "attendance.",
        "website": "Posts on coalitionforsecureai.org from its RSS feed: blog posts, "
                   "press releases and other items, with exact publication times and "
                   "links to CoSAI works. One fetch -- query cosaic:FeedCoverageWindow "
                   "for its fetch date. Credits no author: the feed names only the "
                   "posting account.",
        "calendar": "Entries from the CoSAI meeting calendar (groups.io, cosai-op): "
                    "cosaic:ScheduledMeeting, with cosaic:PlannedMeeting for a future "
                    "date. An entry is not a meeting and not evidence one was held; "
                    "cosaic:correspondsTo gives the mail's meeting for the same series "
                    "and day. Nothing before 2026. Keeps no organizer.",
        "ontology": "The TBox: cosaic: terms plus the MIREOT'd CCO/BFO subset.",
    }
    try:
        counts = store().named_graphs()
    except Exception:                       # introspection must never break the tool
        counts = {}
    return {
        name: {"quads": count, "about": described.get(name.rsplit("/", 1)[-1], "")}
        for name, count in sorted(counts.items())
    }


@mcp.tool()
def graph_schema() -> dict[str, Any]:
    """The vocabulary: classes, properties, and the conventions that matter.

    Read this before writing SPARQL. It also states the two data conventions a caller
    must respect when reporting results.
    """
    roles = load_registry("role-vocabulary")["roles"]
    return {
        "namespaces": {
            "cosaic": "https://cosai-oasis.github.io/ontology/cosai-contrib#",
            "cco": "https://www.commoncoreontologies.org/",
            "obo": "http://purl.obolibrary.org/obo/",
        },
        "grounding": "BFO 2020 via a MIREOT subset of Common Core Ontologies v2.2. "
                     "CCO uses opaque numeric IRIs; every term carries an rdfs:label.",
        "named_graphs": _named_graphs(),
        "continuants": ["Person", "Organization", "Workstream", "GoverningBody", "Committee",
                        "SpecialInterestGroup",
                        "Publication", "Manifestation", "EmailAddress", "PersonName",
                        "ProperName", "AbbreviatedName", "ExternalPublication",
                        "CoSAIWorkStub", "MeetingSeries", "MeetingSummary",
                        "WebsitePost", "BlogPost", "PressRelease",
                        "ScheduledMeeting", "PlannedMeeting"],
        "roles": ["AffiliationRole", "CreditedRole", *sorted(ROLE_CLASSES),
                  "GitHubContributorRole"],
        "roles_unused": {
            "AttendanceRole": "Reserved and empty. No attendee data exists in any "
                              "source, so attendance is unknown, not absent. Kept "
                              "distinct from CreditedRole so it can never be reported "
                              "as authorship.",
        },
        "occurrents": ["PublicationEvent", "RevisionEvent", "AffiliationGain",
                       "AffiliationLoss", "CitationEvent", "Meeting",
                       "MeetingCancellation", "GovernanceEvent", "GovernanceCall"],
        "temporal": ["Instant", "EvidenceInterval", "UncertaintyWindow",
                     "CoverageWindow", "FeedCoverageWindow", "CalendarCoverageWindow"],
        "key_relations": {
            "obo:BFO_0000197": "inheres in — a role to its bearer",
            "obo:BFO_0000199": "occupies temporal region",
            "obo:BFO_0000057": "has participant — an event to a participant",
            "obo:BFO_0000101": "is carrier of — a file to the work it carries",
            "cco:ont00001916": "designates — a name or address to a person",
            "cosaic:onPublication": "a credited role to its publication",
            "cosaic:withOrganization": "an affiliation role to its organization",
            "cosaic:assertedAt": "the instant a claim is evidence about",
            "cosaic:inSeries": "a meeting to its meeting series",
            "cosaic:convenedBy": "a meeting series to the workstream, governing body, "
                                 "committee or SIG whose series it is",
            "obo:BFO_0000050": "part of — a SIG to the workstream it met under",
            "cosaic:succeededBy": "a group to the group that continues its work",
            "cosaic:activityStatus": "a curator's statement that a group is inactive, "
                                     "dated by cosaic:statusAsOf",
            "cosaic:linksTo": "a website post to a CoSAI work its body links to -- a "
                              "link, not authorship and not an announcement claim",
            "cosaic:scheduleOf": "a calendar entry to the meeting series it schedules",
            "cosaic:partOfCall": "a governance message to the call it belongs to",
            "cosaic:callsToApprove": "a call to a work it seeks approval of; use a "
                                     "subproperty (New, Revision, Addition) for the "
                                     "role, and cosaic:closedOn for the outcome",
            "cosaic:decidedBy": "a call to the governing body (gov-tsc, gov-pgb) "
                                "whose decision it is",
            "cosaic:correspondsTo": "a past calendar entry to the meeting the mail "
                                    "records for the same series and UTC day",
        },
        "example_queries": EXAMPLE_QUERIES,
        "writing_sparql": [
            "Copy a traversal from example_queries rather than inferring one; a "
            "predicate that does not exist returns zero rows, not an error.",
            "A credit is a reified role node, not an edge: it bears obo:BFO_0000197 "
            "to the person and cosaic:onPublication to the publication. There is no "
            "direct person-to-publication property.",
            "Filter out cosaic:CreditedRole when counting roles; it is the parent "
            "class and would double every credit.",
            "SERVICE and LOAD are refused. Queries run against the union of the "
            "named graphs, so no GRAPH clause is needed unless provenance is the "
            "question.",
        ],
        "credit_source_labels": sorted(roles),
        "conventions": [
            "Affiliation intervals carry earliestEvidence/latestEvidence and "
            "boundsKnown false. Never read an evidence date as a start or end date.",
            "Inferred events carry inferred true and an UncertaintyWindow with "
            "notBefore/notAfter rather than a date.",
            "Credits carried across a revision are dated to the ORIGINAL publication. "
            "MCP Security was revised 2026-08-12 without refreshing its credit list, "
            "so its credits are evidence about 2026-01-08.",
            "Every publication carries approvalStatus; three documents are drafts.",
            "A group's activityStatus is stated by a curator, never inferred. A group "
            "without one may still have stopped meeting; a quiet period in the mail "
            "is not evidence either way.",
        ],
        "ontology_files": [str(p.relative_to(ONTOLOGY.parent))
                           for p in (ONTOLOGY / "cosai-contrib.ttl",
                                     ONTOLOGY / "alignments" / "cco.ttl",
                                     ONTOLOGY / "alignments" / "bridges.ttl")],
    }


@mcp.resource("cosai://ontology/cosai-contrib.ttl")
def ontology_tbox() -> str:
    """The contribution ontology TBox."""
    return (ONTOLOGY / "cosai-contrib.ttl").read_text(encoding="utf-8")


@mcp.resource("cosai://registry/publications.yaml")
def publications_registry() -> str:
    """The curated publication registry, including pinned commit shas."""
    from .paths import REGISTRY
    return (REGISTRY / "publications.yaml").read_text(encoding="utf-8")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
