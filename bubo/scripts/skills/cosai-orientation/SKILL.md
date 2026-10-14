---
name: cosai-orientation
description: Orient someone to CoSAI — what the coalition is working on now, which workstream or SIG to join and how, when a group working on a given topic meets, how often groups meet and which have been canceling, whether a group is still active or has moved, and how a publication gets approved. Use for newcomer and practitioner questions about groups, meetings, cadence, joining, and governance process. Triggers on "what is CoSAI doing", "how do I get involved", "which group should I join", "when are the meetings", "how often does X meet", "what mailing list", "is there a SIG for", "is X still active", "what happened to", "how does a paper get approved", "meeting schedule", "attendance".
---

# Orienting someone to CoSAI

The `bubo` MCP server holds CoSAI's groups, meeting rhythm and governance
activity alongside its publications. This skill answers questions whose unit is a
**group someone can act on** — a workstream or SIG they can join — rather than a person
or a document.

Groups come in four kinds, and `cosai_overview` returns them in four lists:

- **Workstreams** (WS1 to WS4) do the technical work and produce the publications.
- **Governing bodies**, the TSC and the PGB, approve work and publish nothing.
- **Committees**, currently the Marketing Committee, do project work that is neither
  technical nor governance. Its content and events subcommittees are its own meetings,
  not separate groups.
- **SIGs** run under a workstream, and `part_of` names it.

Start with `cosai_overview`. It returns the groups, their rhythm, recent publications,
recent governance, corpus scale, and the coverage window that bounds every meeting
figure. Read its `not_yet_answerable` field before answering anything about attendance
or what was said at a meeting.

## Tools

| Need | Tool |
| --- | --- |
| What is CoSAI doing | `cosai_overview` |
| Which group to join, and how | `how_to_get_involved` |
| Meetings on a topic | `find_meetings` |
| What a group actually met on | `meeting_timeline` |
| How often a group meets, and whether that changed | `meeting_rhythm` |
| Which meetings have minutes or a recording | `meeting_records` |
| When a group meets next | `upcoming_meetings` |
| Approvals, ballots, review periods | `governance_timeline` |
| How one paper was approved | `approval_record` |
| Blog posts and press releases about a paper | `what_announced_this` |
| Papers themselves | `list_publications` |

## The coverage rule — the one thing to get right

Meeting data comes from list archives, each covering a **limited window**, reported per
list in `meeting_coverage`. Inside it, a missing meeting means one was not announced.
Outside it, nothing is asserted either way.

- Good: "Within the covered window (18 Oct 2024 – 23 Sep 2026), WS1 announced 60
  meetings and canceled 20."
- Wrong: "WS1 met 60 times." / "WS2 did not meet in July 2024."

Counts are what was *seen*, never totals. Say so once, plainly, and do not repeat the
caveat in every sentence.

## The forward schedule

`upcoming_meetings` reads the CoSAI meeting calendar: entries scheduled for a later day
than the calendar was read, which `calendar_read` gives. Each is a scheduled meeting,
not a held one, and the calendar may since have moved or dropped it.

- Good: "The CoSAI calendar, read 26 Sep 2026, schedules the next WS4 weekly meeting
  for 1 Oct at 12:00 New York time."
- Wrong: "WS4 meets on 1 Oct." / "WS4 met on 1 Oct."

The calendar holds nothing before 2026, and a group filter keeps only entries whose
series the registry knows. Where a group has no upcoming entry, answer with its cadence
and when it last met, and do not extrapolate a date from an RRULE: `cadence` gives the
rhythm, not the next date.

A group with **no cadence** is one whose schedule was never stated in a calendar
notice. That is not a group that meets irregularly, and it is certainly not a group
that does not meet. Several groups with no cadence are among the most active.
`meeting_rhythm` measures the cadence from the dates of held meetings instead; report
it as observed ("met about every two weeks in 2026-Q2"), not as a schedule, and say when
a period is marked `partial_coverage`.

## Attendance is not available

No source in this graph names attendees. Asked who attended, or for an attendance rate
by sponsor or by workstream representative, say it is not available and why, and say
where it will come from: TSC and PGB meeting minutes are committed markdown in public
GitHub and do carry `Present:`, `Regrets:` and `Guests:`, and ingesting them is planned
work.

Never infer attendance from a meeting count, from a person's credited role, or from the
fact that a meeting happened. "Not asserted" is the answer, never "nobody attended".

## Discussion and decisions are not held

A meeting's record is stored as a pointer, and most are access-restricted to CoSAI
members — verified by fetch, not assumed. So `meeting_timeline` and `meeting_records`
can say a record exists and whether it is readable, but not what it says. A held meeting
with no record attached may still have one: `meeting_records` reports how many records
could not be attached, so say that rather than "no minutes were taken".

`governance_timeline` records that a step happened and when (a review period opened, a
ballot ran, a paper was approved), taken verbatim from announcement subjects.
`approval_record` gives one paper's calls: the deciding body, the objection deadline,
and the date a closing message reported no objections. Consent takes effect at the
deadline; the close reports it. A call with no close in the archive has no closing
message there, which is not evidence it failed, and a recorded exception says where the
archive lacks a vote.

## Date evidence

Every meeting carries how its date was established. Surface it when precision matters:

| `dateEvidence` | Means |
| --- | --- |
| `"ics"` | Exact start and end from a calendar attachment |
| `"subject"` | A date in the announcement's subject line |
| `"subject-sent-date"` | Only the day the notice was sent — weaker; not a scheduled start |

## Status and succession

Two facts about a group come from a curator, not from mail, and the tools say so:

- **`status`** is "inactive" only where a person has stated it, with `status_as_of`
  giving the date. Report both: "inactive, as stated on 2026-09-24; it last met on
  2026-06-18". Otherwise it reads "no status stated".
- **`succeeded_by`** names the group that continues this one's work, and the successor
  carries **`continues`** pointing back. The WS2 Shared Responsibility Model SIG moved
  to WS3 as the SRF & GRC SIG. Asked about the old group, say where its work went and
  point the person to the successor's list. Keep the two apart in counts and dates:
  each is part of the workstream it met under.

**Never infer a status from a quiet period.** A group whose last meeting was a year ago
and that carries no stated status may have ended, moved, or only stopped announcing:
the WS2 Telemetry SIG sent no calendar notice from March to August 2026 and kept
meeting, as its summaries show. Say when it last met, say no status is stated, and
suggest asking on its list. Never call it inactive.

## Joining

`how_to_get_involved` returns each group's mailing list and a `subscribe` link. Those
links are **derived** from the list identifier, so offer them as the likely address and
suggest confirming, rather than asserting them. A group's list is the one it announces
on. `cosai-op` is the project-wide list, which carries cross-posted notices for every
group, and is never a group's own list.

Joining a workstream or SIG means subscribing to its list and attending the meeting.
The TSC and PGB are governing bodies: their lists show what is being approved, and
taking part in the technical work means a workstream. How their seats are filled is
not recorded here, so do not describe it.
Before recommending a group, check its `status` and `succeeded_by`: send someone to an
inactive group's topic elsewhere, and to a moved group's successor.

## Hand off rather than guess

- Who wrote, edited, reviewed or is credited on anything → the contribution skill.
- Who has cited CoSAI, and how widely → the citation skill.
- **Who leads a group** is neither. Credited roles on a workstream's papers are not the
  same as leading it, and governance roles live in the minutes this graph does not yet
  hold. Answer the meeting half, then say the leadership half is not recorded here —
  do not offer a paper's editor as a group's lead.
