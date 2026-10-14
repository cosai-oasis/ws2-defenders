# Changelog: CoSAI Contribution Ontology (`cosaic:`)

Versions follow SemVer as ADR-WS2-001 D14 reads it for OWL/RDF. While the version is
`0.y.z`, a MINOR release may break compatibility, as SemVer allows before `1.0.0`.

## 0.6.1 — 2026-09-26

**Fixed**

- `canceled` has one value per meeting: whether a `MeetingCancellation` cancels it. A
  meeting announced by one notice and called off by another carried both `true` and
  `false`. The cancellation stays its own event, and the meeting shape requires exactly
  one value.

## 0.6.0 — 2026-09-26

**Added**

- `linksToUnregistered`: a CoSAI-hosted file a website post links to that matches no
  registered work, the evidence the publication candidate seed is derived from.

## 0.5.0 — 2026-09-26

**Added**

- Approval links: `GovernanceCall`, one call as a whole, with `partOfCall` from each
  message's `GovernanceEvent`. Properties `decidedBy`, `callStage`, `subjectMatter`,
  `openedOn`, `objectionDeadline`, `closedOn`, `restatesTscApproval`, `callsToApprove`
  with `callsToApproveNew`, `callsToApproveRevision` and `callsToApproveAddition`,
  `callsToReview`, `isAdditionTo` and `concernsTitle`.

**Changed**

- The named graph built from list mail is `graph/maillist`, which holds meetings and
  governance calls. The file is `ontology/maillist.ttl` and its shape
  `MaillistGraphShape`.

## 0.4.0 — 2026-09-26

**Added**

- The calendar layer, built from the groups.io calendar of `cosai-op`:
  `ScheduledMeeting`, a calendar entry and so a prescriptive information entity, not a
  process; `PlannedMeeting`, a scheduled meeting whose start falls on a later day than the
  calendar was read; and `CalendarCoverageWindow`. Properties `scheduleOf`, `correspondsTo`,
  `scheduledStart`, `scheduledEnd`, `scheduledTimeZone`, `sourceEventId`,
  `sourceCalendar`, `rangeStart` and `rangeEnd`.

**Changed**

- `earliestItem`, `latestItem` and `fetchedOn` apply to any `CoverageWindow`, not only
  a feed window, so a calendar window uses them too.

**Fixed**

- `startsAt` and `endsAt`, used by the meetings build since 0.2.0, are now declared.

## 0.3.0 — 2026-09-26

**Added**

- The website layer, built from the coalitionforsecureai.org RSS feed: `WebsitePost`,
  with `BlogPost` and `PressRelease` from the site's own categories, and
  `FeedCoverageWindow`, a `CoverageWindow` for one fetch of a feed. Properties
  `linksTo`, `sourceFeed`, `sourcePostId`, `siteCategory`, `publishedAt`,
  `earliestItem`, `latestItem` and `fetchedOn`.
- No authorship is credited for a post: `dc:creator` names the posting account, not an
  author, and no rule yet says how a post's authorship is established.

**Changed**

- The requirement for `earliestMessage` and `latestMessage` now applies to mail
  coverage windows only (those with a `sourceList`), so a feed window carries its own
  bounds instead. Every coverage window still states `boundsKnown false`.

## 0.2.0 — 2026-09-24

**Breaking**

- `cosaic:summarisedBy` renamed to `cosaic:summarizedBy`, and `cosaic:cancelled` to
  `cosaic:canceled`, for American English. The old IRIs no longer resolve.

**Added**

- The meetings layer: `MeetingSeries`, `Meeting`, `MeetingCancellation`,
  `MeetingSummary`, `SpecialInterestGroup`, `GovernanceEvent`, `CoverageWindow`, and the
  reserved `AttendanceRole`, with `inSeries`, `convenedBy`, `summarizedBy`,
  `announcedOn`, `cancels`, `coverage`, `cadence`, `icsUid`, `seriesNameVariant`,
  `canceled`, `accessRestricted`, `dateEvidence`, `sourceMessageId`, `sourceList`,
  `earliestMessage` and `latestMessage`.
- `GoverningBody`, for the TSC and PGB.
- `Committee`, for the Marketing Committee.
- `activityStatus` and `statusAsOf`, a curator's dated statement that a group is
  inactive, and `succeededBy`, from a group to the group that continues its work.

## 0.1.0 — 2026-09-12

The contribution graph: people, organizations, workstreams, publications and their
manifestations, credited and affiliation roles, publication and revision events,
affiliation change events with uncertainty windows, and citations.
