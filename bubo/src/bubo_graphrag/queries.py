"""Parameterised queries behind the MCP tools.

Kept in Python rather than read from queries/*.rq because these take arguments and
values must be bound safely. The .rq files are the standalone, copy-pasteable library
for anyone querying the store directly.

Two conventions run through all of them:

  * Affiliation is reported with its evidence dates and `boundsKnown`, never as a bare
    current employer. A caller that wants "where does X work" gets "X was credited under
    Y between these attested dates", which is what the data supports.
  * `approvalStatus` travels with every publication row, so a draft's credits cannot be
    presented as approved ones without the caller seeing it.
"""

from __future__ import annotations

import re


def render(template: str, **params: str) -> str:
    """Resolve a query template.

    Every template must go through here, including those with no parameters: the
    templates use doubled braces to escape SPARQL's own `{}`, so passing one to the
    store without formatting leaves literal `{{` in the query. Two tools did exactly
    that while the tests formatted everything, so the bug was invisible until the
    server ran. One entry point removes the possibility.
    """
    return template.format(**params)


def literal(value: str) -> str:
    """Escape a string for use as a SPARQL literal."""
    escaped = (value.replace("\\", "\\\\")
                    .replace('"', '\\"')
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t"))
    return f'"{escaped}"'


def local_name(value: str) -> str:
    """Validate an identifier used to build a cosaic: IRI.

    Ids come from the registries and are slugs, so anything outside this character set
    is a bug or an injection attempt; either way it should not reach the query.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", value):
        raise ValueError(
            f"invalid identifier {value!r}: expected letters, digits, hyphen, underscore")
    return value


FIND_PERSON = """
SELECT DISTINCT ?person ?label ?matchedName ?credits WHERE {{
  ?name a/rdfs:subClassOf* cosaic:PersonName ;
        cosaic:nameValue ?matchedName ;
        cco:ont00001916 ?p .
  ?p rdfs:label ?label .
  BIND(REPLACE(STR(?p), "^.*#person-", "") AS ?person)
  FILTER(CONTAINS(LCASE(?matchedName), LCASE({needle})))
  {{
    SELECT ?p (COUNT(?c) AS ?credits) WHERE {{
      ?c obo:BFO_0000197 ?p ; cosaic:onPublication ?any .
    }} GROUP BY ?p
  }}
}} ORDER BY DESC(?credits) ?label
"""

FIND_PERSON_BY_ADDRESS = """
SELECT DISTINCT ?person ?label ?address WHERE {{
  ?a a cosaic:EmailAddress ; cosaic:addressValue ?address ; cco:ont00001916 ?p .
  ?p rdfs:label ?label .
  BIND(REPLACE(STR(?p), "^.*#person-", "") AS ?person)
  FILTER(CONTAINS(LCASE(?address), LCASE({needle})))
}} ORDER BY ?label
"""

PERSON_CREDITS = """
SELECT ?publication ?pubId ?role ?sourceLabel ?date ?status ?statedOrg ?equalContribution ?scopeNote
WHERE {{
  ?c obo:BFO_0000197 cosaic:person-{person} ;
     a ?roleClass ;
     cosaic:onPublication ?pub ;
     cosaic:sourceLabel ?sourceLabel .
  ?pub rdfs:label ?publication ; cosaic:approvalStatus ?status .
  BIND(REPLACE(STR(?pub), "^.*#pub-", "") AS ?pubId)
  BIND(REPLACE(STR(?roleClass), "^.*#", "") AS ?role)
  OPTIONAL {{ ?c cosaic:assertedAt ?i . ?i cosaic:date ?date }}
  OPTIONAL {{ ?c cosaic:statedOrganization ?statedOrg }}
  OPTIONAL {{ ?c cosaic:equalContribution ?equalContribution }}
  OPTIONAL {{ ?c cosaic:scopeNote ?scopeNote }}
  FILTER(?roleClass != cosaic:CreditedRole)
}} ORDER BY ?date ?role
"""

PERSON_AFFILIATION = """
SELECT ?organization ?earliest ?latest ?boundsKnown ?independent WHERE {{
  ?r a cosaic:AffiliationRole ;
     obo:BFO_0000197 cosaic:person-{person} ;
     obo:BFO_0000199 ?i .
  ?i cosaic:earliestEvidence ?earliest ;
     cosaic:latestEvidence ?latest ;
     cosaic:boundsKnown ?boundsKnown .
  OPTIONAL {{ ?r cosaic:withOrganization ?o . ?o rdfs:label ?organization }}
  OPTIONAL {{ ?r cosaic:creditedWithoutEmployer ?independent }}
}} ORDER BY ?earliest
"""

PERSON_AFFILIATION_CHANGES = """
SELECT ?kind ?label ?notBefore ?notAfter ?inferred WHERE {{
  ?e a ?t ; obo:BFO_0000057 cosaic:person-{person} ;
     rdfs:label ?label ; cosaic:inferred ?inferred ;
     obo:BFO_0000199 ?w .
  ?w cosaic:notBefore ?notBefore ; cosaic:notAfter ?notAfter .
  VALUES ?t {{ cosaic:AffiliationLoss cosaic:AffiliationGain }}
  BIND(REPLACE(STR(?t), "^.*#", "") AS ?kind)
}} ORDER BY ?notBefore
"""

PERSON_ADDRESSES = """
SELECT DISTINCT ?address ?impliesOrganization WHERE {{
  ?a a cosaic:EmailAddress ; cosaic:addressValue ?address ;
     cco:ont00001916 cosaic:person-{person} .
  OPTIONAL {{ ?a cosaic:impliesOrganization ?o . ?o rdfs:label ?impliesOrganization }}
}} ORDER BY ?address
"""

PUBLICATION_CREDITS = """
SELECT ?person ?personId ?role ?sourceLabel ?statedOrg ?equalContribution ?scopeNote ?githubLogin
WHERE {{
  ?c cosaic:onPublication cosaic:pub-{publication} ;
     a ?roleClass ; cosaic:sourceLabel ?sourceLabel .
  OPTIONAL {{
    ?c obo:BFO_0000197 ?p . ?p rdfs:label ?person .
    BIND(REPLACE(STR(?p), "^.*#person-", "") AS ?personId)
  }}
  OPTIONAL {{ ?c cosaic:statedOrganization ?statedOrg }}
  OPTIONAL {{ ?c cosaic:equalContribution ?equalContribution }}
  OPTIONAL {{ ?c cosaic:scopeNote ?scopeNote }}
  OPTIONAL {{ ?c cosaic:githubLogin ?githubLogin }}
  BIND(REPLACE(STR(?roleClass), "^.*#", "") AS ?role)
  FILTER(?roleClass != cosaic:CreditedRole)
}} ORDER BY ?role ?person
"""

# The credit count is aggregated in the outer query over a plain OPTIONAL, not in a
# sub-select. A sub-select of the form `OPTIONAL { ?c cosaic:onPublication ?pub }` ahead
# of the type pattern is not a left join, and it silently dropped the two documents with
# no credit section -- the MCP/PQC addendum and the Telemetry RFC -- from the listing.
LIST_PUBLICATIONS = """
SELECT ?id ?title ?workstream ?status ?date ?revised ?version (COUNT(?c) AS ?creditCount)
WHERE {{
  ?pub a cosaic:Publication ; rdfs:label ?title ; cosaic:approvalStatus ?status .
  BIND(REPLACE(STR(?pub), "^.*#pub-", "") AS ?id)
  OPTIONAL {{ ?pub cosaic:producedBy ?ws . ?ws rdfs:label ?workstream }}
  OPTIONAL {{ ?pub cosaic:version ?version }}
  OPTIONAL {{
    ?e a cosaic:PublicationEvent ; obo:BFO_0000057 ?pub ; obo:BFO_0000199 ?i .
    ?i cosaic:date ?date
  }}
  OPTIONAL {{
    ?rev a cosaic:RevisionEvent ; obo:BFO_0000057 ?pub ; obo:BFO_0000199 ?ri .
    ?ri cosaic:date ?revised
  }}
  OPTIONAL {{ ?c cosaic:onPublication ?pub }}
  {filters}
}}
GROUP BY ?id ?title ?workstream ?status ?date ?revised ?version
ORDER BY ?date
"""

ORG_CONTRIBUTIONS = """
SELECT ?person ?personId ?publication ?role ?date WHERE {{
  ?c a ?roleClass ; cosaic:onPublication ?pub ; obo:BFO_0000197 ?p .
  ?p rdfs:label ?person .
  ?pub rdfs:label ?publication .
  ?r a cosaic:AffiliationRole ; obo:BFO_0000197 ?p ;
     cosaic:withOrganization cosaic:org-{organization} .
  BIND(REPLACE(STR(?p), "^.*#person-", "") AS ?personId)
  BIND(REPLACE(STR(?roleClass), "^.*#", "") AS ?role)
  OPTIONAL {{ ?c cosaic:assertedAt ?i . ?i cosaic:date ?date }}
  FILTER(?roleClass != cosaic:CreditedRole)
}} ORDER BY ?person ?date
"""

LIST_ORGANIZATIONS = """
SELECT ?id ?name (COUNT(DISTINCT ?p) AS ?people) WHERE {{
  ?org a cosaic:Organization ; rdfs:label ?name .
  BIND(REPLACE(STR(?org), "^.*#org-", "") AS ?id)
  OPTIONAL {{
    ?r a cosaic:AffiliationRole ; cosaic:withOrganization ?org ; obo:BFO_0000197 ?p
  }}
  FILTER(STRSTARTS(STR(?org), "https://cosai-oasis.github.io/ontology/cosai-contrib#org-"))
}} GROUP BY ?id ?name ORDER BY DESC(?people) ?name
"""

PEOPLE_BY_ROLE = """
SELECT ?person ?personId (COUNT(DISTINCT ?pub) AS ?publications) WHERE {{
  ?c a cosaic:{role_class} ; cosaic:onPublication ?pub ; obo:BFO_0000197 ?p .
  ?p rdfs:label ?person .
  BIND(REPLACE(STR(?p), "^.*#person-", "") AS ?personId)
  {extra}
}} GROUP BY ?person ?personId ORDER BY DESC(?publications) ?person
"""

WHAT_CITED = """
SELECT ?publisher ?citingPublication ?url ?category ?verification ?relationship ?signal
WHERE {{
  ?e a cosaic:CitationEvent ;
     cosaic:citedWork cosaic:pub-{publication} ;
     cosaic:citingPublication ?c .
  ?c rdfs:label ?citingPublication .
  OPTIONAL {{ ?c cosaic:publishedBy ?pubr . ?pubr rdfs:label ?publisher }}
  OPTIONAL {{ ?c cosaic:sourceUrl ?url }}
  OPTIONAL {{ ?e cosaic:citationCategory ?category }}
  OPTIONAL {{ ?e cosaic:verification ?verification }}
  OPTIONAL {{ ?e cosaic:publisherRelationship ?relationship }}
  OPTIONAL {{ ?e cosaic:evidenceSignal ?signal }}
}} ORDER BY ?publisher ?citingPublication
"""

CITATION_SUMMARY = """
SELECT ?work ?workId ?inScope (COUNT(DISTINCT ?citing) AS ?citingPublications)
WHERE {{
  ?e a cosaic:CitationEvent ; cosaic:citedWork ?w ; cosaic:citingPublication ?citing .
  ?w rdfs:label ?work ; a ?wt .
  BIND(REPLACE(STR(?w), "^.*#pub-", "") AS ?workId)
  BIND(IF(?wt = cosaic:Publication, true, false) AS ?inScope)
  VALUES ?wt {{ cosaic:Publication cosaic:CoSAIWorkStub }}
}} GROUP BY ?work ?workId ?inScope ORDER BY DESC(?citingPublications)
"""

CITATION_BREAKDOWN = """
SELECT ?category ?verification (COUNT(*) AS ?n) WHERE {{
  ?e a cosaic:CitationEvent .
  OPTIONAL {{ ?e cosaic:citationCategory ?category }}
  OPTIONAL {{ ?e cosaic:verification ?verification }}
  {filters}
}} GROUP BY ?category ?verification ORDER BY DESC(?n)
"""

PERSON_CREDIT_COUNT = """
SELECT (COUNT(?c) AS ?credits) WHERE {{
  ?c obo:BFO_0000197 cosaic:person-{person} ; cosaic:onPublication ?pub .
}}
"""


# --- Orientation: the newcomer's questions ---------------------------------------
#
# These answer "what is CoSAI doing", "how do I get involved" and "when does the group
# working on X meet". They deliberately return the *group* as the unit, because that is
# what a newcomer can act on -- a workstream or SIG they can join, with the list it
# announces on and the rhythm it keeps -- rather than a person or a document.

GROUP_DIRECTORY = """
SELECT ?groupId ?group ?kind ?parent ?status ?statusAsOf ?succeededBy ?continues
       (GROUP_CONCAT(DISTINCT ?listOrBlank; separator=" ") AS ?lists)
       (GROUP_CONCAT(DISTINCT ?cadenceOrBlank; separator=" ") AS ?cadences)
       (COUNT(DISTINCT ?sr) AS ?series)
       (COUNT(DISTINCT ?m) AS ?meetings)
       (COUNT(DISTINCT ?canceledMeeting) AS ?canceled)
       (MAX(?day) AS ?lastMet)
WHERE {{
  ?g rdfs:label ?group .
  {{ ?g a cosaic:Workstream . BIND("workstream" AS ?kind) }}
  UNION
  {{ ?g a cosaic:GoverningBody . BIND("governing-body" AS ?kind) }}
  UNION
  {{ ?g a cosaic:Committee . BIND("committee" AS ?kind) }}
  UNION
  {{ ?g a cosaic:SpecialInterestGroup . BIND("sig" AS ?kind)
     OPTIONAL {{ ?g obo:BFO_0000050 ?p . ?p rdfs:label ?parent }} }}
  BIND(REPLACE(STR(?g), "^.*#(ws-|gov-|com-|sig-)", "") AS ?groupId)
  # Curator statements, not mail evidence: see cosaic:activityStatus. At most one of
  # each per group, so grouping on them does not split a group's row.
  OPTIONAL {{ ?g cosaic:activityStatus ?status .
              OPTIONAL {{ ?g cosaic:statusAsOf ?statusAsOf }} }}
  OPTIONAL {{ ?g cosaic:succeededBy ?next .
              BIND(REPLACE(STR(?next), "^.*#(ws-|gov-|com-|sig-)", "") AS ?succeededBy) }}
  OPTIONAL {{ ?previous cosaic:succeededBy ?g .
              BIND(REPLACE(STR(?previous), "^.*#(ws-|gov-|com-|sig-)", "") AS ?continues) }}
  OPTIONAL {{
    ?sr a cosaic:MeetingSeries ; cosaic:convenedBy ?g .
    OPTIONAL {{ ?sr cosaic:cadence ?cadence }}
    OPTIONAL {{ ?sr cosaic:sourceList ?list }}
    # COALESCE before aggregating: GROUP_CONCAT over a group containing an unbound
    # value returns unbound, so one series without a cadence would erase the cadence
    # of every other series in the same group. Blanks are stripped by the caller.
    BIND(COALESCE(?cadence, "") AS ?cadenceOrBlank)
    BIND(COALESCE(?list, "") AS ?listOrBlank)
    OPTIONAL {{
      ?m cosaic:inSeries ?sr ; obo:BFO_0000199 ?i . ?i cosaic:date ?day .
      OPTIONAL {{ ?m cosaic:canceled true . BIND(?m AS ?canceledMeeting) }}
    }}
  }}
}}
GROUP BY ?groupId ?group ?kind ?parent ?status ?statusAsOf ?succeededBy ?continues
ORDER BY ?kind DESC(?meetings) ?group
"""


# Topic search over every surface a group's subject matter appears on: its own label,
# every verbatim series name (they drift, and the drift is the audit trail), the SIG
# name, and the titles of what the workstream has published. A newcomer asking about
# "MCP" or "supply chain" names a subject, not a group.
SERIES_BY_TOPIC = """
SELECT ?seriesId ?series ?group ?kind ?list ?cadence
       (MIN(?strength) AS ?rank)
       (GROUP_CONCAT(DISTINCT ?matchedOn; separator="; ") AS ?matchedOn)
WHERE {{
  ?sr a cosaic:MeetingSeries ; rdfs:label ?series .
  BIND(REPLACE(STR(?sr), "^.*#series-", "") AS ?seriesId)
  OPTIONAL {{ ?sr cosaic:cadence ?cadence }}
  OPTIONAL {{ ?sr cosaic:sourceList ?list }}
  OPTIONAL {{
    ?sr cosaic:convenedBy ?g . ?g rdfs:label ?group .
    OPTIONAL {{ ?g a cosaic:SpecialInterestGroup . BIND("sig" AS ?sigKind) }}
    OPTIONAL {{ ?g a cosaic:GoverningBody . BIND("governing-body" AS ?govKind) }}
    OPTIONAL {{ ?g a cosaic:Committee . BIND("committee" AS ?comKind) }}
  }}
  BIND(COALESCE(?sigKind, ?govKind, ?comKind, "workstream") AS ?kind)
  {{
    ?sr cosaic:seriesNameVariant ?variant .
    FILTER(CONTAINS(LCASE(?variant), LCASE({term})))
    BIND("series name" AS ?matchedOn) BIND(1 AS ?strength)
  }} UNION {{
    ?sr cosaic:convenedBy ?g2 . ?g2 rdfs:label ?groupLabel .
    FILTER(CONTAINS(LCASE(?groupLabel), LCASE({term})))
    BIND("group name" AS ?matchedOn) BIND(2 AS ?strength)
  }} UNION {{
    ?sr cosaic:convenedBy ?g3 .
    ?pub cosaic:producedBy ?g3 ; rdfs:label ?pubTitle .
    FILTER(CONTAINS(LCASE(?pubTitle), LCASE({term})))
    BIND(CONCAT("the group published: ", ?pubTitle) AS ?matchedOn)
    BIND(3 AS ?strength)
  }}
}}
GROUP BY ?seriesId ?series ?group ?kind ?list ?cadence
ORDER BY ?rank ?group ?series
"""


MEETING_TIMELINE = """
SELECT ?day ?series ?canceled ?evidence ?summarized ?scheduledStart ?timeZone WHERE {{
  ?m a cosaic:Meeting ; obo:BFO_0000199 ?i ; cosaic:canceled ?canceled ;
     cosaic:dateEvidence ?evidence ; cosaic:inSeries ?sr .
  ?i cosaic:date ?day .
  ?sr rdfs:label ?series .
  BIND(EXISTS {{ ?m cosaic:summarizedBy ?s }} AS ?summarized)
  OPTIONAL {{
    SELECT ?m (MIN(?st) AS ?scheduledStart) (SAMPLE(?tz) AS ?timeZone) WHERE {{
      ?e cosaic:correspondsTo ?m ; cosaic:scheduledStart ?st .
      OPTIONAL {{ ?e cosaic:scheduledTimeZone ?tz }}
    }} GROUP BY ?m
  }}
  {filters}
}} ORDER BY DESC(?day) ?series
"""

# One row per meeting, oldest first within each series, for measuring rhythm. The gaps
# between held meetings are computed by the caller: SPARQL has no window functions.
MEETING_ROWS = """
SELECT ?seriesId ?series ?day ?canceled ?evidence ?list ?cadence WHERE {{
  ?m a cosaic:Meeting ; obo:BFO_0000199 ?i ; cosaic:canceled ?canceled ;
     cosaic:dateEvidence ?evidence ; cosaic:inSeries ?sr .
  ?i cosaic:date ?day .
  ?sr rdfs:label ?series .
  BIND(REPLACE(STR(?sr), "^.*#series-", "") AS ?seriesId)
  OPTIONAL {{ ?sr cosaic:sourceList ?list }}
  OPTIONAL {{ ?sr cosaic:cadence ?cadence }}
  {filters}
}} ORDER BY ?seriesId ?day
"""

# Meetings with the records attached to them. A meeting with no summary still appears,
# with ?summary unbound: "held, no record" is the finding, not a gap in the query.
MEETING_RECORDS = """
SELECT ?day ?series ?list ?canceled ?evidence ?summary ?url ?restricted ?scheduledStart
       ?timeZone WHERE {{
  ?m a cosaic:Meeting ; obo:BFO_0000199 ?i ; cosaic:canceled ?canceled ;
     cosaic:dateEvidence ?evidence ; cosaic:inSeries ?sr .
  ?i cosaic:date ?day .
  ?sr rdfs:label ?series .
  OPTIONAL {{
    SELECT ?m (MIN(?st) AS ?scheduledStart) (SAMPLE(?tz) AS ?timeZone) WHERE {{
      ?e cosaic:correspondsTo ?m ; cosaic:scheduledStart ?st .
      OPTIONAL {{ ?e cosaic:scheduledTimeZone ?tz }}
    }} GROUP BY ?m
  }}
  OPTIONAL {{ ?sr cosaic:sourceList ?list }}
  OPTIONAL {{
    ?m cosaic:summarizedBy ?summary .
    OPTIONAL {{ ?summary cosaic:sourceUrl ?url }}
    OPTIONAL {{ ?summary cosaic:accessRestricted ?restricted }}
  }}
  {filters}
}} ORDER BY DESC(?day) ?series
"""

# Records posted on the given lists that could not be attached to one meeting, so a
# caller can say how many records exist beyond the ones shown per meeting.
UNATTACHED_RECORDS = """
SELECT (COUNT(DISTINCT ?s) AS ?unattached) WHERE {{
  ?s a cosaic:MeetingSummary ; cosaic:sourceList ?list .
  FILTER NOT EXISTS {{ ?m cosaic:summarizedBy ?s }}
  OPTIONAL {{ ?s cosaic:assertedAt ?i . ?i cosaic:date ?day }}
  {filters}
}}
"""

GOVERNANCE_TIMELINE = """
SELECT ?day ?event ?list WHERE {{
  ?g a cosaic:GovernanceEvent ; rdfs:label ?event ; obo:BFO_0000199 ?i .
  ?i cosaic:date ?day .
  OPTIONAL {{ ?g cosaic:sourceList ?list }}
}} ORDER BY DESC(?day)
"""

RECENT_PUBLICATIONS = """
SELECT ?id ?title ?workstream ?status ?date WHERE {{
  ?pub a cosaic:Publication ; rdfs:label ?title ; cosaic:approvalStatus ?status .
  BIND(REPLACE(STR(?pub), "^.*#pub-", "") AS ?id)
  OPTIONAL {{ ?pub cosaic:producedBy ?ws . ?ws rdfs:label ?workstream }}
  ?e a cosaic:PublicationEvent ; obo:BFO_0000057 ?pub ; obo:BFO_0000199 ?i .
  ?i cosaic:date ?date
}} ORDER BY DESC(?date)
"""

CORPUS_COUNTS = """
SELECT (COUNT(DISTINCT ?pub) AS ?publications) (COUNT(DISTINCT ?person) AS ?people)
       (COUNT(DISTINCT ?org) AS ?organizations) WHERE {{
  {{ ?pub a cosaic:Publication }} UNION {{ ?person a cosaic:Person }}
  UNION {{ ?org a cosaic:Organization .
           FILTER(STRSTARTS(STR(?org),
             "https://cosai-oasis.github.io/ontology/cosai-contrib#org-")) }}
}}
"""

COVERAGE = """
SELECT ?list ?earliest ?latest WHERE {{
  ?c a cosaic:CoverageWindow ; cosaic:sourceList ?list ;
     cosaic:earliestMessage ?earliest ; cosaic:latestMessage ?latest
}} ORDER BY ?list
"""


# Rank credited people, optionally excluding role classes. Separate from
# PEOPLE_BY_ROLE, which filters *to* one role: "who has contributed most, setting aside
# governance" needs the complement, and a model with only the former reaches for the
# SPARQL escape hatch and invents the credit path.
PEOPLE_RANKED = """
SELECT ?person ?personId (COUNT(DISTINCT ?pub) AS ?publications)
       (COUNT(DISTINCT ?c) AS ?credits)
       (GROUP_CONCAT(DISTINCT ?role; separator=" ") AS ?roles)
WHERE {{
  ?c a ?roleClass ; cosaic:onPublication ?pub ; obo:BFO_0000197 ?p .
  ?p rdfs:label ?person .
  BIND(REPLACE(STR(?p), "^.*#person-", "") AS ?personId)
  BIND(REPLACE(STR(?roleClass), "^.*#", "") AS ?role)
  # CreditedRole is the parent class; counting it would double every credit.
  FILTER(?roleClass != cosaic:CreditedRole)
  {filters}
}} GROUP BY ?person ?personId ORDER BY DESC(?publications) DESC(?credits) ?person
"""


# --- approvals, announcements and the forward schedule ------------------------------

# Every governance call on one work, with its role. A call's absence of closedOn is "no
# close in the archive", never "failed". A notice naming both bodies returns two rows.
APPROVAL_CALLS = """
SELECT ?callId ?label ?stage ?role ?body ?opened ?deadline ?closed ?restates WHERE {{
  ?call a cosaic:GovernanceCall ; rdfs:label ?label ; cosaic:callStage ?stage ;
        ?p cosaic:pub-{publication} .
  VALUES (?p ?role) {{
    (cosaic:callsToApproveNew "new") (cosaic:callsToApproveRevision "revision")
    (cosaic:callsToApproveAddition "addition") (cosaic:callsToReview "review")
  }}
  BIND(REPLACE(STR(?call), "^.*#govcall-", "") AS ?callId)
  OPTIONAL {{ ?call cosaic:decidedBy ?b . BIND(REPLACE(STR(?b), "^.*#gov-", "") AS ?body) }}
  OPTIONAL {{ ?call cosaic:openedOn ?opened }}
  OPTIONAL {{ ?call cosaic:objectionDeadline ?deadline }}
  OPTIONAL {{ ?call cosaic:closedOn ?closed }}
  OPTIONAL {{ ?call cosaic:restatesTscApproval ?restates }}
}} ORDER BY ?opened ?label ?body
"""

# The work a work was approved as an addition to, if any.
ADDITION_TO = """
SELECT ?parent WHERE {{
  cosaic:pub-{publication} cosaic:isAdditionTo ?a .
  BIND(REPLACE(STR(?a), "^.*#pub-", "") AS ?parent)
}}
"""

# Calendar entries for a future date, soonest first. Scheduled, not held: a planned
# meeting is judged from the calendar's read, and may since have moved or been dropped.
UPCOMING_MEETINGS = """
SELECT ?eventId ?label ?start ?end ?timeZone ?seriesId ?series WHERE {{
  ?e a cosaic:PlannedMeeting ; rdfs:label ?label ; cosaic:scheduledStart ?start ;
     cosaic:sourceEventId ?eventId .
  OPTIONAL {{ ?e cosaic:scheduledEnd ?end }}
  OPTIONAL {{ ?e cosaic:scheduledTimeZone ?timeZone }}
  OPTIONAL {{
    ?e cosaic:scheduleOf ?sr . ?sr rdfs:label ?series .
    BIND(REPLACE(STR(?sr), "^.*#series-", "") AS ?seriesId)
  }}
  {filters}
}} ORDER BY ?start ?label
"""

# What one source's fetch covers: a feed or a calendar window, by class.
SOURCE_WINDOW = """
SELECT ?label ?fetched ?earliest ?latest ?rangeStart ?rangeEnd WHERE {{
  ?w a cosaic:{window_class} ; rdfs:label ?label ; cosaic:fetchedOn ?fetched .
  OPTIONAL {{ ?w cosaic:earliestItem ?earliest }}
  OPTIONAL {{ ?w cosaic:latestItem ?latest }}
  OPTIONAL {{ ?w cosaic:rangeStart ?rangeStart }}
  OPTIONAL {{ ?w cosaic:rangeEnd ?rangeEnd }}
}}
"""

# Website posts linking a work, oldest first. The site's categories, never an author.
POSTS_LINKING = """
SELECT ?postId ?title ?published ?url (GROUP_CONCAT(DISTINCT ?category; separator="|")
       AS ?categories) WHERE {{
  ?post cosaic:linksTo cosaic:pub-{publication} ; rdfs:label ?title ;
        cosaic:publishedAt ?published ; cosaic:sourceUrl ?url .
  OPTIONAL {{ ?post cosaic:siteCategory ?category }}
  BIND(REPLACE(STR(?post), "^.*#post-", "") AS ?postId)
}} GROUP BY ?postId ?title ?published ?url ORDER BY ?published
"""

# TSC calls approving blog posts, by the post's curated title.
BLOG_CALLS = """
SELECT ?title ?opened ?deadline ?closed WHERE {{
  ?call a cosaic:GovernanceCall ; cosaic:subjectMatter "blog" ; cosaic:concernsTitle ?title .
  OPTIONAL {{ ?call cosaic:openedOn ?opened }}
  OPTIONAL {{ ?call cosaic:objectionDeadline ?deadline }}
  OPTIONAL {{ ?call cosaic:closedOn ?closed }}
}} ORDER BY ?opened
"""

# Every inferred employer change across the corpus, with the person and its window.
ALL_AFFILIATION_CHANGES = """
SELECT ?personId ?person ?kind ?label ?notBefore ?notAfter ?inferred WHERE {{
  ?e a ?t ; obo:BFO_0000057 ?p ; rdfs:label ?label ; cosaic:inferred ?inferred ;
     obo:BFO_0000199 ?w .
  ?p a cosaic:Person ; rdfs:label ?person .
  ?w cosaic:notBefore ?notBefore ; cosaic:notAfter ?notAfter .
  VALUES ?t {{ cosaic:AffiliationLoss cosaic:AffiliationGain }}
  BIND(REPLACE(STR(?t), "^.*#", "") AS ?kind)
  BIND(REPLACE(STR(?p), "^.*#person-", "") AS ?personId)
}} ORDER BY ?notBefore ?person
"""
