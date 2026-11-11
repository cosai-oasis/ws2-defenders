# Ontology

This directory defines the concepts and relationships used in Bubo’s knowledge graph. It covers people, organizations, publications, contribution roles, meetings, and governance, along with the sources and dates supporting those records. It also contains validation rules for checking the graph’s structure.

The model distinguishes things that persist, such as people, organizations, and publications, from events such as publishing, revising, citing, or canceling a meeting. A `Publication` represents a work, while a `Manifestation` represents a file carrying it. Contribution credits and affiliations have their own role records, allowing each relationship to carry supporting evidence.

Meetings can be standalone events or occurrences within a recurring series. A `Meeting` represents one occurrence and connects to its `MeetingSeries` through `inSeries`. The series represents the schedule, with `cadence` recording the recurrence rule when known. Standalone meetings use the same structure and are represented as a series of one.

Affiliation dates are evidence dates. `earliestEvidence` and `latestEvidence` show when an affiliation was attested, with `boundsKnown false` because the actual beginning and ending are unknown. Inferred affiliation changes carry `notBefore`, `notAfter`, and `inferred true`. Nothing is interpolated between separate attested spans. Credits retained across a revision remain evidence about their original assertion date unless the credit list was refreshed.

Data is separated by source into named graphs for ontology, publications, citations, mailing lists, website posts, and calendar entries. Each source partition is validated against its own class allowlist and applicable domain requirements. Cross-graph uniqueness and referential integrity are checked separately at dataset level.

`Alignments/` is the source folder for all bridges between terms in the `cosaic` ontology and counterparts in the SKOS ontology and all MIREOT'd terms and relationships from OWL, RDFS, and SKOS ontologies.

`Shapes/` holds the graph shapes for Publications, Citations, Mail list, Website, Calendar, and the TBox. There can be no duplicate triples across different graphs, however the graphs are not disjoint. One IRI can appear in multiple graphs, however the relationships make it a different entity and not a duplicated triple.

`Shapes/` also contains the shape of all claims that the engine is able to make in response to questions that a user might ask it. These claims contain no bare start or end dates, but rather affiliation intervals that avoid the false precision of a start or end date. Every claim must reference where it came from.
