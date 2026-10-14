# CoSAI AI Telemetry RFC: document-specific conventions

These apply only to *Telemetry for AI Security* (`telemetry/CoSAI-AI-Telemetry-RFC.md`
in the `cosai-oasis/ws2-defenders` repository). They are binding in addition to P1 to P6.

## Editorial

- **Priority order is D > R > Q > A.** State it as the document's deliberate bias
  wherever fields or recommendations are ranked.
- **Two notes survive as fact.** *Convention status* (Appendix D) and *Framework status*
  (Appendix H) were work notes; their instructions were removed under P3 and what
  remained was retitled. Do not add instructions back to them.
- **The markdown in the repository is authoritative.** The `.docx` built from it with
  pandoc is for circulation only, and there is no sync path back from any other copy.

## Identifiers and names

- **MITRE ATLAS `AML.Txxxx` identifiers are canonical.** The CoSAI `AT10xx` identifiers
  are deprecated aliases, permitted only in Appendix A.4's migration table and in the
  historical `IR-` rows.
- **Appendix C field names match the canonical names in §§5 to 16 exactly**, so the
  cross reference can be joined by name. Do not truncate or merge a field name there.

## Counts that the document's own validator asserts

The RFC's `validate.py` hard-codes the requirement tier totals and the attack corpus
size. Update the validator in the same change whenever either moves:

| Asserted | Value |
| --- | --- |
| Tier totals | 50 MUST, 33 SHOULD, 15 MAY, 98 fields |
| Attack corpus | 40 attacks: `TA-01` to `TA-19`, `IR-01` to `IR-05`, `AOC-01` to `AOC-16` |

The validator also checks that each inline field reference points at the section that
defines the field, that the reference list is sequential, and that each `[[n]]`
citation points at the reference its context names.

## Known exemption

The official title of ISO/IEC 42001 contains dashes. Keep the title verbatim; the
validator's dash check reports it, and that report is a known false positive. When
using the review skill's checker, pass the title with `--allow`.
