# ARCADE

ARCADE (Assessing Risks and Control through Attack Detection Evaluations), arcade for
short, is a harness that turns the CoSAI Risk Map from a set of *asserted* relationships
into a set of *tested* ones, as
[`secure-ai-tooling#491`](https://github.com/cosai-oasis/secure-ai-tooling/issues/491)
asks. The Risk Map says that a control addresses a risk, 37 controls against 36 risks,
reciprocally linked; no executed evidence exists anywhere that any one of those edges
holds.

arcade runs a documented attack against a deliberately vulnerable target, undefended and
then defended, and derives its verdict from the telemetry the
[Telemetry RFC](../telemetry/CoSAI-AI-Telemetry-RFC.md) says a compliant system emits.
Each run produces a record keyed to the Risk Map's own ids, so a practitioner asking
*"does this control actually stop that risk, and how would I know?"* gets a reproducible
answer carrying a date, the versions it ran against, and a claim-strength tier that says
what the answer does and does not license. The same run tests the RFC: a MUST field that
cannot evidence the outcome it exists to evidence is a finding against the RFC.

Run records join [bubo](../bubo/)'s ontology through the same Risk Map ids.

## Status

This directory holds no code yet. The decisions that govern arcade are in
[ADR-WS2-002](../adr/002-testable-riskmap-arcade.md). The two decisions everything
else rests on are reserved as ADR-WS2-006 (the target range) and ADR-WS2-007 (the pair
contract).
