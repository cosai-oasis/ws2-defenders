# Sample telemetry profile

## 1. Conventions

The keywords MUST, SHOULD and MAY are to be interpreted as described in RFC 2119 when,
and only when, they appear in capitals. See [Retention](#2-retention).

## 2. Retention

### 2.1 Duration

Frankly, collectors used to be allowed to drop events. This revision changes that:
collectors must keep every event for 30 days.

Controls map to ISO/IEC 42001:2023 — Information technology — Artificial intelligence — Management system.

TODO: confirm the 30-day figure with the working group before publication.

## 3. Export

Exporters SHOULD batch events — see §4 for transport.

| Field | Tier |
| --- | --- |
| Event ID | MUST |
| Stop Reason | MUST | extra |

See [Transport](#transport) for details.

```
Frankly, code blocks are not prose, so this line is never flagged — even with a dash.
```
