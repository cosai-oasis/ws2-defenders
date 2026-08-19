# AITF Collector Configuration

Pre-configured OpenTelemetry Collector setup for AITF AI telemetry.

## Overview

The AITF Collector extends the standard OTel Collector with:

- **AI span filtering** — Routes AI-specific spans to dedicated pipelines
- **OCSF export** — Writes OCSF-formatted events for SIEM/XDR consumption
- **Prometheus metrics** — Exposes AITF metrics at `:8889`
- **Health checks** — Standard OTel health endpoint at `:13133`

## Quick Start

```bash
# Using the official OTel Collector with AITF config
docker run -v $(pwd)/config:/etc/otelcol:ro \
  otel/opentelemetry-collector-contrib:latest \
  --config /etc/otelcol/aitf-collector-config.yaml
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OTLP backend endpoint |
| `OTEL_EXPORTER_OTLP_INSECURE` | `true` | Disable TLS |

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 4317 | gRPC | OTLP receiver |
| 4318 | HTTP | OTLP receiver |
| 8889 | HTTP | Prometheus metrics |
| 13133 | HTTP | Health check |
| 55679 | HTTP | zPages debug |

## Pipelines

1. **traces/ai** — Main pipeline: receives OTLP → AITF processors → OTLP + OCSF file
2. **traces/debug** — Debug pipeline: AI spans only → console output
3. **metrics** — Metrics pipeline: OTLP → Prometheus
