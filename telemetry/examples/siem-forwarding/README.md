# AITF SIEM Forwarding Examples

Forward OCSF-formatted AI telemetry from AITF into security platforms for monitoring, detection, and incident response.

## Overview

AITF generates **OCSF Category 7** (AI System Activity) events from AI workloads -- LLM inference, agent sessions, MCP tool calls, RAG pipelines, and security findings. These examples show how to forward those events into three major security platforms:

| Platform | Native OCSF | Ingestion Method | Real-Time | Batch |
|---|---|---|---|---|
| **AWS Security Lake** | Yes | S3 (Parquet) / Kinesis Firehose | Yes | Yes |
| **Trend Vision One** | No (CEF) | Syslog/CEF to Service Gateway | Yes | Yes |
| **Splunk** | No (CIM) | HTTP Event Collector (HEC) | Yes | Yes |

All three examples use the AITF Python SDK (`aitf.ocsf.*`, `aitf.exporters.*`, `aitf.processors.*`) and implement OpenTelemetry `SpanExporter` interfaces, so they plug directly into any OTel pipeline.


## Architecture

```
 +-----------------------+
 |   AI Application      |
 |  (LLM, Agent, MCP)    |
 +-----------+-----------+
             |
             | OpenTelemetry Spans
             v
 +-----------+-----------+
 |   AITF Processors     |
 |  - SecurityProcessor  |
 |  - CostProcessor      |
 |  - ComplianceProcessor|
 +-----------+-----------+
             |
             | OCSF Category 7 Events
             v
 +-----------+-----------+
 |   AITF OCSFMapper     |
 |  - 7001 Inference     |
 |  - 7002 Agent         |
 |  - 7003 Tool          |
 |  - 7004 Retrieval     |
 |  - 7005 Security      |
 |  - 7006 Supply Chain  |
 |  - 7007 Governance    |
 |  - 7008 Identity      |
 +-----------+-----------+
             |
     +-------+-------+------------------+
     |               |                  |
     v               v                  v
 +---+---+     +-----+------+    +------+-------+
 |  AWS  |     | Trend V1   |    |   Splunk     |
 |  Sec  |     |   XDR      |    |    HEC       |
 | Lake  |     | (CEF/syslg)|    | (CIM mapped) |
 +---+---+     +-----+------+    +------+-------+
     |               |                  |
     v               v                  v
 +---+---+     +-----+------+    +------+-------+
 | Athena |    | Workbench  |    | Dashboards   |
 | Queries|    | Alerts +   |    | SPL Queries  |
 +--------+    | Suspicious |    | CIM Models   |
               | Objects API|    +--------------+
               +------------+
```


## 1. AWS Security Lake

**File:** `aws_security_lake.py`

AWS Security Lake uses OCSF as its native schema, making it the most natural destination for AITF events.

### Key Features

- **Native OCSF support** -- no schema translation needed
- **Parquet conversion** using PyArrow for efficient columnar storage
- **Two ingestion approaches:**
  - S3 Direct (batch) -- write Parquet files to the Security Lake bucket
  - Kinesis Firehose (real-time) -- stream events through a delivery stream
- **Custom source registration** -- registers "AITF-AI-Telemetry" in Security Lake
- **Athena queries** -- six predefined queries for security analytics
- **Cross-correlation** -- join AI events with VPC Flow Logs, CloudTrail, etc.

### Prerequisites

```bash
pip install boto3 pyarrow opentelemetry-sdk aitf
```

### AWS IAM Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::aws-security-data-lake-*",
                "arn:aws:s3:::aws-security-data-lake-*/ext/AITF-AI-Telemetry/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "firehose:PutRecord",
                "firehose:PutRecordBatch"
            ],
            "Resource": "arn:aws:firehose:*:*:deliverystream/aws-security-data-lake-*"
        },
        {
            "Effect": "Allow",
            "Action": "securitylake:CreateCustomLogSource",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "athena:StartQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults"
            ],
            "Resource": "*"
        }
    ]
}
```

### Environment Variables

```bash
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=123456789012
export SECURITY_LAKE_BUCKET=aws-security-data-lake-us-east-1-abcdef123456
export SECURITY_LAKE_FIREHOSE=aws-security-data-lake-delivery-AITF-AI-Telemetry
export SECURITY_LAKE_APPROACH=s3  # or "firehose"
```

### Running

```bash
python examples/siem-forwarding/aws_security_lake.py
```


## 2. Trend Vision One

**File:** `trend_vision_one.py`

Trend Vision One (TV1) integrates through three complementary methods: syslog/CEF forwarding for log ingestion, the Suspicious Objects API for threat indicator push, and Workbench alert annotation for incident enrichment.

### Key Features

- **Syslog/CEF forwarding** -- AITF OCSF events are converted to CEF (Common Event Format) syslog messages and sent to a TV1 Service Gateway collector. This is how TV1's Third-Party Log Collection ingests external data.
  - [Third-Party Log Collection docs](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-third-party-log-intro)
- **Suspicious Object API** (`POST /v3.0/response/suspiciousObjects`) -- push threat indicators (domains, IPs, URLs, file hashes) extracted from high-severity findings to TV1's block list
  - [API reference](https://automation.trendmicro.com/xdr/api-v3/)
- **Workbench alert enrichment** (`GET /v3.0/workbench/alerts`, `PATCH /v3.0/workbench/alerts/{id}`, `POST /v3.0/workbench/alerts/{id}/notes`) -- query alerts generated by TV1 detection models and annotate them with AITF context
- **Custom detection model specs** -- four AI-specific detection rules for configuring in the TV1 console (Detection Model Management > Custom Models):
  - Prompt Injection Attempt (OWASP LLM01)
  - Jailbreak Attempt (OWASP LLM01)
  - Data Exfiltration via AI (OWASP LLM02)
  - Anomalous Model Cost Spike (OWASP LLM10)

### Prerequisites

```bash
pip install requests opentelemetry-sdk aitf
```

### Trend Vision One Setup

1. **Service Gateway** -- deploy a Service Gateway virtual appliance (Workflow and Automation > Service Gateway Management)
2. **Third-Party Log Collection** -- enable the service on the gateway and create a collector:
   - Protocol: TCP (recommended) or UDP
   - Port: 6514-6533
   - Log format: CEF
3. **API Key** -- obtain from Administration > API Keys > Add API Key

### Environment Variables

```bash
# Syslog/CEF collector (primary ingestion)
export TV1_COLLECTOR_HOST=service-gateway.example.com
export TV1_COLLECTOR_PORT=6514
export TV1_COLLECTOR_PROTOCOL=tcp
export TV1_COLLECTOR_TLS=true

# REST API (threat enrichment + alert management)
export TV1_API_BASE_URL=https://api.xdr.trendmicro.com
export TV1_API_KEY=your-api-key-here
```

### API Key Permissions

The TV1 API key requires the following roles:
- **Suspicious Objects** -- for threat indicator submission
- **Workbench** -- for alert query, status update, and note creation

### API Reference

- [Third-Party Log Collection](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-third-party-log-intro)
- [Authentication](https://automation.trendmicro.com/xdr/Guides/Authentication/)
- [Regional Domains](https://automation.trendmicro.com/xdr/Guides/Regional-domains/)
- [API v3.0 Reference](https://automation.trendmicro.com/xdr/api-v3/)
- [Python SDK (pytmv1)](https://github.com/trendmicro/tm-v1-pytv1)
- [API Cookbook](https://github.com/trendmicro/tm-v1-api-cookbook)

### Running

```bash
python examples/siem-forwarding/trend_vision_one.py
```


## 3. Splunk

**File:** `splunk_forwarding.py`

Splunk uses HTTP Event Collector (HEC) for ingestion and the Common Information Model (CIM) for data normalization. This example maps OCSF events to CIM data models and provides comprehensive SPL queries.

### Key Features

- **HTTP Event Collector (HEC)** ingestion with gzip compression
- **Two exporter modes:**
  - Streaming -- immediate delivery for security findings
  - Batch -- efficient batching with background flush thread
- **OCSF-to-CIM mapping** for four CIM data models:
  - `alerts` -- AI security findings
  - `authentication` -- AI identity events
  - `performance` -- inference latency and token usage
  - `change` -- agent activity and tool execution
- **16 SPL queries** covering:
  - Security monitoring (findings, OWASP coverage, injections)
  - Model analytics (usage, latency, cost anomalies)
  - Agent monitoring (sessions, delegation, excessive agency)
  - Compliance coverage
  - Dashboard panels (single values, timelines, heatmaps)
- **Dashboard XML template** ready to install in Splunk

### Prerequisites

```bash
pip install requests opentelemetry-sdk aitf
```

### Splunk Setup

1. Create an index:
```
Settings > Indexes > New Index
  Name: aitf_ai_telemetry
  Max Size: 500 GB
```

2. Create an HEC token:
```
Settings > Data Inputs > HTTP Event Collector > New Token
  Name: AITF AI Telemetry
  Source type: _json
  Allowed indexes: aitf_ai_telemetry
```

3. Enable HEC:
```
Settings > Data Inputs > HTTP Event Collector > Global Settings
  All Tokens: Enabled
  HTTP Port: 8088
  SSL: Enabled
```

### Environment Variables

```bash
export SPLUNK_HEC_URL=https://splunk.example.com:8088/services/collector
export SPLUNK_HEC_TOKEN=your-hec-token-here
export SPLUNK_INDEX=aitf_ai_telemetry
export SPLUNK_VERIFY_SSL=true
```

### Source Types

Events are categorized by OCSF class with specific sourcetypes:

| OCSF Class | Class UID | Splunk Sourcetype |
|---|---|---|
| Model Inference | 7001 | `aitf:ocsf:ai:inference` |
| Agent Activity | 7002 | `aitf:ocsf:ai:agent` |
| Tool Execution | 7003 | `aitf:ocsf:ai:tool` |
| Data Retrieval | 7004 | `aitf:ocsf:ai:retrieval` |
| Security Finding | 7005 | `aitf:ocsf:ai:security` |
| Supply Chain | 7006 | `aitf:ocsf:ai:supply_chain` |
| Governance | 7007 | `aitf:ocsf:ai:governance` |
| Identity | 7008 | `aitf:ocsf:ai:identity` |

### Running

```bash
python examples/siem-forwarding/splunk_forwarding.py
```


## Common Patterns

### Using Multiple SIEM Destinations

You can forward AITF events to multiple platforms simultaneously:

```python
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()

# Forward to all three platforms
provider.add_span_processor(BatchSpanProcessor(SecurityLakeS3Exporter(aws_config)))
provider.add_span_processor(BatchSpanProcessor(TrendVisionOneExporter(tv1_config)))
provider.add_span_processor(BatchSpanProcessor(SplunkBatchExporter(splunk_config)))
```

### Filtering Events by Severity

Send only high-severity events to expensive real-time pipelines:

```python
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

# Real-time: only security findings (streaming)
provider.add_span_processor(SimpleSpanProcessor(streaming_exporter))

# Batch: all events (cheaper, higher latency)
provider.add_span_processor(BatchSpanProcessor(batch_exporter))
```

### Adding Compliance Metadata

All exporters work with the AITF compliance mapper:

```python
from aitf.exporters.ocsf_exporter import OCSFExporter

exporter = OCSFExporter(
    compliance_frameworks=["nist_ai_rmf", "mitre_atlas", "eu_ai_act", "soc2"],
)
```


## OCSF Event Classes Reference

| Class UID | Event Class | Description |
|---|---|---|
| 7001 | Model Inference | LLM/embedding inference operations |
| 7002 | Agent Activity | Agent sessions, steps, delegation |
| 7003 | Tool Execution | Function calls, MCP tools, skills |
| 7004 | Data Retrieval | RAG, vector search, document retrieval |
| 7005 | Security Finding | OWASP threats, injections, exfiltration |
| 7006 | Supply Chain | Model provenance, integrity, AI BOM |
| 7007 | Governance | Compliance checks, policy violations |
| 7008 | Identity | Agent auth, permissions, delegation chains |


## API & Documentation References

Each SIEM integration uses only documented, production APIs:

### AWS Security Lake
- [AWS Security Lake - Custom Sources](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html)
- [boto3 S3 put_object](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/put_object.html)
- [boto3 Firehose put_record_batch](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/firehose/client/put_record_batch.html)
- [OCSF Schema (native)](https://schema.ocsf.io/)

### Trend Vision One
- [Third-Party Log Collection (syslog/CEF ingestion)](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-third-party-log-intro)
- [API v3.0 Reference](https://automation.trendmicro.com/xdr/api-v3/)
- [Authentication (Bearer token)](https://automation.trendmicro.com/xdr/Guides/Authentication/)
- [Regional Domains](https://automation.trendmicro.com/xdr/Guides/Regional-domains/)
- [Python SDK (pytmv1)](https://github.com/trendmicro/tm-v1-pytv1)
- [API Cookbook (examples)](https://github.com/trendmicro/tm-v1-api-cookbook)

### Splunk
- [HTTP Event Collector (HEC) API](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
- [HEC /services/collector endpoint](https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector)
- [Common Information Model (CIM)](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- [Splunk SDKs](https://dev.splunk.com/enterprise/docs/devtools/)
