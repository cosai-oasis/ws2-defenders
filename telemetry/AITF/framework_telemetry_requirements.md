# AI Security & Governance Frameworks: Telemetry & Logging Requirements

**Research Date:** February 6, 2026  
**Purpose:** Comprehensive mapping of telemetry, logging, detection, and audit requirements across major AI security frameworks

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [OWASP Top 10 for LLM Applications 2025](#1-owasp-top-10-for-llm-applications-2025)
3. [OWASP Top 10 for Agentic Applications 2026](#2-owasp-top-10-for-agentic-applications-2026)
4. [MITRE ATLAS](#3-mitre-atlas)
5. [CSA AI Controls Matrix](#4-csa-ai-controls-matrix)
6. [NIST AI Risk Management Framework](#5-nist-ai-risk-management-framework)
7. [ISO/IEC 42001](#6-isoiec-42001)
8. [Cross-Framework Telemetry Mapping](#7-cross-framework-telemetry-mapping)
9. [Implementation Recommendations](#8-implementation-recommendations)

---

## Executive Summary

This document provides a comprehensive analysis of telemetry and logging requirements across six major AI security and governance frameworks. Key findings:

| Framework | Primary Focus | Telemetry Emphasis |
|-----------|--------------|-------------------|
| OWASP LLM Top 10 2025 | LLM-specific vulnerabilities | Input/output monitoring, prompt logging, resource consumption |
| OWASP Agentic AI 2026 | Autonomous agent security | Tool calls, decision chains, inter-agent communication |
| MITRE ATLAS | Adversarial ML threats | Attack detection, anomaly monitoring, model behavior |
| CSA AICM | Cloud AI security | 243 controls across 18 domains, audit logging |
| NIST AI RMF | Risk management lifecycle | Continuous monitoring, bias/drift detection |
| ISO 42001 | AI management systems | Tamper-evident logs, lifecycle event trails |

---

## 1. OWASP Top 10 for LLM Applications 2025

### Overview
The OWASP Top 10 for LLM Applications 2025 identifies critical security risks for Large Language Model applications. While telemetry requirements are implicit, they are essential for detection and compliance.

### Telemetry Requirements by Vulnerability

#### LLM01:2025 - Prompt Injection

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Input Logging** | All user prompts (with PII masking) | Pattern analysis for injection attempts |
| **System Prompt Access** | Attempts to reference/modify system prompts | Direct injection detection |
| **External Content Ingestion** | URLs, documents, emails processed | Indirect injection tracking |
| **Output Deviations** | Responses that deviate from expected behavior | Successful injection indicators |
| **Tool Call Sequences** | Unexpected tool invocations post-input | Action hijacking detection |

**Compliance Evidence:**
- Baseline of normal prompt patterns
- Alert logs for detected injection attempts
- Incident response records

#### LLM02:2025 - Sensitive Information Disclosure

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Output Scanning Logs** | All LLM outputs scanned for PII/credentials | Data leak detection |
| **Training Data Access** | Queries that trigger memorization recall | Extraction attempt detection |
| **Credential Pattern Matches** | API keys, passwords, tokens in outputs | Credential leak alerts |
| **User Query Patterns** | Repeated probing for sensitive data | Exfiltration attempt patterns |

**Compliance Evidence:**
- DLP scan results and alerts
- Data classification tags in logs
- Redaction/masking audit trails

#### LLM03:2025 - Supply Chain

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Dependency Inventory** | All third-party models, plugins, datasets | Asset tracking |
| **Integrity Verification** | Hash checks on model files, adapters | Tampering detection |
| **Update Events** | When/how components were updated | Change tracking |
| **CI/CD Pipeline Logs** | Build and deployment activities | Compromise detection |

**Compliance Evidence:**
- SBOM (Software Bill of Materials) for AI components
- Cryptographic verification records
- Vendor security assessment logs

#### LLM04:2025 - Data and Model Poisoning

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Training Data Provenance** | Source, timestamp, integrity hash | Data lineage tracking |
| **Fine-tuning Events** | Dataset used, parameters, outcomes | Model change audit |
| **RAG Database Changes** | Additions/modifications to embeddings | Poisoning detection |
| **Model Performance Metrics** | Accuracy, bias scores over time | Drift/degradation alerts |
| **Data Quality Scores** | Anomaly scores for training data | Poisoned data detection |

**Compliance Evidence:**
- Data lineage documentation
- Model versioning with checksums
- Performance baseline comparisons

#### LLM05:2025 - Improper Output Handling

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Output Destinations** | Where LLM outputs are sent | Downstream risk tracking |
| **Encoding/Sanitization Events** | What filtering was applied | Control verification |
| **Downstream System Logs** | SQL queries, shell commands executed | Injection propagation |
| **Error Responses** | Failed sanitization attempts | Control gaps |

**Compliance Evidence:**
- Output validation rule logs
- Integration security scan results
- Incident correlation records

#### LLM06:2025 - Excessive Agency

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Permission Requests** | What capabilities LLM requested | Privilege escalation |
| **Tool Invocations** | Every tool/API called by LLM | Action audit trail |
| **Human Override Events** | When humans intervened | Control effectiveness |
| **Autonomous Decision Chains** | Multi-step actions without approval | Agency boundaries |
| **Resource Access Logs** | Files, databases, APIs accessed | Scope verification |

**Compliance Evidence:**
- Tool permission manifests
- Human-in-the-loop approval records
- Action authorization logs

#### LLM07:2025 - System Prompt Leakage

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Prompt Extraction Attempts** | Queries asking for instructions | Leakage attempts |
| **Response Content Analysis** | Outputs containing system prompt fragments | Successful leaks |
| **Jailbreak Pattern Matches** | Known bypass techniques detected | Attack monitoring |

**Compliance Evidence:**
- System prompt access controls
- Leak detection alert history
- Prompt hardening test results

#### LLM08:2025 - Vector and Embedding Weaknesses

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Vector Database Access** | All queries and modifications | Unauthorized access |
| **Embedding Updates** | When/how embeddings changed | Poisoning detection |
| **Similarity Search Logs** | Unusual retrieval patterns | Attack patterns |
| **Cross-tenant Queries** | Isolation boundary violations | Data leakage |

**Compliance Evidence:**
- RAG system audit logs
- Embedding integrity verification
- Access control enforcement records

#### LLM09:2025 - Misinformation

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Factual Verification Logs** | Claims checked against sources | Accuracy monitoring |
| **Confidence Scores** | LLM uncertainty indicators | Hallucination risk |
| **Citation Verification** | Whether cited sources exist | Fabrication detection |
| **User Feedback** | Reports of incorrect information | Quality tracking |

**Compliance Evidence:**
- Fact-checking pipeline results
- Hallucination rate metrics
- User correction logs

#### LLM10:2025 - Unbounded Consumption

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Token Usage** | Input/output tokens per request | Resource monitoring |
| **Compute Metrics** | CPU, GPU, memory utilization | Capacity planning |
| **Request Rates** | Requests per user/API key/time | DoS detection |
| **Cost Tracking** | Financial impact per request | Billing anomalies |
| **Context Length** | Prompt sizes over time | Context flooding |

**Compliance Evidence:**
- Rate limiting enforcement logs
- Cost anomaly alerts
- Capacity utilization reports

---

## 2. OWASP Top 10 for Agentic Applications 2026

### Overview
Released December 2025, this framework addresses security risks specific to autonomous AI agents that can plan, decide, and act across complex workflows.

### Core Telemetry Principles

The framework emphasizes two foundational principles that directly impact telemetry:

1. **Least Agency** - Monitor that agents operate within minimum required autonomy
2. **Strong Observability** - Track what agents do, why, and with what tools/identities

### Telemetry Requirements by Vulnerability

#### ASI01 - Agent Goal Hijack

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Goal State Changes** | Agent objective modifications | Unauthorized goal changes |
| **Input Source Tracking** | Origin of all natural language inputs | Poisoned content sources |
| **Planning Steps** | Reasoning chains and decisions | Manipulation detection |
| **Content Ingestion Logs** | PDFs, emails, RAG documents processed | Indirect injection sources |
| **Behavioral Deviations** | Actions inconsistent with stated goals | Hijacking indicators |

**Compliance Evidence:**
- Goal modification approval logs
- Content provenance tracking
- Behavioral baseline comparisons

#### ASI02 - Tool Misuse and Exploitation

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Tool Invocation Logs** | Every tool call with full parameters | Complete action audit |
| **Permission Checks** | Tool access authorization events | Privilege verification |
| **Argument Validation** | Tool parameter validation results | Unsafe input detection |
| **Tool Chaining Sequences** | Multi-tool execution patterns | Unexpected chains |
| **Sandbox Violations** | Attempts to escape isolation | Security boundary breaches |

**Compliance Evidence:**
- Tool permission manifests
- Sandbox enforcement records
- Argument validation audit trails

#### ASI03 - Identity and Privilege Abuse

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Credential Usage** | All credential access/use events | Unauthorized use |
| **Privilege Escalation** | Permission changes during execution | Scope creep |
| **Identity Delegation** | Credential passing between agents | Confused deputy |
| **Session Boundaries** | Credential lifecycle management | Credential reuse |
| **Cross-Agent Auth** | Authentication events between agents | Lateral movement |

**Compliance Evidence:**
- Credential lifecycle audit
- Short-lived token enforcement
- Task-scoped permission records

#### ASI04 - Agentic Supply Chain Vulnerabilities

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Component Loading** | Dynamic tool/plugin fetches | Unauthorized components |
| **MCP Server Connections** | External server interactions | Malicious servers |
| **Manifest Verification** | Signature checks on components | Tampering detection |
| **Dependency Resolution** | What dependencies were loaded | Supply chain tracking |
| **Registry Access** | Tool/plugin registry queries | Compromise indicators |

**Compliance Evidence:**
- Component signature verification logs
- Approved registry allowlists
- Kill switch activation records

#### ASI05 - Unexpected Code Execution

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Code Generation Events** | All agent-generated code | Audit trail |
| **Execution Requests** | Code execution attempts | Unauthorized execution |
| **Sandbox Logs** | Code running in isolated environments | Escape attempts |
| **Shell Command Logs** | System commands executed | Dangerous commands |
| **Deserialization Events** | Object deserialization activities | RCE vectors |

**Compliance Evidence:**
- Code review pipeline logs
- Sandbox enforcement records
- Execution approval workflows

#### ASI06 - Memory and Context Poisoning

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Memory Writes** | All updates to agent memory | Poisoning attempts |
| **Memory Reads** | Context retrieval events | Usage tracking |
| **Provenance Tracking** | Source of memory entries | Trusted vs untrusted |
| **Memory Expiry** | Cleanup of suspicious entries | Hygiene verification |
| **Cross-session Persistence** | Data carried between sessions | Long-term poisoning |

**Compliance Evidence:**
- Memory segmentation enforcement
- Provenance tagging records
- Memory hygiene audit logs

#### ASI07 - Insecure Inter-Agent Communication

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Message Logs** | All inter-agent messages | Communication audit |
| **Authentication Events** | mTLS, signature verification | Auth verification |
| **Message Integrity** | Payload signature validation | Tampering detection |
| **Replay Detection** | Duplicate message identification | Replay attacks |
| **Discovery Events** | Agent discovery and registration | Spoofing detection |

**Compliance Evidence:**
- mTLS certificate logs
- Anti-replay nonce tracking
- Authenticated discovery records

#### ASI08 - Cascading Failures

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Error Propagation** | Error state across agents | Cascade detection |
| **Circuit Breaker Events** | When/why circuits opened | Failure isolation |
| **Rate Limit Hits** | Throttling events | Runaway prevention |
| **Recovery Actions** | How systems recovered | Resilience verification |
| **Plan Execution State** | Multi-step plan status | Failure points |

**Compliance Evidence:**
- Circuit breaker activation logs
- Rate limiting enforcement
- Recovery audit trails

#### ASI09 - Human-Agent Trust Exploitation

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Approval Requests** | Human confirmation prompts | Manipulation patterns |
| **Persuasion Indicators** | Pressure tactics in outputs | Trust exploitation |
| **Sensitive Action Logs** | High-risk actions approved | Audit trail |
| **User Decision Timing** | Time taken to approve | Rushed decisions |
| **Risk Disclosure** | Whether risks were shown | Informed consent |

**Compliance Evidence:**
- Forced confirmation records
- Immutable approval logs
- Risk indicator presentation audit

#### ASI10 - Rogue Agents

| Telemetry Category | Required Data Points | Detection Purpose |
|-------------------|---------------------|-------------------|
| **Behavioral Baselines** | Normal agent behavior patterns | Anomaly detection |
| **Self-replication Events** | Agent spawning activities | Unauthorized agents |
| **Persistence Attempts** | Cross-session survival tactics | Rogue persistence |
| **Impersonation Attempts** | Identity spoofing events | Agent impersonation |
| **Kill Switch Events** | Termination command responses | Control verification |

**Compliance Evidence:**
- Behavioral monitoring dashboards
- Agent lifecycle audit
- Kill switch effectiveness tests

---

## 3. MITRE ATLAS

### Overview
MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is a knowledge base of 15 tactics, 66 techniques, and 46 sub-techniques specifically for AI/ML threats. As of October 2025, it includes 14 new agentic AI techniques.

### Telemetry Requirements by Tactic

#### Reconnaissance (AML.TA0001)

| Technique | Required Telemetry | Detection Method |
|-----------|-------------------|------------------|
| **Discover ML Artifacts** | API documentation access, model endpoint probing | Access pattern analysis |
| **Discover ML Model Ontology** | Model architecture queries, capability probing | Query anomaly detection |
| **Search for Victim's Publicly Available Research** | N/A (external) | Threat intelligence feeds |

**Key Telemetry:**
- API access logs with detailed request metadata
- Model endpoint query patterns
- Error response tracking (information leakage)

#### Resource Development (AML.TA0002)

| Technique | Required Telemetry | Detection Method |
|-----------|-------------------|------------------|
| **Acquire Public ML Artifacts** | N/A (external) | Supply chain monitoring |
| **Develop Adversarial ML Attacks** | N/A (external) | Threat intelligence |
| **Publish Poisoned Datasets** | Dataset download sources, integrity verification | Provenance tracking |

**Key Telemetry:**
- Dataset source verification logs
- Hash/signature verification events
- External dependency tracking

#### Initial Access (AML.TA0003)

| Technique | Required Telemetry | Detection Method |
|-----------|-------------------|------------------|
| **ML Supply Chain Compromise** | Component loading events, version changes | Integrity monitoring |
| **Valid Accounts** | Authentication events, API key usage | Access pattern analysis |
| **Prompt Injection (AML.T0051)** | All input prompts, output analysis | Pattern matching, anomaly detection |

**Key Telemetry:**
- Complete prompt logging (sanitized)
- Authentication and authorization events
- Supply chain component verification

#### ML Model Access (AML.TA0004)

| Technique | Required Telemetry | Detection Method |
|-----------|-------------------|------------------|
| **Inference API Access** | All API queries, response metadata | Rate/pattern analysis |
| **ML Artifact Collection** | Model file access attempts | Access control logs |
| **Physical Access to ML System** | Physical security logs | Badge/access card events |

**Key Telemetry:**
- Complete API query logs
- Model artifact access controls
- Query frequency and pattern metrics

#### ML Attack Staging (AML.TA0012)

| Technique | Required Telemetry | Detection Method |
|-----------|-------------------|------------------|
| **Poison Training Data (AML.T0020)** | Training data changes, quality metrics | Anomaly detection |
| **Backdoor ML Model** | Model behavior tests, trigger pattern scans | Behavioral monitoring |
| **Craft Adversarial Data** | Input pattern analysis | Statistical anomaly detection |
| **Create Proxy Model** | Query volume patterns | Excessive query detection |

**Key Telemetry:**
- Training data lineage and integrity
- Model performance over time
- Input distribution statistics
- Query rate and pattern metrics

#### Exfiltration (AML.TA0009)

| Technique | Required Telemetry | Detection Method |
|-----------|-------------------|------------------|
| **Exfiltrate via ML Inference API** | Response content analysis | Data leak detection |
| **Model Extraction via API** | Query patterns, response completeness | Extraction pattern detection |
| **Exfiltrate via AI Agent Tool Invocation** (New) | Agent tool calls, data access | Tool abuse detection |

**Key Telemetry:**
- Output content scanning
- Query-response pair analysis
- Tool invocation with data access logs

### New Agentic AI Techniques (October 2025)

| Technique | Required Telemetry | Detection Method |
|-----------|-------------------|------------------|
| **AI Agent Context Poisoning** | Memory/context modifications | Memory integrity monitoring |
| **Modify AI Agent Configuration** | Configuration changes | Config change audit |
| **RAG Credential Harvesting** | Credential access in RAG responses | Credential pattern detection |
| **Credentials from AI Agent Configuration** | Config access, credential extraction | Secret scanning |
| **Discover AI Agent Configuration** | Config probing queries | Query pattern analysis |
| **Data from AI Services** | Service data retrieval | Data access monitoring |
| **Exfiltration via AI Agent Tool Invocation** | Tool calls with data | Data flow analysis |

---

## 4. CSA AI Controls Matrix

### Overview
The Cloud Security Alliance AI Controls Matrix (AICM) provides 243 control objectives across 18 security domains for cloud-based AI systems. It extends the Cloud Controls Matrix (CCM v4) with AI-specific controls, including a dedicated Model Security (MDS) domain, and defines a shared responsibility model across four provider types: Cloud Service Provider (CSP), Model Provider (MP), Orchestrated Service Provider (OSP), and Application Provider (AP).

### 18 Control Domains

| Domain ID | Domain Name | Controls | AI Relevance |
|-----------|-------------|----------|--------------|
| **A&A** | Audit & Assurance | A&A-01 to A&A-06 | AI system audit trails, compliance evidence, third-party assessments |
| **AIS** | Application & Interface Security | AIS-01 to AIS-07 | LLM API security, prompt/completion interfaces, input validation |
| **BCR** | Business Continuity & Operational Resilience | BCR-01 to BCR-11 | AI service availability, model failover, inference redundancy |
| **CCC** | Change Control & Configuration Management | CCC-01 to CCC-09 | Model versioning, deployment pipeline changes, config drift |
| **CEK** | Cryptography, Encryption & Key Management | CEK-01 to CEK-21 | Encryption for training data, model weights, inference payloads |
| **DCS** | Datacenter Security | DCS-01 to DCS-09 | GPU cluster physical security, hardware tamper protection |
| **DSP** | Data Security & Privacy | DSP-01 to DSP-19 | Training data protection, PII in prompts, data classification |
| **GRC** | Governance, Risk Management & Compliance | GRC-01 to GRC-08 | AI governance policies, risk treatment, regulatory mapping |
| **HRS** | Human Resources Security | HRS-01 to HRS-13 | AI ethics training, security awareness, role-based access |
| **IAM** | Identity & Access Management | IAM-01 to IAM-16 | Agent identity, API auth, delegation chains, least privilege |
| **IPY** | Interoperability & Portability | IPY-01 to IPY-04 | Model format portability, vendor lock-in prevention |
| **IVS** | Infrastructure & Virtualization Security | IVS-01 to IVS-09 | GPU/TPU infrastructure, container isolation, network segmentation |
| **LOG** | Logging & Monitoring | LOG-01 to LOG-13 | AI event logging, inference audit trails, anomaly detection |
| **MDS** | Model Security | MDS-01 to MDS-05 | Model tampering, adversarial robustness, provenance, behavior monitoring |
| **SEF** | Security Incident Management & Forensics | SEF-01 to SEF-08 | AI incident response, breach notification, forensic analysis |
| **STA** | Supply Chain Management, Transparency & Accountability | STA-01 to STA-14 | Model provenance, AI-BOM, third-party model auditing |
| **TVM** | Threat & Vulnerability Management | TVM-01 to TVM-10 | AI-specific threat detection, adversarial testing, red teaming |
| **UEM** | Universal Endpoint Management | UEM-01 to UEM-15 | Edge AI device management, endpoint security |

### Logging, Monitoring, and Audit Controls

#### Audit Logging Domain (LOG)

| Control ID | Control Objective | Telemetry Requirement |
|-----------|------------------|----------------------|
| **LOG-01** | Audit Logging Policy | Define what AI events to log, review annually |
| **LOG-02** | Audit Logs Protection | Tamper-evident storage, retention policies |
| **LOG-03** | Audit Logs Access | Restrict access, maintain accountability records |
| **LOG-04** | Audit Logs Monitoring | Monitor for anomalies, define timely response |
| **LOG-05** | Log Records | Generate records with security-relevant info |
| **LOG-06** | Log Protection | Prevent unauthorized modification/deletion |
| **LOG-07** | Transaction/Activity Logging | Log key lifecycle events |
| **LOG-08** | Access Control Logs | Log and audit physical access |

#### Model Security Domain (MDS) — AI-Specific

| Control ID | Control Objective | Telemetry Requirement |
|-----------|------------------|----------------------|
| **MDS-01** | Model Tampering Protection | Monitor model integrity, detect unauthorized modifications |
| **MDS-02** | Adversarial Robustness | Track adversarial inputs, prompt injection attempts, robustness testing |
| **MDS-03** | Model Access Controls | Log model access patterns, detect extraction attempts |
| **MDS-04** | Model Provenance Tracking | Maintain model lineage, AI-BOM, supply chain integrity |
| **MDS-05** | Model Behavior Monitoring | Track inference patterns, detect drift, monitor agent behavior |

#### AITF Event Type to AICM Domain Mapping

| Event Type | Primary AICM Controls | Domain |
|------------|----------------------|--------|
| **Model Inference** | AIS-04, MDS-01, LOG-07 | Model Security |
| **Agent Activity** | AIS-02, MDS-05, GRC-02 | Governance, Risk & Compliance |
| **Tool Execution** | AIS-01, AIS-04, LOG-05 | Application & Interface Security |
| **Data Retrieval** | DSP-01, DSP-04, CEK-03 | Data Security & Privacy |
| **Security Finding** | SEF-03, TVM-01, LOG-04 | Security Incident Management |
| **Supply Chain** | STA-01, STA-03, CCC-01 | Supply Chain Management |
| **Governance** | GRC-01, A&A-01, LOG-01 | Governance, Risk & Compliance |
| **Identity** | IAM-01, IAM-02, IAM-04 | Identity & Access Management |

#### AI-Specific Security Domains

| Domain | Telemetry Focus | Key Controls |
|--------|----------------|--------------|
| **Model Manipulation** | Model behavior monitoring | MDS-01, MDS-05 — Performance drift detection |
| **Data Poisoning** | Training data integrity | DSP-01, DSP-04 — Data lineage, quality monitoring |
| **Sensitive Data Disclosure** | Output scanning | DSP-01, CEK-03 — DLP integration, redaction audit |
| **Model Theft** | Access and query monitoring | MDS-03, IAM-04 — Extraction pattern detection |
| **Service Failures** | Availability monitoring | BCR-01 — Error rates, SLA compliance |
| **Insecure Supply Chains** | Component tracking | STA-01, STA-03 — SBOM, integrity verification |
| **Insecure Apps/Plugins** | Integration monitoring | AIS-01, AIS-04 — API security, plugin audit |
| **Denial of Service** | Resource monitoring | IVS-01, TVM-01 — Rate limiting, capacity alerts |
| **Loss of Governance/Compliance** | Audit trails | GRC-01, A&A-01 — Regulatory evidence collection |

#### Shared Responsibility Model

| Responsibility | Cloud Service Provider | Model Provider | Orchestrated Service Provider | Application Provider |
|---------------|----------------------|----------------|-------------------------------|---------------------|
| **Infrastructure** | Physical security, network logs | GPU cluster | Orchestration layer | Application logs |
| **Model Operations** | Hosting infrastructure | Training, fine-tuning, serving | Model routing, composition | Inference integration |
| **Data Security** | Storage encryption | Training data protection | Data pipeline security | Input/output filtering |
| **Identity** | IAM infrastructure | Model access controls | Service-to-service auth | User/agent authentication |
| **Logging** | Infrastructure logs | Model operation logs | Orchestration audit trails | Application telemetry |

#### Five Critical Pillars

Each AICM control is analyzed through five critical pillars:

1. **Control Type Classification** — AI-specific, hybrid AI-cloud, or traditional cloud controls
2. **Control Applicability and Ownership** — Shared responsibility across CSP, MP, OSP, AP
3. **Architectural Relevance** — Physical, network, compute, storage, application, and data layers
4. **LLM Lifecycle Relevance** — Preparation, Development, Deployment, Operation, Retirement
5. **Threat Category** — Mapping to specific AI threat vectors (OWASP LLM, MITRE ATLAS)

### AICM Audit Guidelines

The framework includes implementation and auditing guidelines mapped to:
- ISO 42001:2023
- ISO 27001
- NIST AI RMF 1.0
- EU AI Act
- OWASP Top 10 for LLM Applications
- MITRE ATLAS

---

## 5. NIST AI Risk Management Framework

### Overview
The NIST AI RMF provides a structured approach across four functions: GOVERN, MAP, MEASURE, and MANAGE. Telemetry requirements are embedded throughout.

### Telemetry by Function

#### GOVERN Function

| Sub-function | Telemetry Requirement | Purpose |
|-------------|----------------------|---------|
| **GOVERN 1.1** | Policy compliance monitoring | Governance effectiveness |
| **GOVERN 1.2** | Accountability tracking | Responsibility verification |
| **GOVERN 1.3** | Risk management process logs | Process adherence |
| **GOVERN 2** | AI system inventory | Asset management |
| **GOVERN 3** | Workforce competency records | Training compliance |
| **GOVERN 4** | Organizational culture metrics | Adoption tracking |
| **GOVERN 5** | Third-party assessment logs | Supply chain governance |
| **GOVERN 6** | Policy review records | Continuous improvement |

#### MAP Function

| Sub-function | Telemetry Requirement | Purpose |
|-------------|----------------------|---------|
| **MAP 1.1** | System context documentation | Risk contextualization |
| **MAP 1.2** | Intended use tracking | Scope verification |
| **MAP 1.3** | Benefit-cost analysis logs | Value assessment |
| **MAP 1.4** | Stakeholder input records | Inclusive development |
| **MAP 1.5** | Risk tolerance thresholds | Boundary definition |
| **MAP 2** | Use case categorization | Risk prioritization |
| **MAP 3** | Data property documentation | Data understanding |
| **MAP 4** | Impact assessment records | Harm potential |
| **MAP 5** | Dependency mapping | System understanding |

#### MEASURE Function

| Sub-function | Telemetry Requirement | Purpose |
|-------------|----------------------|---------|
| **MEASURE 1.1** | Metric collection pipelines | Performance tracking |
| **MEASURE 1.2** | Measurement methodology logs | Validity assurance |
| **MEASURE 1.3** | Threshold monitoring | Boundary alerts |
| **MEASURE 2.1** | Validity/reliability metrics | Quality assurance |
| **MEASURE 2.2** | Safety metrics | Harm prevention |
| **MEASURE 2.3** | Security monitoring | Threat detection |
| **MEASURE 2.4** | Resilience metrics | System robustness |
| **MEASURE 2.5** | Accountability logs | Responsibility tracking |
| **MEASURE 2.6** | Transparency metrics | Explainability |
| **MEASURE 2.7** | Privacy metrics | Data protection |
| **MEASURE 2.8** | Fairness/bias monitoring | Equity assurance |
| **MEASURE 2.9** | Environmental impact | Sustainability |
| **MEASURE 3** | Risk tracking logs | Identified risk monitoring |
| **MEASURE 4** | Feedback collection | Measurement improvement |

**Key Telemetry Tools:**
- Bias-scanning pipelines
- Drift detection modules
- Security testing automation
- Explainability dashboards

#### MANAGE Function

| Sub-function | Telemetry Requirement | Purpose |
|-------------|----------------------|---------|
| **MANAGE 1** | Risk prioritization records | Response planning |
| **MANAGE 2** | Mitigation implementation logs | Control verification |
| **MANAGE 3** | Deployment monitoring | Production tracking |
| **MANAGE 4** | Incident response logs | Event handling |

### NIST Generative AI Profile (AI 600-1)

Additional telemetry for GenAI risks:

| Risk Category | Required Telemetry |
|--------------|-------------------|
| **Confabulation** | Hallucination rate tracking, factual verification |
| **Dangerous Content** | Content filtering logs, flagged outputs |
| **Data Privacy** | PII detection, privacy incident logs |
| **Information Integrity** | Source verification, misinformation detection |
| **Homogenization** | Diversity metrics across outputs |
| **Human-AI Configuration** | Interaction logs, decision attribution |
| **Environmental Impact** | Compute resource utilization |

---

## 6. ISO/IEC 42001

### Overview
ISO/IEC 42001:2023 is the first international standard for AI Management Systems (AIMS), requiring tamper-evident, lifecycle-mapped, and auditable event trails.

### Audit and Logging Requirements by Clause

#### Clause 7.5 - Documented Information

| Requirement | Telemetry Implementation |
|------------|-------------------------|
| **Model cards** | Version-controlled model documentation |
| **Audit logs** | Comprehensive system event logging |
| **Decision records** | AI decision audit trail |
| **Compliance reports** | Automated compliance evidence |

#### Clause 9.1 - Monitoring, Measurement, Analysis, Evaluation

| Requirement | Telemetry Implementation |
|------------|-------------------------|
| **Performance monitoring** | Model accuracy, latency, throughput |
| **Compliance monitoring** | Regulatory adherence tracking |
| **Effectiveness evaluation** | Control verification logs |
| **Continuous assessment** | Real-time dashboards |

#### Clause 9.2 - Internal Audit

| Requirement | Telemetry Implementation |
|------------|-------------------------|
| **Audit program logs** | Audit schedule, scope, methods |
| **Audit findings** | Non-conformity records |
| **Corrective actions** | Remediation tracking |
| **Auditor independence** | Assignment records |

#### Annex A Controls - Telemetry Requirements

| Control | Logging Requirement | Threat Addressed |
|---------|-------------------|-----------------|
| **A.5.1 - Deployment** | Deployment event logs | Information disclosure |
| **A.6.2.8 - Event Logging** | Comprehensive AI event trails | Repudiation, all threats |
| **A.7.1 - Verification** | Model decision logs | Repudiation |
| **A.10.3 - Operation & Monitoring** | Operational telemetry | Denial of service |

### ISO 42001 A.6.2.8 - AI System Recording of Event Logs

This is the primary control for telemetry. Requirements include:

| Requirement | Description |
|------------|-------------|
| **Tamper-evidence** | Logs must be protected from modification |
| **Lifecycle mapping** | Events tracked across all AI lifecycle stages |
| **Auditability** | Logs must support external audit |
| **Completeness** | Every significant event must be logged |
| **Immutability** | WORM storage or cryptographic signing |

### AI Lifecycle Event Logging

| Lifecycle Stage | Events to Log |
|----------------|---------------|
| **Preparation** | Requirements, data collection plans |
| **Development** | Training runs, hyperparameters, datasets |
| **Evaluation** | Test results, validation metrics |
| **Deployment** | Release events, configuration changes |
| **Delivery** | User interactions, inference requests |
| **Retirement** | Decommissioning, data disposal |

---

## 7. Cross-Framework Telemetry Mapping

### Common Telemetry Categories

| Category | OWASP LLM | OWASP Agentic | ATLAS | CSA | NIST | ISO 42001 |
|----------|-----------|---------------|-------|-----|------|-----------|
| **Input/Prompt Logging** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Output Monitoring** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Tool/Action Audit** | ✓ | ✓✓ | ✓ | ✓ | ✓ | ✓ |
| **Model Performance** | ✓ | ✓ | ✓ | ✓ | ✓✓ | ✓ |
| **Data Lineage** | ✓ | ✓ | ✓✓ | ✓ | ✓ | ✓ |
| **Security Events** | ✓ | ✓ | ✓✓ | ✓✓ | ✓ | ✓ |
| **Resource Consumption** | ✓✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Identity/Access** | ✓ | ✓✓ | ✓ | ✓✓ | ✓ | ✓ |
| **Agent Communication** | - | ✓✓ | ✓✓ | ✓ | ✓ | ✓ |
| **Compliance Evidence** | ✓ | ✓ | ✓ | ✓✓ | ✓✓ | ✓✓ |

### Unified Telemetry Schema Recommendations

```json
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "event_type": "enum",
  "ai_system_id": "string",
  "component": {
    "type": "model|agent|tool|pipeline",
    "name": "string",
    "version": "semver"
  },
  "actor": {
    "type": "user|agent|system",
    "id": "string",
    "session_id": "string"
  },
  "action": {
    "type": "inference|training|tool_call|config_change",
    "details": "object"
  },
  "input": {
    "type": "prompt|data|file",
    "hash": "sha256",
    "sanitized_content": "string"
  },
  "output": {
    "type": "response|action|artifact",
    "hash": "sha256",
    "metrics": "object"
  },
  "security": {
    "threat_indicators": ["string"],
    "risk_score": "float",
    "mitigations_applied": ["string"]
  },
  "compliance": {
    "frameworks": ["OWASP", "NIST", "ISO42001"],
    "controls_satisfied": ["string"]
  },
  "metadata": {
    "environment": "string",
    "region": "string",
    "tags": ["string"]
  }
}
```

---

## 8. Implementation Recommendations

### Priority Telemetry by Risk Level

#### Critical (Implement Immediately)

| Telemetry Type | Frameworks Requiring | Rationale |
|---------------|---------------------|-----------|
| **Complete prompt/input logging** | All | Foundation for all detection |
| **Output scanning and logging** | All | Data leakage prevention |
| **Tool/action invocation logs** | OWASP Agentic, ATLAS | Agency control |
| **Authentication/authorization** | All | Access control verification |
| **Model integrity verification** | ATLAS, ISO 42001 | Supply chain security |

#### High (Implement Within 30 Days)

| Telemetry Type | Frameworks Requiring | Rationale |
|---------------|---------------------|-----------|
| **Performance/drift monitoring** | NIST, ISO 42001 | Model degradation |
| **Resource consumption metrics** | OWASP LLM, CSA | DoS prevention |
| **Inter-agent communication** | OWASP Agentic, ATLAS | Multi-agent security |
| **Memory/context tracking** | OWASP Agentic, ATLAS | Poisoning detection |
| **Data lineage tracking** | All | Provenance verification |

#### Medium (Implement Within 90 Days)

| Telemetry Type | Frameworks Requiring | Rationale |
|---------------|---------------------|-----------|
| **Bias/fairness metrics** | NIST | Equity assurance |
| **Explainability logs** | NIST, ISO 42001 | Transparency |
| **Environmental metrics** | NIST | Sustainability |
| **User feedback collection** | NIST | Continuous improvement |

### Compliance Evidence Matrix

| Framework | Primary Evidence | Retention Period |
|-----------|-----------------|-----------------|
| **OWASP LLM** | Incident detection logs, mitigation records | 1 year minimum |
| **OWASP Agentic** | Tool audit trails, agent behavior logs | 1 year minimum |
| **MITRE ATLAS** | Attack detection logs, threat intelligence | 2 years |
| **CSA AICM** | Control implementation evidence | Per regulatory requirement |
| **NIST AI RMF** | Risk assessment documentation | Life of system + 3 years |
| **ISO 42001** | Complete audit trails, management review | 3 years minimum |

### Tooling Recommendations

| Category | Recommended Capabilities |
|----------|------------------------|
| **Log Collection** | Structured logging, real-time streaming, PII masking |
| **SIEM Integration** | AI-specific detection rules, ATLAS/ATT&CK mapping |
| **Observability** | Distributed tracing, metric aggregation, anomaly detection |
| **Compliance** | Automated evidence collection, control mapping, audit reports |
| **Drift Detection** | Statistical monitoring, performance baselines, alerting |

---

## Appendix: Quick Reference Cards

### OWASP LLM 2025 - Detection Checklist

- [ ] Prompt injection pattern detection
- [ ] Sensitive data output scanning
- [ ] Supply chain integrity verification
- [ ] Training data anomaly detection
- [ ] Output sanitization validation
- [ ] Tool permission enforcement
- [ ] System prompt leak detection
- [ ] Vector database access monitoring
- [ ] Hallucination rate tracking
- [ ] Resource consumption alerting

### OWASP Agentic 2026 - Detection Checklist

- [ ] Goal modification monitoring
- [ ] Tool invocation audit
- [ ] Credential lifecycle tracking
- [ ] Component integrity verification
- [ ] Code execution sandboxing
- [ ] Memory poisoning detection
- [ ] Inter-agent authentication
- [ ] Cascading failure isolation
- [ ] Trust exploitation indicators
- [ ] Rogue agent behavioral detection

### MITRE ATLAS - Key Detection Points

- [ ] API query pattern analysis
- [ ] Model artifact access logging
- [ ] Training data integrity monitoring
- [ ] Adversarial input detection
- [ ] Extraction attempt identification
- [ ] Agent context poisoning alerts
- [ ] Configuration change monitoring
- [ ] Credential harvesting detection

---

*Document Version: 1.0*  
*Last Updated: February 6, 2026*  
*Sources: OWASP GenAI, MITRE ATLAS, CSA, NIST, ISO*
