# AITF Compliance Framework Mapping

AITF automatically maps AI telemetry events to eight regulatory and security frameworks.

## Overview

Every OCSF event produced by AITF is enriched with compliance metadata, mapping the event to relevant controls across multiple frameworks. This enables automated compliance reporting and audit trail generation.

## Framework Coverage Matrix

| AI Event Type | NIST AI RMF | MITRE ATLAS | ISO 42001 | EU AI Act | SOC 2 | GDPR | CCPA | CSA AICM |
|---------------|-------------|-------------|-----------|-----------|-------|------|------|----------|
| Model Inference | MAP-1.1, MEASURE-2.5 | AML.T0040 | 6.1.4, 8.4 | Art. 13, 15 | CC6.1 | Art. 5, 22 | 1798.100 | MDS-01..11/13, AIS-03..09/12/14/15, LOG-07/08/13..15, GRC-13..15, TVM-11, DSP-07 (32 controls) |
| Agent Activity | GOVERN-1.2, MANAGE-3.1 | AML.T0048 | 8.2, A.6.2.5 | Art. 14, 52 | CC7.2 | Art. 22 | - | AIS-02/11/13, IAM-04/05/16/19, GRC-09/10/15, LOG-05/11, MDS-10 (13 controls) |
| Tool Execution | MAP-3.5, MANAGE-4.2 | AML.T0043 | A.6.2.7 | Art. 9 | CC6.3 | Art. 25 | - | AIS-01/04/08/09/10/13, IAM-05/16, LOG-05/11, TVM-05/11 (12 controls) |
| Data Retrieval | MAP-1.5, MEASURE-2.7 | AML.T0025 | A.7.4 | Art. 10 | CC6.1 | Art. 5, 6 | 1798.100 | DSP-01..24, CEK-03, LOG-07/10 (27 controls) |
| Security Finding | MANAGE-2.4, MANAGE-4.1 | AML.T0051 | 6.1.2, A.6.2.4 | Art. 9, 62 | CC7.2, CC7.3 | Art. 32, 33 | 1798.150 | SEF-01..09, TVM-01..04/06..13, LOG-02..04/12, MDS-06/07 (27 controls) |
| Supply Chain | MAP-5.2, GOVERN-6.1 | AML.T0010 | A.6.2.3 | Art. 15, 28 | CC9.2 | Art. 28 | - | STA-01..16, CCC-01..09, MDS-08/09/12/13, DCS-01..15, IPY-01..04, I&S-01..09 (57 controls) |
| Governance | GOVERN-1.1, MANAGE-1.3 | - | 5.1, 9.1 | Art. 9, 61 | CC1.2 | Art. 5 | 1798.185 | GRC-01..15, A&A-01..06, BCR-01..11, HRS-01..15, LOG-01/06, DSP-01 (50 controls) |
| Identity | GOVERN-1.5, MANAGE-2.1 | AML.T0052 | A.6.2.6 | Art. 9 | CC6.1, CC6.2 | Art. 32 | 1798.140 | IAM-01..19, CEK-01..21, LOG-04/09, UEM-01..14 (56 controls) |

---

## Framework Details

### 1. NIST AI RMF (AI Risk Management Framework)

The NIST AI RMF provides a structured approach to managing AI risks.

#### GOVERN Function

| Control | Description | Triggered By |
|---------|-------------|-------------|
| GOVERN-1.1 | AI risk management policies established | Governance events |
| GOVERN-1.2 | Responsibility and accountability assigned | Agent activity, delegation |
| GOVERN-1.5 | Ongoing monitoring mechanisms | Identity, auth events |
| GOVERN-6.1 | Policies for third-party AI | Supply chain events |

#### MAP Function

| Control | Description | Triggered By |
|---------|-------------|-------------|
| MAP-1.1 | Intended purpose documented | Model inference events |
| MAP-1.5 | AI limitations identified | Data retrieval, quality events |
| MAP-3.5 | Scientific integrity maintained | Tool execution events |
| MAP-5.2 | Third-party components identified | Supply chain events |

#### MEASURE Function

| Control | Description | Triggered By |
|---------|-------------|-------------|
| MEASURE-2.5 | Performance monitoring | Model inference, quality metrics |
| MEASURE-2.7 | AI system fairness assessed | Data retrieval, bias detection |

#### MANAGE Function

| Control | Description | Triggered By |
|---------|-------------|-------------|
| MANAGE-1.3 | Risk treatment applied | Governance events |
| MANAGE-2.1 | Access controls implemented | Identity events |
| MANAGE-2.4 | Mechanisms for feedback | Security findings |
| MANAGE-3.1 | Incidents managed | Agent errors, security events |
| MANAGE-4.1 | Post-deployment monitoring | Security findings |
| MANAGE-4.2 | Post-deployment activity managed | Tool execution events |

---

### 2. MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

MITRE ATLAS catalogs adversarial techniques against AI systems.

| Technique | Description | Detected From |
|-----------|-------------|---------------|
| AML.T0010 | ML Supply Chain Compromise | Supply chain events |
| AML.T0020 | Poison Training Data | Data poisoning detection |
| AML.T0025 | Exfiltration via ML Inference API | Data retrieval anomalies |
| AML.T0040 | ML Model Inference API Access | Inference monitoring |
| AML.T0043 | Craft Adversarial Data | Tool execution, input analysis |
| AML.T0048 | Command and Control via AI | Agent activity patterns |
| AML.T0051 | LLM Prompt Injection | Prompt injection detection |
| AML.T0052 | Phishing via AI | Identity, social engineering |
| AML.T0054 | LLM Jailbreak | Jailbreak attempt detection |

---

### 3. ISO/IEC 42001 (AI Management System)

| Control | Description | Triggered By |
|---------|-------------|-------------|
| 5.1 | Leadership commitment | Governance events |
| 6.1.2 | AI risk assessment | Security findings |
| 6.1.4 | AI risk treatment | Inference controls |
| 8.2 | AI system lifecycle | Agent activity |
| 8.4 | AI system operation | Inference events |
| 9.1 | Monitoring and measurement | All telemetry |
| A.6.2.3 | Third-party management | Supply chain events |
| A.6.2.4 | AI security controls | Security findings |
| A.6.2.5 | AI system transparency | Agent activity |
| A.6.2.6 | Access control for AI | Identity events |
| A.6.2.7 | AI tool management | Tool execution |
| A.7.4 | Data management for AI | Data retrieval |

---

### 4. EU AI Act

| Article | Description | Triggered By |
|---------|-------------|-------------|
| Art. 9 | Risk management system | Security findings, governance, identity |
| Art. 10 | Data governance | Data retrieval events |
| Art. 13 | Transparency | Inference events, model info |
| Art. 14 | Human oversight | Agent activity, human-in-loop |
| Art. 15 | Accuracy, robustness, security | Inference quality, supply chain |
| Art. 28 | Obligations of deployers | Supply chain events |
| Art. 52 | Transparency obligations | Agent interaction disclosure |
| Art. 61 | Post-market monitoring | Governance events |
| Art. 62 | Reporting serious incidents | Security findings |

---

### 5. SOC 2

| Control | Description | Triggered By |
|---------|-------------|-------------|
| CC1.2 | Board oversight | Governance events |
| CC6.1 | Logical access controls | Inference, identity, data retrieval |
| CC6.2 | User authentication | Identity events |
| CC6.3 | Access authorization | Tool execution, permissions |
| CC7.2 | Monitoring for anomalies | Security findings, agent activity |
| CC7.3 | Evaluation of security events | Security findings |
| CC9.2 | Vendor management | Supply chain events |

---

### 6. GDPR (General Data Protection Regulation)

| Article | Description | Triggered By |
|---------|-------------|-------------|
| Art. 5 | Principles of processing | Inference, data retrieval, governance |
| Art. 6 | Lawfulness of processing | Data retrieval events |
| Art. 22 | Automated decision-making | Inference, agent activity |
| Art. 25 | Data protection by design | Tool execution, PII detection |
| Art. 28 | Processor obligations | Supply chain events |
| Art. 32 | Security of processing | Security findings, identity |
| Art. 33 | Notification of breach | Security findings (critical) |

---

### 7. CCPA (California Consumer Privacy Act)

| Section | Description | Triggered By |
|---------|-------------|-------------|
| 1798.100 | Right to know | Inference, data retrieval |
| 1798.105 | Right to delete | Data management events |
| 1798.140 | Definition of personal info | Identity, PII detection |
| 1798.150 | Private right of action | Security findings (breach) |
| 1798.185 | Rulemaking authority | Governance events |

---

### 8. CSA AI Controls Matrix (AICM) v1.0.3

The Cloud Security Alliance AI Controls Matrix (AICM) v1.0.3 provides **243 control objectives** across **18 security domains** for cloud-based AI systems. It extends the Cloud Controls Matrix (CCM v4) with **34 AI-Specific controls** and **196 Cloud & AI Related controls**, along with a shared responsibility model across four provider types: Processing Infrastructure (PI), Model Provider, Orchestrated Service Provider, and Application Provider.

AITF maps **all 243 AICM controls** across all 8 event types, covering **all 18 domains** with 100% control coverage.

#### 18 Control Domains

| Domain ID | Domain Name | Controls | AI-Specific | AITF Event Type(s) |
|-----------|-------------|----------|-------------|---------------------|
| A&A | Audit & Assurance | 6 | 0 | governance |
| AIS | Application & Interface Security | 15 | 6 (AIS-08, 09, 11, 13, 14, 15) | model_inference, agent_activity, tool_execution |
| BCR | Business Continuity & Operational Resilience | 11 | 0 | governance |
| CCC | Change Control & Configuration Management | 9 | 0 | supply_chain |
| CEK | Cryptography, Encryption & Key Management | 21 | 0 | data_retrieval, identity |
| DCS | Datacenter Security | 15 | 0 | supply_chain |
| DSP | Data Security & Privacy | 24 | 4 (DSP-21, 22, 23, 24) | data_retrieval, governance |
| GRC | Governance, Risk & Compliance | 15 | 7 (GRC-09..15) | governance, model_inference, agent_activity |
| HRS | Human Resources | 15 | 2 (HRS-14, 15) | governance |
| I&S | Infrastructure Security | 9 | 0 | supply_chain |
| IAM | Identity & Access Management | 19 | 1 (IAM-18) | identity, agent_activity, tool_execution |
| IPY | Interoperability & Portability | 4 | 0 | supply_chain |
| LOG | Logging & Monitoring | 15 | 2 (LOG-14, 15) | model_inference, security_finding, governance |
| MDS | Model Security | 13 | 10 (MDS-02..08, 11, 12) | model_inference, security_finding, supply_chain |
| SEF | Security Incident Management & Forensics | 9 | 0 | security_finding |
| STA | Supply Chain Management & Accountability | 16 | 1 (STA-16) | supply_chain |
| TVM | Threat & Vulnerability Management | 13 | 2 (TVM-11, 12) | security_finding, tool_execution |
| UEM | Universal Endpoint Management | 14 | 0 | identity |

#### AI-Specific Controls (34 total)

These controls are unique to AI systems and have no equivalent in the traditional CCM:

| Control | Title | Domain | Threat Categories |
|---------|-------|--------|-------------------|
| AIS-08 | Input Validation | AIS | Model manipulation, data poisoning, prompt injection |
| AIS-09 | Output Validation | AIS | Sensitive data disclosure, model manipulation |
| AIS-11 | Agents Security Boundaries | AIS | Agent lateral movement, privilege escalation |
| AIS-13 | AI Sandboxing | AIS | Tool isolation, lateral movement prevention |
| AIS-14 | AI Cache Protection | AIS | Cache poisoning, data leakage |
| AIS-15 | Prompt Differentiation | AIS | Prompt injection, instruction confusion |
| DSP-21 | Data Poisoning Prevention & Detection | DSP | Training data integrity |
| DSP-22 | Privacy Enhancing Technologies | DSP | PII in training data |
| DSP-23 | Data Integrity Check | DSP | Dataset versioning, unauthorized changes |
| DSP-24 | Data Differentiation and Relevance | DSP | Training data quality |
| GRC-09 | Acceptable Use of the AI Service | GRC | Misuse prevention |
| GRC-10 | AI Impact Assessment | GRC | Ethical, societal, operational impacts |
| GRC-11 | Bias and Fairness Assessment | GRC | Algorithmic bias, fairness |
| GRC-12 | Ethics Committee | GRC | Ethical AI alignment |
| GRC-13 | Explainability Requirement | GRC | Model transparency |
| GRC-14 | Explainability Evaluation | GRC | XAI measurement |
| GRC-15 | Human Supervision | GRC | Human oversight and control |
| HRS-14 | AI Competency Training | HRS | Personnel AI awareness |
| HRS-15 | AI Acceptable Use | HRS | Organizational AI policies |
| IAM-18 | Output Modification Authorization | IAM | Authorized output changes |
| LOG-14 | Input Monitoring | LOG | Prompt/input auditing |
| LOG-15 | Output Monitoring | LOG | Completion/output auditing |
| MDS-02 | Model Artifact Scanning | MDS | Vulnerability scanning |
| MDS-03 | Model Documentation | MDS | Model cards, documentation |
| MDS-04 | Model Documentation Requirements | MDS | Documentation standards |
| MDS-05 | Model Documentation Validation | MDS | Documentation accuracy |
| MDS-06 | Adversarial Attack Analysis | MDS | Threat modeling for models |
| MDS-07 | Model Hardening | MDS | Adversarial robustness |
| MDS-08 | Model Integrity Checks | MDS | Checksum verification |
| MDS-11 | Model Failure | MDS | Failure risk evaluation |
| MDS-12 | Open Model Risk Assessment | MDS | Open-source model risks |
| STA-16 | Service Bill of Material (BOM) | STA | AI-BOM, supply chain transparency |
| TVM-11 | Guardrails | TVM | Content filtering, safety checks |
| TVM-12 | Threat Analysis and Modelling | TVM | AI-specific threat models |

#### AITF Event Type to AICM Mapping

| Event Type | Primary Domain | Controls | Count |
|------------|---------------|----------|-------|
| model_inference | Model Security (MDS) | MDS-01..11/13, AIS-03..09/12/14/15, LOG-07/08/13..15, GRC-13..15, TVM-11, DSP-07 | 32 |
| agent_activity | Application & Interface Security (AIS) | AIS-02/11/13, IAM-04/05/16/19, GRC-09/10/15, LOG-05/11, MDS-10 | 13 |
| tool_execution | Application & Interface Security (AIS) | AIS-01/04/08/09/10/13, IAM-05/16, LOG-05/11, TVM-05/11 | 12 |
| data_retrieval | Data Security & Privacy (DSP) | DSP-01..24, CEK-03, LOG-07/10 | 27 |
| security_finding | Security Incident Management (SEF) | SEF-01..09, TVM-01..04/06..13, LOG-02..04/12, MDS-06/07 | 27 |
| supply_chain | Supply Chain Management (STA) | STA-01..16, CCC-01..09, MDS-08/09/12/13, DCS-01..15, IPY-01..04, I&S-01..09 | 57 |
| governance | Governance, Risk & Compliance (GRC) | GRC-01..15, A&A-01..06, BCR-01..11, HRS-01..15, LOG-01/06, DSP-01 | 50 |
| identity | Identity & Access Management (IAM) | IAM-01..19, CEK-01..21, LOG-04/09, UEM-01..14 | 56 |

#### Nine AICM Threat Categories

Each AICM control maps to one or more of these threat categories (from the AICM v1.0.3 spreadsheet):

1. **Model Manipulation** — Adversarial attacks on model behavior (114 controls)
2. **Data Poisoning** — Corruption of training/fine-tuning data (117 controls)
3. **Sensitive Data Disclosure** — Leakage of PII or confidential data (209 controls)
4. **Model Theft** — Unauthorized model extraction or copying (124 controls)
5. **Model/Service Failure** — Degradation or outage of AI services (164 controls)
6. **Insecure Supply Chain** — Compromised models, datasets, or dependencies (172 controls)
7. **Insecure Apps/Plugins** — Vulnerable AI applications and integrations (153 controls)
8. **Denial of Service (DoS)** — Resource exhaustion or availability attacks (128 controls)
9. **Loss of Governance/Compliance** — Regulatory or policy violations (232 controls)

#### Five Critical Pillars

Each AICM control is analyzed through:

1. **Control Type Classification** — AI-Specific (34 controls) or Cloud & AI Related (196 controls)
2. **Control Applicability and Ownership** — Shared responsibility across Processing Infrastructure (PI), Model Provider, Orchestrated Service Provider, Application Provider
3. **Architectural Relevance** — Physical, network, compute, storage, application, and data layers
4. **LLM Lifecycle Relevance** — Preparation, Development, Evaluation/Validation, Deployment, Delivery, Service Retirement
5. **Threat Category** — Mapping to the 9 AI threat vectors above

---

## Compliance Event Format

Each OCSF event includes a `compliance` field:

```json
{
  "compliance": {
    "nist_ai_rmf": {
      "controls": ["MAP-1.1", "MEASURE-2.5"],
      "function": "MAP"
    },
    "mitre_atlas": {
      "techniques": ["AML.T0040"],
      "tactic": "ML Attack Staging"
    },
    "iso_42001": {
      "controls": ["6.1.4", "8.4"],
      "clause": "Operation"
    },
    "eu_ai_act": {
      "articles": ["Article 13", "Article 15"],
      "risk_level": "high"
    },
    "soc2": {
      "controls": ["CC6.1"],
      "criteria": "Common Criteria"
    },
    "gdpr": {
      "articles": ["Article 5", "Article 22"],
      "lawful_basis": "legitimate_interest"
    },
    "ccpa": {
      "sections": ["1798.100"],
      "category": "personal_information"
    },
    "csa_aicm": {
      "controls": [
        "MDS-01", "MDS-02", "MDS-06", "MDS-07", "MDS-08", "MDS-09",
        "MDS-10", "MDS-11", "MDS-13", "AIS-04", "AIS-08", "AIS-09",
        "AIS-14", "AIS-15", "LOG-07", "LOG-08", "LOG-14", "LOG-15",
        "GRC-13", "GRC-14", "GRC-15", "TVM-11", "DSP-07"
      ],
      "domain": "Model Security",
      "domains": ["MDS", "AIS", "LOG", "GRC", "TVM", "DSP"]
    }
  }
}
```

## Audit Record Generation

AITF can generate audit records from compliance events:

```json
{
  "audit_id": "aud-abc123",
  "timestamp": "2026-02-15T10:30:00Z",
  "event_type": "model_inference",
  "ocsf_class_uid": 7001,
  "frameworks_mapped": 8,
  "controls_mapped": 33,
  "violations_detected": 0,
  "risk_score": 15.0,
  "actor": {"user": "analyst@example.com"},
  "model": {"name": "gpt-4o", "provider": "openai"},
  "compliance_details": {
    "nist_ai_rmf": ["MAP-1.1", "MEASURE-2.5"],
    "eu_ai_act": ["Article 13"]
  }
}
```
