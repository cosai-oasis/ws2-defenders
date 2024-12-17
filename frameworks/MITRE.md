<!-- TOC start -->

- [MITRE](#mitre)
- [1. ATT\&CK](#1-attck)
  - [2.1. Overview](#21-overview)
    - [2.1.1. Scoping of AI system and/or cybersecurity purview](#211-scoping-of-ai-system-andor-cybersecurity-purview)
    - [2.1.2. Persona addressed](#212-persona-addressed)
    - [2.1.3. Guidance provided](#213-guidance-provided)
  - [2.2. Detail on current framework](#22-detail-on-current-framework)
  - [2.3. What is missing for defenders of AI systems](#23-what-is-missing-for-defenders-of-ai-systems)
- [2. ATLAS](#2-atlas)
  - [2.1. Overview](#21-overview-1)
    - [2.1.1. Scoping of AI system and/or cybersecurity purview](#211-scoping-of-ai-system-andor-cybersecurity-purview-1)
    - [2.1.2. Persona addressed](#212-persona-addressed-1)
    - [2.1.3. Guidance provided](#213-guidance-provided-1)
  - [2.2. Detail on current framework](#22-detail-on-current-framework-1)
    - [2.2.1. ATLAS Matrix](#221-atlas-matrix)
    - [2.2.2. Core Components](#222-core-components)
      - [2.2.2.1. Tactics](#2221-tactics)
      - [2.2.2.2. Techniques](#2222-techniques)
      - [2.2.2.3. Procedures](#2223-procedures)
    - [2.2.3. Attack Surface](#223-attack-surface)
    - [2.2.4. Threat Mitigation](#224-threat-mitigation)
  - [2.3. What is missing for defenders of AI systems](#23-what-is-missing-for-defenders-of-ai-systems-1)
- [3. CAPEC](#3-capec)
  - [2.1. Overview](#21-overview-2)
    - [2.1.1. Scoping of AI system and/or cybersecurity purview](#211-scoping-of-ai-system-andor-cybersecurity-purview-2)
    - [2.1.2. Persona addressed](#212-persona-addressed-2)
    - [2.1.3. Guidance provided](#213-guidance-provided-2)
  - [2.2. Detail on current framework](#22-detail-on-current-framework-2)
  - [2.3. What is missing for defenders of AI systems](#23-what-is-missing-for-defenders-of-ai-systems-2)
- [4. References](#4-references)

<!-- TOC end -->

<!-- TOC --><a name="mitre"></a>
## MITRE

<!-- TOC --><a name="1-attck"></a>
## 1. ATT&CK

<!-- TOC --><a name="21-overview"></a>
### 2.1. Overview

The MITRE ATT&CK framework is a globally recognized, open-source knowledge base that documents real-world adversary tactics, techniques, and procedures (TTPs) across the cyber-attack lifecycle. It organizes adversary behaviors into tactics (what attackers aim to achieve) and techniques/sub-techniques (how they do it), mapped into an intuitive matrix that spans multiple domains, including enterprise, mobile, cloud, and industrial control systems (ICS). Originally focused on post-attack activities, it now also includes early-stage attacker actions like reconnaissance. 

ATT&CK serves as a practical tool for red teaming, behavioral analytics, threat intelligence enrichment, and defensive gap assessments, linking techniques to adversary groups, software, and mitigations. It provides a practical, data-driven guide to strengthening defenses against real-world threats.

<!-- TOC --><a name="211-scoping-of-ai-system-andor-cybersecurity-purview"></a>
#### 2.1.1. Scoping of AI system and/or cybersecurity purview

The MITRE ATT&CK framework provides a structured approach for identifying, analyzing, and addressing threats in AI systems and cybersecurity. Scoping ATT&CK for AI systems involves adapting the framework's tactics and techniques to the unique aspects of AI, while integrating it into the broader cybersecurity purview.

***Components of AI Systems and Relevant ATT&CK Techniques***

| **Component**       | **Description**                                                  | **Relevant ATT&CK Techniques**                     |
|----------------------|------------------------------------------------------------------|----------------------------------------------------|
| **Data Pipeline**    | Protect data integrity, ensure secure collection and storage.   | Data Destruction (T1485), Data Manipulation (T1565) |
| **ML Models**        | Safeguard against adversarial attacks and model theft.          | Exploit Public-Facing Applications (T1190), Adversary-in-the-Middle (T1557) |
| **APIs and Interfaces** | Secure endpoints and prevent injection attacks.                | Input Capture (T1056), Command and Scripting Interpreter (T1059) |
| **Infrastructure**   | Secure cloud, edge, and on-prem systems hosting AI.             | Resource Hijacking (T1496), Cloud Service Exploitation (T1586) |


---

***ATT&CK Tactics in Cybersecurity Purview***

| **Tactic**            | **Description**                                                                  | **Relevant Techniques**                                       |
|------------------------|----------------------------------------------------------------------------------|--------------------------------------------------------------|
| **Initial Access**     | Methods used to gain unauthorized access to AI systems.                         | Phishing (T1566), Supply Chain Compromise (T1195), Valid Accounts (T1078) |
| **Defense Evasion**    | Hiding malicious activity or bypassing defenses.                                | Indicator Removal on Host (T1070), Abuse Elevation Control Mechanism (T1574) |
| **Privilege Escalation** | Techniques to gain elevated permissions in AI systems.                         | Exploitation for Privilege Escalation (T1068), New Service (T1201) |
| **Command and Control** | Techniques to maintain communication with compromised AI systems.               | Encrypted Channel (T1573), Multi-Hop Proxy (T1090) |
| **Impact**             | Techniques that manipulate AI outcomes or disrupt operations.                   | Data Manipulation (T1565), Service Stop (T1489) |

---

***Implementation Steps***

| **Step**               | **Description**                                                                  | **Example**                                                 |
|-------------------------|----------------------------------------------------------------------------------|------------------------------------------------------------|
| **Asset Identification** | Inventory all AI-related assets and categorize based on importance and exposure. | Identify datasets, ML models, APIs, and supporting infrastructure. |
| **ATT&CK Mapping**       | Map tactics and techniques to AI vulnerabilities and processes.                 | Link "Model Evasion" to "Defense Evasion" and Input Injection. |
| **Red and Blue Teaming** | Use ATT&CK to simulate attacks (Red) and monitor defense readiness (Blue).       | Test adversarial input attacks on deployed AI systems.      |
| **Metrics and Coverage** | Measure defensive coverage and prioritize high-risk tactics.                    | Analyze detection capabilities for TTPs like Data Manipulation (T1565). |

---

<!-- TOC --><a name="212-persona-addressed"></a>
#### 2.1.2. Persona addressed


| **Activity**                                | **Red Team** | **Blue Team** | **AI/ML Engineers** | **Threat Intelligence Analysts** | **Incident Responders** | **Software Architects** | **Security Architects** | **SOC Managers** | **SREs**     | **Executives & Risk Managers** | **Product Developers** |
|---------------------------------------------|--------------|---------------|----------------------|-----------------------------------|--------------------------|--------------------------|--------------------------|-------------------|-------------|---------------------------------|-------------------------|
| **Adversary Emulation for AI Systems**      | R            | C             | C                    | C                                 | I                        | C                        | C                        | I                 | C           | I                               | C                       |
| **Threat Detection in AI Systems**          | -            | R             | C                    | C                                 | C                        | C                        | I                        | A                 | C           | I                               | C                       |
| **AI-Specific Threat Intelligence Enrichment** | C          | C             | C                    | R                                 | C                        | I                        | I                        | I                 | C           | I                               | C                       |
| **Defensive Gap Assessment for AI**         | -            | R             | C                    | C                                 | C                        | C                        | A                        | C                 | I           | I                               | -                       |
| **SOC Maturity Assessment with AI Tools**   | I            | R             | C                    | C                                 | I                        | I                        | A                        | I                 | I           | I                               | -                       |
| **Incident Response for AI Breaches**       | I            | C             | C                    | C                                 | R                        | C                        | C                        | A                 | R           | I                               | I                       |
| **AI System Security Architecture Design**  | I            | C             | C                    | I                                 | C                        | R                        | R                        | A                 | C           | C                               | -                       |
| **AI-Specific Detection Rule Development**  | I            | R             | C                    | C                                 | I                        | C                        | C                        | A                 | C           | I                               | -                       |
| **Adversary Use of AI-Based Techniques**    | R            | C             | C                    | R                                 | I                        | C                        | I                        | I                 | C           | I                               | -                       |
| **Product Alignment with ATT&CK for AI**    | I            | I             | C                    | I                                 | I                        | C                        | C                        | I                 | I           | C                               | R                       |
| **AI Cybersecurity Investment Prioritization** | I         | I             | I                    | C                                 | I                        | C                        | C                        | C                 | I           | A                               | -                       |
| **AI System Reliability & Observability**   | I            | C             | C                    | C                                 | I                        | C                        | C                        | I                 | R           | A                               | C                       |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)

<!-- TOC --><a name="213-guidance-provided"></a>
#### 2.1.3. Guidance provided

The MITRE ATT&CK framework provides a robust foundation for securing AI systems by aligning traditional cybersecurity practices with AI-specific threats. By mapping adversary behaviors, simulating attacks, and enhancing detection capabilities, ATT&CK ensures AI systems are resilient against both known and emerging threats. Organizations can leverage ATT&CK to build a unified, proactive security posture that addresses the unique challenges posed by AI technology.

<!-- TOC --><a name="22-detail-on-current-framework"></a>
### 2.2. Detail on current framework

The MITRE ATT&CK framework provides a critical foundation for securing AI systems against emerging threats. AI systems introduce unique vulnerabilities and attack surfaces, such as adversarial inputs, data poisoning, and model theft, which require tailored applications of ATT&CK to ensure comprehensive threat coverage.

AI systems operate in complex environments and are susceptible to both traditional cybersecurity threats and AI-specific attacks. The ATT&CK framework offers a structured approach to:

1. Understand Threats: Map adversary behaviors targeting AI components such as data pipelines, models, APIs, and infrastructure.
2. Enhance Security Posture: Identify and mitigate vulnerabilities in AI systems by applying relevant ATT&CK techniques.
3. Integrate Defense: Bridge gaps between traditional IT security and AI-specific requirements.

***AI-Specific Threats Addressed by ATT&CK***

| **Category**         | **Threat**                                               | **Relevant ATT&CK Techniques**                     |
|-----------------------|----------------------------------------------------------|----------------------------------------------------|
| **Data-Related**      | Data poisoning to degrade AI model performance.          | Data Manipulation (T1565), Data Destruction (T1485) |
|                       | Data exfiltration from AI datasets or inference systems. | Exfiltration Over Web Service (T1567), Automated Exfiltration (T1020) |
| **Model-Specific**    | Adversarial inputs misleading AI predictions.            | Command and Scripting Interpreter (T1059), Exploit Public-Facing Applications (T1190) |
|                       | Model theft through reverse engineering or inference.    | Credential Dumping (T1003), Application Layer Protocol (T1071) |
| **Infrastructure**    | Resource hijacking for unauthorized use (e.g., cryptomining). | Resource Hijacking (T1496), Cloud Service Exploitation (T1586) |
|                       | API exploitation leading to malicious actions.           | Input Capture (T1056), API Abuse (T1555) |
| **Lifecycle Threats** | Reconnaissance for vulnerable AI components.             | Gather Victim Network Information (T1590) |
|                       | Manipulation of AI outputs to disrupt operations.        | Data Manipulation (T1565), Service Stop (T1489) |


***Application of ATT&CK Tactics to AI Systems***

| **Tactic**            | **Description**                                            | **Example Technique**                              |
|------------------------|------------------------------------------------------------|---------------------------------------------------|
| **Reconnaissance**     | Discovering weak points in AI workflows.                   | Gather Victim Network Information (T1590)         |
| **Initial Access**     | Exploiting APIs or supply chain vulnerabilities.           | Exploit Public-Facing Applications (T1190)        |
| **Execution**          | Triggering malicious actions via adversarial inputs.       | Command and Scripting Interpreter (T1059)         |
| **Persistence**        | Maintaining access to AI systems.                         | Account Manipulation (T1098)                      |
| **Exfiltration**       | Stealing datasets, models, or outputs.                     | Exfiltration Over Web Service (T1567)             |
| **Impact**             | Manipulating functionality or disrupting AI operations.    | Data Manipulation (T1565), Service Stop (T1489)   |


***Integration of ATT&CK into AI Security Lifecycle***

| **Step**               | **Description**                                          | **Example**                                                   |
|-------------------------|----------------------------------------------------------|--------------------------------------------------------------|
| **Asset Identification** | Inventory and categorize AI-related assets.              | Identify datasets, ML models, APIs, and supporting infrastructure. |
| **ATT&CK Mapping**       | Map tactics and techniques to AI vulnerabilities.        | Link "Model Evasion" to "Defense Evasion" and Input Injection. |
| **Threat Simulation**    | Simulate real-world adversary behaviors.                 | Test adversarial input attacks or model theft scenarios.      |
| **Continuous Monitoring** | Monitor for adversarial behaviors using ATT&CK-aligned analytics. | Detect adversarial inputs or unauthorized API access.          |
| **Incident Management**  | Develop playbooks for AI-specific incidents.             | Retrain poisoned models or revoke exploited APIs.             |



<!-- TOC --><a name="23-what-is-missing-for-defenders-of-ai-systems"></a>
### 2.3. What is missing for defenders of AI systems

While the MITRE ATT&CK framework provides a robust structure for addressing traditional cybersecurity threats, it lacks several critical elements specific to the unique challenges posed by AI systems. Those gaps are covered by MITRE ATLAS Framework.

***Challenges and Limitations of ATT&CK for AI Systems***

| **Challenge**           | **Description**                                                        |
|--------------------------|------------------------------------------------------------------------|
| **Dynamic Threat Landscape** | AI systems and adversaries evolve rapidly, requiring continuous updates to ATT&CK. |
| **Complexity of Mapping**     | Deep expertise in both cybersecurity and AI is needed for effective ATT&CK mapping. |
| **Operational Integration**   | Customization is required to integrate ATT&CK into existing workflows for AI security. |


<!-- TOC --><a name="2-atlas"></a>
## 2. ATLAS

<!-- TOC --><a name="21-overview-1"></a>
### 2.1. Overview

The MITRE Adversarial Threat Landscape for AI Systems (ATLAS) is a knowledge base designed to address threats to AI-enabled systems. It documents adversary tactics, techniques, and real-world attack observations while complementing the MITRE ATT&CK framework.

While MITRE ATT&CK remains the framework for traditional cybersecurity and adversary behaviors, MITRE ATLAS extends this model into the AI domain. ATLAS focuses on the unique adversarial threats faced by AI systems, such as model poisoning, prompt injection, and evasion attacks, complementing the capabilities of ATT&CK for a holistic view of modern cyber and AI threats.

ATLAS serves as a critical tool for understanding, simulating, and mitigating threats to AI systems. It helps stakeholders (e.g., analysts, developers, and defenders) prepare for AI-specific security challenges through shared knowledge and practical tools.

<!-- TOC --><a name="211-scoping-of-ai-system-andor-cybersecurity-purview-1"></a>
#### 2.1.1. Scoping of AI system and/or cybersecurity purview

Scoping an AI system within the ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) framework involves identifying the unique components, vulnerabilities, and threats across its lifecycle. This also includes defining the boundaries of cybersecurity purview to secure the AI ecosystem comprehensively. 

***Components to Include***

| **Component**         | **Description**                                                                 | **Risks**                                           |
|------------------------|---------------------------------------------------------------------------------|----------------------------------------------------|
| **Data Pipelines**     | Sources of training and inference data, preprocessing, storage, and management. | Data poisoning, unauthorized access, exfiltration. |
| **Model Training and Development** | Machine learning models and workflows for training and validation.             | Adversarial attacks, algorithm manipulation.       |
| **Inference Systems**  | APIs, endpoints, and real-time decision-making systems.                         | Adversarial inputs, API abuse, output manipulation.|
| **Infrastructure**     | Hosting environments (cloud, edge, on-prem) and AI libraries/frameworks.        | Misconfigured services, resource hijacking, tampering. |

---

***Threat Landscape***

| **Threat Category**      | **Description**                                                              |
|---------------------------|------------------------------------------------------------------------------|
| **Adversarial Techniques** | Targeted attacks like adversarial examples or model evasion.                |
| **Reconnaissance**        | Discovering vulnerable AI systems, datasets, or APIs.                       |
| **Exfiltration and Theft**| Stealing intellectual property such as models or sensitive data.             |
| **Impact Tactics**        | Manipulating outputs to disrupt operations or mislead decision-making.       |

---

***Security Domains***

| **Domain**           | **Description**                                                                 | **Risks**                                           |
|-----------------------|---------------------------------------------------------------------------------|----------------------------------------------------|
| **Data Security**     | Secure collection, preprocessing, storage, and access to datasets.              | Data poisoning, unauthorized modification, or theft. |
| **Model Security**    | Protect models from adversarial inputs, reverse engineering, and theft.          | Compromised outputs, model tampering.              |
| **Endpoint/API Security** | Secure interfaces and APIs exposed to external systems.                     | Input validation bypass, API abuse.               |
| **Infrastructure Security** | Protect hosting environments like cloud, edge, and on-prem.               | Misconfigurations, resource hijacking, unauthorized access. |

---

***Defensive Capabilities***

| **Capability**           | **Description**                                                             | **Example Actions**                                 |
|---------------------------|-----------------------------------------------------------------------------|----------------------------------------------------|
| **Monitoring and Detection** | Establish pipelines to monitor model behavior and inference anomalies.    | Use logs, telemetry, and AI-enhanced tools.        |
| **Mitigation and Response**  | Develop playbooks to handle AI-specific incidents like data poisoning.    | Retrain models, revoke API access, patch issues.   |

---

***Organizational Roles***

| **Role**                 | **Responsibilities**                                                        | **Key Activities**                                 |
|---------------------------|-----------------------------------------------------------------------------|----------------------------------------------------|
| **Cross-Disciplinary Teams** | Collaboration between AI engineers, security teams, and risk managers.   | Define security boundaries, review AI risks.       |
| **Red and Blue Teams**     | Test resilience using adversarial attack scenarios.                        | Conduct red/blue team exercises specific to AI.    |
| **Regulatory Alignment**   | Ensure compliance with AI regulations and ethical standards.               | Align practices with EU AI Act, NIST AI RMF, etc.  |

---

<!-- TOC --><a name="212-persona-addressed-1"></a>
#### 2.1.2. Persona addressed

| **Activity**                                | **Red Team** | **Blue Team** | **AI/ML Engineers** | **Threat Intelligence Analysts** | **Incident Responders** | **Software Architects** | **Security Architects** | **SOC Managers** | **SREs**     | **Executives & Risk Managers** | **Product Developers** |
|---------------------------------------------|--------------|---------------|----------------------|-----------------------------------|--------------------------|--------------------------|--------------------------|-------------------|-------------|---------------------------------|-------------------------|
| **Adversary Emulation for AI/ML Systems**   | R            | C             | C                    | C                                 | I                        | C                        | C                        | I                 | C           | I                               | C                       |
| **Threat Detection for AI/ML Systems**      | -            | R             | C                    | C                                 | C                        | C                        | I                        | A                 | C           | I                               | C                       |
| **AI/ML-Specific Threat Intelligence**      | C            | C             | C                    | R                                 | C                        | I                        | I                        | I                 | C           | I                               | C                       |
| **Defensive Gap Assessment for AI/ML**      | -            | R             | C                    | C                                 | C                        | C                        | A                        | C                 | I           | I                               | -                       |
| **SOC Maturity Assessment with AI Tools**   | I            | R             | C                    | C                                 | I                        | I                        | A                        | I                 | I           | I                               | -                       |
| **Incident Response for AI Breaches**       | I            | C             | C                    | C                                 | R                        | C                        | C                        | A                 | R           | I                               | I                       |
| **AI System Security Architecture Design**  | I            | C             | C                    | I                                 | C                        | R                        | R                        | A                 | C           | C                               | -                       |
| **AI-Specific Detection Rule Development**  | I            | R             | C                    | C                                 | I                        | C                        | C                        | A                 | C           | I                               | -                       |
| **Adversary Use of AI in Attacks**          | R            | C             | C                    | R                                 | I                        | C                        | I                        | I                 | C           | I                               | -                       |
| **Product Alignment with ATLAS for AI**     | I            | I             | C                    | I                                 | I                        | C                        | C                        | I                 | I           | C                               | R                       |
| **AI Cybersecurity Investment Prioritization** | I         | I             | I                    | C                                 | I                        | C                        | C                        | C                 | I           | A                               | -                       |
| **AI System Reliability & Observability**   | I            | C             | C                    | C                                 | I                        | C                        | C                        | I                 | R           | A                               | C                       |
| **Threat Modeling for AI/ML**               | C            | C             | R                    | C                                 | C                        | C                        | R                        | C                 | C           | I                               | -                       |
| **AI Supply Chain Risk Assessment**         | C            | C             | C                    | R                                 | C                        | C                        | R                        | C                 | C           | A                               | C                       |
| **Adversarial Input Detection and Mitigation** | I         | R             | C                    | C                                 | C                        | C                        | C                        | A                 | C           | I                               | -                       |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)



<!-- TOC --><a name="213-guidance-provided-1"></a>
#### 2.1.3. Guidance provided

ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) provides comprehensive guidance for defending AI systems by addressing unique threats such as data poisoning, adversarial inputs, model theft, API exploitation, and AI misuse. It extends the MITRE ATT&CK framework with AI-specific tactics, techniques, and procedures (TTPs), emphasizing the need to secure AI across its lifecycle—from data preparation and model training to inference and operation. 

ATLAS advocates for robust detection and mitigation strategies, including behavioral analytics, adversarial robustness testing, and strict access controls, while integrating AI into red and blue team exercises and enhancing threat intelligence. It also highlights the importance of securing AI supply chains, protecting pre-trained models and frameworks, and addressing cross-domain risks in cloud, edge, and IoT environments. 


<!-- TOC --><a name="22-detail-on-current-framework-1"></a>
### 2.2. Detail on current framework

The design and structure of MITRE ATLAS reflect its commitment to providing a comprehensive, adaptable framework for addressing adversarial threats to AI systems. Its integration of tactics, techniques, and real-world procedures, combined with a focus on tools and mitigations, ensures its utility across diverse AI environments. By targeting the unique vulnerabilities of AI systems, ATLAS serves as both a practical resource and a strategic guide for securing the next generation of intelligent technologies.

<!-- TOC --><a name="221-atlas-matrix"></a>
#### 2.2.1. ATLAS Matrix

The ATLAS Matrix provides a visual representation of adversary tactics and techniques, similar to the ATT&CK Matrix but adapted for AI systems. It organizes:

1. Tactics as the top-level categories (e.g., Data Poisoning, Evasion, Extraction).
2. Techniques under each tactic as actionable adversary behaviors.
3. Links to Procedures that document real-world use cases and observed attacks.


<!-- TOC --><a name="222-core-components"></a>
#### 2.2.2. Core Components

The ATLAS Framework is organized into components that reflect the adversarial threat landscape of AI systems. These components include Tactics, Techniques, and Procedures (TTPs) and are designed to capture adversary behavior in both training and inference stages.

<!-- TOC --><a name="2221-tactics"></a>
##### 2.2.2.1. Tactics

Tactics represent adversary goals and are categorized to address the unique operational aspects of AI systems. Each tactic defines a specific objective the adversary seeks to achieve. AI-Specific Tactics include:

| **Tactic**              | **Description**                                                                                  |
|--------------------------|-------------------------------------------------------------------------------------------------|
| **Data Poisoning**       | Manipulating training datasets to degrade model performance or introduce malicious behavior.   |
| **Evasion**              | Designing adversarial inputs to mislead AI models into producing incorrect outputs.            |
| **Extraction**           | Stealing sensitive information such as model parameters, architecture, or training data.       |
| **Inversion**            | Recovering private or sensitive information about the model's training data from its outputs.  |
| **Prompt Injection**     | Injecting malicious inputs into large language models (LLMs) to override or manipulate behavior.|
| **Traditional Cyber Tactics** | Using established cyber techniques (e.g., API abuse, credential theft) to target AI systems.  |

---

<!-- TOC --><a name="2222-techniques"></a>
##### 2.2.2.2. Techniques

Techniques describe the methods adversaries use to achieve their tactical objectives. These are highly specific to the AI domain and reflect the different stages of the AI lifecycle. Each technique may apply to one or more tactics. Examples of Techniques:

| **Technique**                  | **Description**                                                                                       |
|--------------------------------|-------------------------------------------------------------------------------------------------------|
| **Training Data Poisoning**    | Introducing malicious or biased data into the training dataset to degrade model accuracy or integrity. |
| **Adversarial Perturbations**  | Modifying inputs slightly to cause the AI model to produce incorrect predictions or classifications.   |
| **API Abuse**                  | Exploiting AI model APIs to manipulate outputs or extract sensitive data.                             |
| **Model Extraction**           | Reverse engineering or stealing the AI model's parameters or architecture via inference queries.      |
| **Overfitting Exploitation**   | Identifying and exploiting a model's reliance on specific patterns in data to induce errors.           |

---

<!-- TOC --><a name="2223-procedures"></a>
##### 2.2.2.3. Procedures

Procedures represent real-world adversary actions and implementations of techniques. These are based on observed adversarial behavior and case studies. Examples of Adversary Procedures:

| **Procedure**                 | **Description**                                                                                      |
|-------------------------------|------------------------------------------------------------------------------------------------------|
| **Adversarial Input**         | Designing specific inputs (e.g., images or text) to trick AI models into producing incorrect outputs. |
| **LLM Exploitation**          | Using malicious prompts to force large language models (LLMs) to generate unintended responses.      |
| **Steganographic Poisoning**  | Embedding malicious data within seemingly benign files to influence model behavior during training.  |
| **Environmental Manipulation**| Altering real-world conditions (e.g., light, noise) to confuse AI perception systems.                |
| **Dataset Manipulation**      | Subtly modifying public datasets used for training to introduce vulnerabilities into the final model. |

---

<!-- TOC --><a name="223-attack-surface"></a>
#### 2.2.3. Attack Surface

| **Aspect**  | **Description**  | **Examples** |
|-------------|------------------|--------------|
| **AI Access Time**    | Stages of the AI lifecycle where attacks can occur. | **1. Training Phase**: Manipulating training data or configurations. |
|  |  | **2. Inference Phase**: Targeting live AI models to manipulate outputs or extract data. |
| **AI Access Points**  | Interfaces through which adversaries interact with the AI system. | **1. Digital Access**: APIs, web services, file inputs. |
|  |  | **2. Physical Access**: Environmental data like sensor inputs. |
| **System Knowledge**  | Levels of understanding adversaries have about the AI system's internals. | **1. White-box Access**: Full access to model architecture, parameters, and training data. |
|  |  | **2. Black-box Access**: Limited to observing inputs and outputs. |

---

<!-- TOC --><a name="224-threat-mitigation"></a>
#### 2.2.4. Threat Mitigation

ATLAS includes a set of mitigation techniques and security measures to prevent or reduce the impact of adversarial attacks:

| **Mitigation Category**   | **Description**  | **Examples**  |
|---------------------------|------------------|---------------|
| **Data Integrity**         | Ensures that training data is authentic, clean, and robust against manipulation. | 1. Validating data sources. |
|  |  | 2. Removing outliers or malicious entries in datasets. |
| **Adversarial Detection**  | Monitors for unusual input patterns and detects adversarial perturbations. | 1. Deploying anomaly detection systems. |
|  |  | 2. Using input validation mechanisms. |
| **Robust Model Design**    | Improves model resilience through advanced training techniques. | 1. Adversarial training to simulate attack scenarios. |
|  |  | 2. Using defensive distillation methods. |
| **Access Controls**        | Restricts unauthorized access to AI model APIs and infrastructure. | 1. Implementing API key management. |
|  |  | 2. Enforcing strong authentication and rate limiting. |
| **Monitoring and Logging** | Tracks API queries, model behavior, and system usage to detect anomalies or attacks. | 1. Setting up logging for API calls. |
|  |  | 2. Analyzing usage patterns to flag suspicious activities. |

---

<!-- TOC --><a name="23-what-is-missing-for-defenders-of-ai-systems-1"></a>
### 2.3. What is missing for defenders of AI systems

ATLAS provides a strong foundation for securing AI systems by extending adversarial tactics, techniques, and procedures (TTPs) to AI/ML. As AI Technology evolves, ATLAS will have to be adding more coverage of advanced adversarial techniques, feedback loop attacks, and supply chain risks.

<!-- TOC --><a name="3-capec"></a>
## 3. CAPEC

<!-- TOC --><a name="21-overview-2"></a>
### 2.1. Overview

The Common Attack Pattern Enumeration and Classification (CAPEC) is a standardized, community-driven framework for understanding, categorizing, and mitigating cyber-attack techniques. It provides a structured taxonomy of attack patterns that describe methods attackers use to exploit software systems. While CAPEC is not designed to defend AI systems it is relevant for AI-based systems focused on cybersecurity, as it provides machine-readable, systematic descriptions of attacks that can be used to enhance threat detection, prevention, and response capabilities.


<!-- TOC --><a name="211-scoping-of-ai-system-andor-cybersecurity-purview-2"></a>
#### 2.1.1. Scoping of AI system and/or cybersecurity purview

CAPEC is not designed to scope cybersecurity of AI system. However it can be very valuable framework to aid building AI based cybersecurity systems.

| **Focus Area**                      | **CAPEC Integration**                                                                                  | **AI Application Examples**                                                                                 |
|------------------------------------|--------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **Proactive Threat Modeling**       | CAPEC supports identifying, simulating, and mitigating attack scenarios during the design phase.      | AI analyzes system design to predict attacks like Phishing (CAPEC-98) and recommend mitigations.        |
| **Dynamic Threat Modeling**         | CAPEC enables real-time threat modeling and attack chain prediction using AI systems.                 | AI dynamically models attack chains (e.g., from Credential Theft to Privilege Escalation).          |
| **SIEM Integration**                | CAPEC patterns help AI-enhanced SIEM tools detect malicious activity by correlating logs with attacks.| AI flags network traffic anomalies based on CAPEC-defined patterns like HTTP Response Splitting (CAPEC-34). |
| **SOAR Platforms**                  | AI-driven SOAR systems automate threat response workflows based on CAPEC attack metadata.             | AI automates response playbooks for attacks such as SQL Injection (CAPEC-66) based on CAPEC severity.   |
| **Endpoint Detection and Response** | CAPEC attack descriptions guide AI-based endpoint analysis to detect malicious activity.              | AI identifies and mitigates Malware Execution (CAPEC-175) on endpoints.                                 |
| **Threat Intelligence Enrichment**  | CAPEC integrates with threat intelligence frameworks like STIX/TAXII to enrich data with attack info. | AI correlates live threat feeds with CAPEC patterns to detect emerging threats.                             |
| **Threat Actor Profiling**          | CAPEC patterns assist AI systems in analyzing TTPs (Tactics, Techniques, Procedures) of adversaries.  | AI identifies adversarial tactics through attack patterns like Credential Abuse or Malware Injection.|
| **Predictive Threat Analysis**      | CAPEC attack lifecycle context allows AI to predict emerging threats and preemptively respond.        | AI predicts new attacks based on historical CAPEC data and prioritizes preemptive mitigations.              |


<!-- TOC --><a name="212-persona-addressed-2"></a>
#### 2.1.2. Persona addressed

| **Task/Activity**                                 | **AI Engineer**                 | **Cybersecurity Analyst**      | **SOC Analyst**                | **Incident Manager**            | **Executive Leadership**        | **Software Architect**          | **Software Developer**          | **SME**                         | **Data Scientist**              |
|---------------------------------------------------|---------------------------------|--------------------------------|--------------------------------|---------------------------------|---------------------------------|---------------------------------|---------------------------------|---------------------------------|---------------------------------|
| **Integrate CAPEC into AI Systems**               | R                               | C                              | I                              | I                              | I                              | A                               | C                               | C                               | R                               |
| **Threat Modeling Using CAPEC**                   | C                               | R                              | C                              | A                              | I                              | R                               | C                               | C                               | C                               |
| **Train AI Models with CAPEC Data**               | R                               | C                              | I                              | I                              | I                              | C                               | I                               | C                               | R                               |
| **Identify CAPEC Attack Patterns**                | C                               | R                              | C                              | A                              | I                              | C                               | I                               | R                               | C                               |
| **Automate Threat Detection Using CAPEC**         | R                               | C                              | I                              | A                              | I                              | C                               | I                               | C                               | R                               |
| **Vulnerability Assessment and Simulation**       | C                               | R                              | I                              | A                              | I                              | R                               | R                               | C                               | C                               |
| **Incident Response and Mitigation**              | I                               | C                              | R                              | A                              | I                              | I                               | I                               | C                               | I                               |
| **Maintain and Update CAPEC Data**                | R                               | R                              | I                              | A                              | I                              | C                               | I                               | R                               | C                               |
| **Align CAPEC with Threat Intelligence (STIX/TAXII)** | C                            | R                              | C                              | A                              | I                              | C                               | I                               | R                               | C                               |
| **Report CAPEC-Based Threat Insights**            | C                               | R                              | I                              | A                              | I                              | I                               | I                               | R                               | C                               |
| **CAPEC Training and Awareness**                  | C                               | R                              | C                              | I                              | A                              | C                               | I                               | R                               | C                               |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)


<!-- TOC --><a name="213-guidance-provided-2"></a>
#### 2.1.3. Guidance provided

CAPEC provides a robust foundation for AI systems to improve cybersecurity automation, detection, prediction, and response, making it useful for AI-driven security solutions. However it doesn't provide any guidance for AI systems security.

<!-- TOC --><a name="22-detail-on-current-framework-2"></a>
### 2.2. Detail on current framework

CAPEC provides a comprehensive, structured foundation that AI systems can leverage to detect, analyze, and mitigate cyber-attacks effectively. By combining CAPEC with AI pattern recognition, behavioral analysis, and automation capabilities, organizations can significantly enhance their cybersecurity posture throughout the threat lifecycle.

***CAPEC Features Applicable to AI Systems***

| **Feature**                  | **Description**                                                                 |
|------------------------------|-------------------------------------------------------------------------------|
| **Attack Patterns**          | Reusable descriptions of attack techniques like SQL Injection and XSS.       |
| **Structured Taxonomy**      | Hierarchical classification of attack methods for easy analysis and linking. |
| **Data Integration**         | Works with CWE, CVE, and CybOX to create a comprehensive security framework. |
| **Machine-Readable Format**  | Provides formats suitable for AI systems to perform automated analysis.      |
| **Attack Lifecycle Context** | Includes attack descriptions, preconditions, methods, consequences, and mitigations. |

---

***Applications of CAPEC for AI Systems***

| **Application**                    | **Description**                                                                                   | **Example Use Case**                                                                                 |
|------------------------------------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **Training AI Models**             | CAPEC provides high-quality labeled datasets for supervised learning.                            | Train AI to detect SQL Injection or Buffer Overflow using CAPEC data.                              |
| **Attack Pattern Detection**       | AI uses CAPEC to recognize known and evolving attacks by matching observed behaviors.             | Identify HTTP Response Splitting (CAPEC-34) based on network traffic analysis.                     |
| **Threat Modeling and Prediction** | AI predicts potential attack scenarios during software development using CAPEC taxonomy.       | Simulate attacks like phishing or privilege escalation to find exploitable paths.                  |
| **Automated Vulnerability Assessment** | CAPEC helps simulate attack patterns for penetration testing and risk evaluation.               | AI-based scanner tests applications for vulnerabilities like XSS or SQL Injection.                 |
| **Behavioral Analysis and Anomaly Detection** | Detect deviations in system behavior by comparing it to CAPEC-defined attack patterns.         | Flag unusual process executions resembling Buffer Overflow attacks.                                |
| **Incident Classification and Response** | AI classifies incidents and suggests mitigations using CAPEC context (prerequisites, impact).  | Classify an incident as Session Fixation (CAPEC-60) and prioritize countermeasures.                |
| **Attack Chain Analysis**          | AI models the sequence of steps in an attack using CAPEC patterns to predict adversary behavior. | Predict escalation from Phishing (CAPEC-98) to credential theft or lateral movement.               |
| **Real-Time Threat Intelligence**  | CAPEC integrates with live feeds for real-time attack detection and counteractions.              | Correlate threat feeds with CAPEC patterns to detect and block ongoing attacks.                    |



<!-- TOC --><a name="23-what-is-missing-for-defenders-of-ai-systems-2"></a>
### 2.3. What is missing for defenders of AI systems

CAPEC focuses primarily on traditional software and system vulnerabilities but does not include AI-specific attack patterns. It integrates with CWE, which is focused on general software vulnerabilities but lacks specificity for AI. While CAPEC is well-suited for traditional IT systems but does not sufficiently address emerging AI-specific security domains.


<!-- TOC --><a name="4-references"></a>
## 4. References

| Framework | Referenced Material |
| --- | --- |
| MITRE ATT&CK | [MITRE ATT&CK](https://attack.mitre.org/) |
| MITRE ATLAS | [MITRE ATLAS](https://atlas.mitre.org/) |
| MITRE CAPEC | [MITRE CAPEC](https://capec.mitre.org/) |

*Document was created with assistance of OpenAI ChatGPT 4o model.*