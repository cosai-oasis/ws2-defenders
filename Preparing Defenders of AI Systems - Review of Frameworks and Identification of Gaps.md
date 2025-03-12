<!-- TOC start -->

- [Preparing Defenders of AI Systems:  Review of Frameworks and Identification of Gaps, V1.0 -- DRAFT](#preparing-defenders-of-ai-systems--review-of-frameworks-and-identification-of-gaps-v10----draft)
  - [OASIS Open Project : Coalition for Secure AI (CoSAI) - Workstream 2: Preparing Defenders for a Changing Cybersecurity Landscape](#oasis-open-project--coalition-for-secure-ai-cosai---workstream-2-preparing-defenders-for-a-changing-cybersecurity-landscape)
  - [1. Executive Summary](#1-executive-summary)
  - [2. How to use this document](#2-how-to-use-this-document)
    - [2.1. Understanding the Structure](#21-understanding-the-structure)
    - [2.2. Practical Application](#22-practical-application)
    - [2.3. Making Framework Choices](#23-making-framework-choices)
    - [2.4. Additional Resources](#24-additional-resources)
    - [2.5. Leveraging Defender Frameworks](#25-leveraging-defender-frameworks)
    - [2.6. Scope of Preparing Defenders of AI Systems](#26-scope-of-preparing-defenders-of-ai-systems)
      - [2.6.1 In Scope](#261-in-scope)
      - [2.6.2 Out of Scope](#262-out-of-scope)
  - [3. Changing Attack Surface with AI Adoption](#3-changing-attack-surface-with-ai-adoption)
    - [3.1. AI Risk Scenarios](#31-ai-risk-scenarios)
      - [3.1.1 AI as a Target: Key Security Risks](#311-ai-as-a-target-key-security-risks)
      - [3.1.2 AI as an Enabler of Cyber Attacks on other assets, targets, infrastructures](#312-ai-as-an-enabler-of-cyber-attacks-on-other-assets-targets-infrastructures)
      - [3.1.3 AI Risks in Business Processes](#313-ai-risks-in-business-processes)
    - [3.2. AI Defender Frameworks Overview](#32-ai-defender-frameworks-overview)
    - [3.3. Change needed for Defenders of AI Systems](#33-change-needed-for-defenders-of-ai-systems)
      - [3.3.1. AI-Specific Threat Intelligence \& Adversarial Detection](#331-ai-specific-threat-intelligence--adversarial-detection)
      - [3.3.2. Zero Trust for AI Systems](#332-zero-trust-for-ai-systems)
      - [3.3.3. AI Model \& Data Supply Chain Security](#333-ai-model--data-supply-chain-security)
      - [3.3.4. AI-Specific Incident Response \& SOC Automation](#334-ai-specific-incident-response--soc-automation)
      - [3.3.5. Secure AI Model Deployment \& Runtime Protection](#335-secure-ai-model-deployment--runtime-protection)
      - [3.3.6. AI Security Awareness \& Red Teaming](#336-ai-security-awareness--red-teaming)
  - [4. Roles Addressed](#4-roles-addressed)
    - [4.1. Persona](#41-persona)
    - [4.2. Relevant Frameworks](#42-relevant-frameworks)
    - [4.3. Activities and Responsibilities](#43-activities-and-responsibilities)
  - [5. Takeaways and Conclusion](#5-takeaways-and-conclusion)
    - [5.1. Key Takeaways:](#51-key-takeaways)
    - [5.2. Conclusion:](#52-conclusion)
  - [6. Appendix](#6-appendix)
    - [6.1. Deep Dive in Frameworks](#61-deep-dive-in-frameworks)
      - [6.1.1. NIST](#611-nist)
        - [6.1.1.1. NIST CSF 2.0](#6111-nist-csf-20)
          - [6.1.1.1.1. Overview](#61111-overview)
          - [6.1.1.1.2. Scoping of AI system and/or cybersecurity purview](#61112-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.1.1.3. Persona addressed](#61113-persona-addressed)
          - [6.1.1.1.4. Guidance provided](#61114-guidance-provided)
          - [6.1.1.1.5. Detail on current framework](#61115-detail-on-current-framework)
          - [6.1.1.1.6. What is missing for defenders of AI systems](#61116-what-is-missing-for-defenders-of-ai-systems)
        - [6.1.1.2. NIST RMF](#6112-nist-rmf)
          - [6.1.1.2.1. Overview](#61121-overview)
          - [6.1.1.2.2. Scoping of AI system and/or cybersecurity purview](#61122-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.1.2.3. Persona addressed](#61123-persona-addressed)
          - [6.1.1.2.4. Guidance provided](#61124-guidance-provided)
          - [6.1.1.2.5. Detail on current framework](#61125-detail-on-current-framework)
          - [6.1.1.2.6. What is missing for defenders of AI systems](#61126-what-is-missing-for-defenders-of-ai-systems)
        - [6.1.1.3. NIST AI RMF 1.0](#6113-nist-ai-rmf-10)
          - [6.1.1.3.1. Overview](#61131-overview)
          - [6.1.1.3.2. Scoping of AI system and/or cybersecurity purview](#61132-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.1.3.3. Persona addressed](#61133-persona-addressed)
          - [6.1.1.3.4. Guidance provided](#61134-guidance-provided)
          - [6.1.1.3.5. Detail on current framework](#61135-detail-on-current-framework)
          - [6.1.1.3.6. What is missing for defenders of AI systems](#61136-what-is-missing-for-defenders-of-ai-systems)
        - [6.1.1.4. NIST AI RMF 1.0 for Generative AI (GAI)](#6114-nist-ai-rmf-10-for-generative-ai-gai)
          - [6.1.1.4.1. Overview](#61141-overview)
          - [6.1.1.4.2. Scoping of AI system and/or cybersecurity purview](#61142-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.1.4.3. Persona addressed](#61143-persona-addressed)
          - [6.1.1.4.4. Guidance provided](#61144-guidance-provided)
          - [6.1.1.4.5. Detail on current framework](#61145-detail-on-current-framework)
          - [6.1.1.4.6. What is missing for defenders of AI systems](#61146-what-is-missing-for-defenders-of-ai-systems)
        - [6.1.1.5. NIST AI Adversarial Machine Learning (AML)](#6115-nist-ai-adversarial-machine-learning-aml)
          - [6.1.1.5.1. Overview](#61151-overview)
          - [6.1.1.5.2. Scoping of AI system and/or cybersecurity purview](#61152-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.1.5.3. Persona addressed](#61153-persona-addressed)
          - [6.1.1.5.4. Guidance provided](#61154-guidance-provided)
          - [6.1.1.5.5. Detail on current framework](#61155-detail-on-current-framework)
          - [6.1.1.5.6. What is missing for defenders of AI systems](#61156-what-is-missing-for-defenders-of-ai-systems)
      - [6.1.2. MITRE](#612-mitre)
        - [6.1.2.1. MITRE ATT\&CK](#6121-mitre-attck)
          - [6.1.2.1.1. Overview](#61211-overview)
          - [6.1.2.1.2. Scoping of AI system and/or cybersecurity purview](#61212-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.2.1.3. Persona addressed](#61213-persona-addressed)
          - [6.1.2.1.4. Guidance provided](#61214-guidance-provided)
          - [6.1.2.1.5. Detail on current framework](#61215-detail-on-current-framework)
          - [6.1.2.1.6. What is missing for defenders of AI systems](#61216-what-is-missing-for-defenders-of-ai-systems)
        - [6.1.2.2. MITRE ATLAS](#6122-mitre-atlas)
          - [6.1.2.2.1. Overview](#61221-overview)
          - [6.1.2.2.2. Scoping of AI system and/or cybersecurity purview](#61222-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.2.2.3. Persona addressed](#61223-persona-addressed)
          - [6.1.2.2.4. Guidance provided](#61224-guidance-provided)
          - [6.1.2.2.5. Detail on current framework](#61225-detail-on-current-framework)
          - [6.1.2.2.6. What is missing for defenders of AI systems](#61226-what-is-missing-for-defenders-of-ai-systems)
        - [6.1.2.3. MITRE CAPEC](#6123-mitre-capec)
          - [6.1.2.3.1. Overview](#61231-overview)
          - [6.1.2.3.2. Scoping of AI system and/or cybersecurity purview](#61232-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.2.3.3. Persona addressed](#61233-persona-addressed)
          - [6.1.2.3.4. Guidance provided](#61234-guidance-provided)
          - [6.1.2.3.5. Detail on current framework](#61235-detail-on-current-framework)
          - [6.1.2.3.6. What is missing for defenders of AI systems](#61236-what-is-missing-for-defenders-of-ai-systems)
        - [6.1.2.4. MITRE D3FEND](#6124-mitre-d3fend)
          - [6.1.2.4.1. Overview](#61241-overview)
          - [6.1.2.4.2. Scoping of AI system and/or cybersecurity purview](#61242-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.2.4.3. Persona addressed](#61243-persona-addressed)
          - [6.1.2.4.4. Guidance provided](#61244-guidance-provided)
          - [6.1.2.4.5. Detail on current framework](#61245-detail-on-current-framework)
          - [6.1.2.4.6. What is missing for defenders of AI systems](#61246-what-is-missing-for-defenders-of-ai-systems)
      - [6.1.3. CISA](#613-cisa)
        - [6.1.3.1. Zero Trust Maturity Model 2.0](#6131-zero-trust-maturity-model-20)
          - [6.1.3.1.1. Overview](#61311-overview)
          - [6.1.3.1.2. Cybersecurity Purview](#61312-cybersecurity-purview)
          - [6.1.3.1.3. Persona Addressed](#61313-persona-addressed)
          - [6.1.3.1.4. Guidance Provided](#61314-guidance-provided)
          - [6.1.3.1.5. Detail on current framework](#61315-detail-on-current-framework)
          - [6.1.3.1.6. What is missing for defenders of AI systems](#61316-what-is-missing-for-defenders-of-ai-systems)
      - [6.1.4. OASIS](#614-oasis)
        - [6.1.4.1. OASIS STIX 2.1](#6141-oasis-stix-21)
          - [6.1.4.1.1. Overview](#61411-overview)
          - [6.1.4.1.2. Scoping of AI system and/or cybersecurity purview](#61412-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.4.1.3. Persona addressed](#61413-persona-addressed)
          - [6.1.4.1.4. Guidance provided](#61414-guidance-provided)
          - [6.1.4.1.5. Detail on current framework](#61415-detail-on-current-framework)
          - [6.1.4.1.6. What is missing for defenders of AI systems](#61416-what-is-missing-for-defenders-of-ai-systems)
      - [6.1.5. MIT](#615-mit)
        - [6.1.5.1. MIT AI Risk Repository](#6151-mit-ai-risk-repository)
          - [6.1.5.1.1. Overview](#61511-overview)
          - [6.1.5.1.2. Scoping of AI system and/or cybersecurity purview](#61512-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.5.1.3. Persona addressed](#61513-persona-addressed)
          - [6.1.5.1.4. Guidance provided](#61514-guidance-provided)
          - [6.1.5.1.5. Detail on current framework](#61515-detail-on-current-framework)
          - [6.1.5.1.6. What is missing for defenders of AI systems](#61516-what-is-missing-for-defenders-of-ai-systems)
      - [6.1.6. OCSF](#616-ocsf)
        - [6.1.6.1. Open Cybersecurity Schema Framework (OCSF)](#6161-open-cybersecurity-schema-framework-ocsf)
          - [6.1.6.1.1. Overview](#61611-overview)
          - [6.1.6.1.2. Scoping of AI system and/or cybersecurity purview](#61612-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.6.1.3. Persona addressed](#61613-persona-addressed)
          - [6.1.6.1.4. Guidance provided](#61614-guidance-provided)
          - [6.1.6.1.5. Detail on current framework](#61615-detail-on-current-framework)
          - [6.1.6.1.6. What is missing for defenders of AI systems](#61616-what-is-missing-for-defenders-of-ai-systems)
      - [6.1.7. OWASP](#617-owasp)
        - [6.1.7.1. Top 10 for LLM Applications 2025](#6171-top-10-for-llm-applications-2025)
          - [6.1.7.1.1. Overview](#61711-overview)
          - [6.1.7.1.2. Scoping of AI system and/or cybersecurity purview](#61712-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.7.1.3. Persona addressed](#61713-persona-addressed)
          - [6.1.7.1.4. Guidance provided](#61714-guidance-provided)
          - [6.1.7.1.5. Detail on current framework](#61715-detail-on-current-framework)
          - [6.1.7.1.6. What is missing for defenders of AI systems](#61716-what-is-missing-for-defenders-of-ai-systems)
      - [6.1.8. Amazon](#618-amazon)
        - [6.1.8.1. The AWS Generative AI Security Scoping Matrix](#6181-the-aws-generative-ai-security-scoping-matrix)
          - [6.1.8.1.1. Overview](#61811-overview)
          - [6.1.8.1.2. Scoping of AI system and/or cybersecurity purview](#61812-scoping-of-ai-system-andor-cybersecurity-purview)
          - [6.1.8.1.3. Persona addressed](#61813-persona-addressed)
          - [6.1.8.1.4. Guidance provided](#61814-guidance-provided)
          - [6.1.8.1.5. Detail on current framework](#61815-detail-on-current-framework)
          - [6.1.8.1.6. What is missing for defenders of AI systems](#61816-what-is-missing-for-defenders-of-ai-systems)
    - [6.2. References](#62-references)
    - [6.3. Acknowledgements](#63-acknowledgements)
      - [6.3.1. Workstream Leads Chairs:](#631-workstream-leads-chairs)
      - [6.3.2. Editors:](#632-editors)
      - [6.3.3. List of active contributors:](#633-list-of-active-contributors)
    - [6.4 CoSAI Security Focus](#64-cosai-security-focus)
    - [6.5. Guidelines on usage of more advanced AI systems (e.g. large language models (LLMs), multi-modal language models. etc) for drafting documents for OASIS CoSAI:](#65-guidelines-on-usage-of-more-advanced-ai-systems-eg-large-language-models-llms-multi-modal-language-models-etc-for-drafting-documents-for-oasis-cosai)
    - [6.6. Copyright Notice](#66-copyright-notice)

<!-- TOC end -->

# Preparing Defenders of AI Systems:  Review of Frameworks and Identification of Gaps, V1.0 -- DRAFT

## OASIS Open Project : [Coalition for Secure AI (CoSAI)](https://github.com/cosai-oasis) - [Workstream 2: Preparing Defenders for a Changing Cybersecurity Landscape](https://github.com/cosai-oasis/ws2-defenders)


## 1. Executive Summary

At the intersection of innovation and security lies a critical challenge for today's enterprises: how to harness the transformative power of generative AI while establishing robust security frameworks to protect these valuable assets. As AI systems move from experimental projects to core operational infrastructure, organizations face a security landscape that traditional governance models were never designed to address.

This whitepaper examines the evolving relationship between AI advancement and preparing defenders for a changing risk landscape, offering security leaders a practical roadmap through this complex terrain. Our analysis reveals that while existing frameworks provide valuable foundations, they leave significant gaps when applied to AI's unique security challenges.

### The Three Domains of AI Security

Our research identifies three interconnected security domains that demand specialized attention:

| **Security Domain**     |  **Details**    |
|-------------------------|------------------------|
| **AI Model Security**   | Beyond traditional cybersecurity concerns, AI models face sophisticated adversarial attacks designed to manipulate their behavior through techniques like prompt injection, data poisoning, and model inversion. These attacks can bypass carefully constructed guardrails, extract sensitive information, or force harmful outputs. Defending against these threats requires specialized approaches including robust input validation, adversarial training, and continuous monitoring for behavioral anomalies. |
| **AI Platform Security** | The infrastructure supporting AI systems presents distinctive vulnerabilities across training environments, inference endpoints, and deployment pipelines. Threats range from unauthorized API access to compute resource hijacking. Effective defense requires specialized monitoring for high-performance computing resources, secure model registry implementation, and runtime protection mechanisms capable of detecting attacks in real-time. |
| **AI Security Governance** | As AI systems make increasingly consequential decisions, governance mechanisms must evolve to establish appropriate boundaries, audit trails, and access controls. This includes defining security perimeters around AI capabilities, monitoring for unauthorized actions, and creating specialized incident response playbooks for AI-specific threats.|

### Bridging the Gaps: From Frameworks to Implementation

Our analysis of established security frameworks—including NIST, MITRE ATT&CK/ATLAS, and OWASP —reveals both valuable guidance and significant gaps in addressing these AI-specific security domains. The most pressing challenge for organizations is bridging the divide between theoretical frameworks and practical implementation.

While we acknowledge the broader discourse around AI ethics, transparency, and safety, this whitepaper maintains a deliberate focus on security. By narrowing our scope to the defender's perspective, we provide actionable guidance for security practitioners charged with protecting AI assets while enabling responsible innovation.  We provide defenders a resource for understanding which frameworks apply to their role, refining the scope further with specific responsibilities each framework indicates for their role.

For security leaders navigating this evolving landscape, this whitepaper offers a comprehensive examination of current approaches, critical gaps, and practical steps forward in securing the enterprise AI journey.

**NOTE**: In recognition of the rapidly evolving nature of AI and cybersecurity, this document is intended as a living resource. The Coalition for Secure AI (CoSAI) commits to continually updating its content to reflect emerging technologies, new threat vectors, and evolving best practices, ensuring that our guidance remains current and actionable for all stakeholders.  This v1.0 DRAFT was published Mar 12, 2025.

## 2. How to use this document

To get maximum value from this resource:

### 2.1. Understanding the Structure

* Begin with Section 1, which provides context on the changing attack surface with AI adoption and outlines key changes needed for defenders. Use Section 1.5 to understand some of the key takeaways and conclusions from the paper
* Review Section 2's detailed analysis of each major framework (NIST, MITRE, CISA, etc.)

### 2.2. Practical Application

***Assessment***
* Use the roles and responsibilities matrices (e.g. RACI) in the _Roles Addressed_ sections to identify relevant stakeholders in your organization
* Review framework summaries to determine which are most applicable to your environment, industry, geography, and/or AI use cases
* Map current security controls to framework recommendations

***Gap Analysis***
* Leverage the "What is Missing" sections to identify potential blind spots in any given framework - combine with other frameworks that may fill those gaps
* Compare your existing security practices against framework recommendations - leverage your current strengths and extend them to your AI solutions
* Prioritize areas needing additional controls or processes

***Implementation***
* Reference detailed framework sections for specific control guidance
* Use the cross-framework analysis to develop a comprehensive security strategy
* Apply recommendations based on your organization's AI implementation scope

***Continuous Improvement***
* Monitor the effectiveness of implemented controls
* Stay current with framework updates and emerging threats
* Contribute feedback and learnings to the broader AI security community and in to CoSAI

### 2.3. Making Framework Choices

* Consider starting with foundational frameworks like NIST CSF 2.0 for general security governance and the AWS Generative AI Security Scoping Matrix to help scope your AI use cases and risks
* Add AI-specific frameworks like MITRE ATLAS for adversarial threats
* Layer in specialized guidance like the OWASP Top 10 for LLM Applications as needed
* Multiple frameworks will likely be necessary for your organization depending on their requirements

### 2.4. Additional Resources
    
* Reference the appendices for detailed mappings between frameworks
* Use cited sources to dive deeper into specific areas of interest
* Engage with the CoSAI community for implementation support and best practices

Remember that securing AI systems is an evolving challenge. This document should be treated as a living resource that provides guidance while encouraging adaptation to your specific needs and circumstances.

### 2.5. Leveraging Defender Frameworks

This work reviews the body of knowledge preparing defenders of AI systems, including many of the framework standards used for cybersecurity.  It makes three contributions to guide securing AI systems:
1. Overview and detail on defender frameworks
2. Mapping frameworks to organizational roles and responsibilities
3. Identifying the gaps in these frameworks

For each framework from the defenders corpus we provide an overview identifying the source, purpose and audience of the material.  An overview of the material and its scope for general or specific cybersecurity topics including defense of AI systems is presented.  Further detail on the framework is provided, especially for practioners, summarized to capture the key concepts in and uses for the framework.  This material is intended to give defenders a systematic guide to understand how each framework is applicable to their work.

Organizational roles are categorized, and each framework is mapped to intended audiences and stakeholders.  This document presents a high-level mapping, and the framework detail mapping breaks down responsibilities further.  For each, a RACI matrix is used to map roles to the actions specified for the framework, indicating who is responsible, accountable, consulted and informed.  This mapping assists defenders in understanding the responsibilities associated for each framework, which roles are responsible and how.

Gaps in each framework are identified, and gaps common to all frameworks are surfaced in this document.  This points to extensions required to the system of frameworks in order to effectively secure AI systems.  Specific missing elements for each framework are also identified, indicating specific work that may be done to cover these gaps. 

### 2.6. Scope of Preparing Defenders of AI Systems

#### 2.6.1 In Scope

This document is focuced on AI Security which includes:
+ AI Threat Detection & Intelligence
+ Adversarial AI Red Teaming & AI-specific SOC
+ Zero Trust AI Access control & Supply Chain
+ Automated AI Security Monitoring & Runtime Protection
+ Secure AI Model Lifecycle
+ AI Security Compliance
+ Cybersecurity Frameworks Analysis and Identification of Gaps

#### 2.6.2 Out of Scope

Out of scop of this document is:
+ AI Data Privacy
+ AI Ethics Trust and Abuse (content, behavioral, account takeover, spam, misinformation)
+ AI Based Attacks 
+ AI Hallucination
+ Trustworthy AI

## 3. Changing Attack Surface with AI Adoption

### 3.1. AI Risk Scenarios

AI systems are fundamentally altering the cybersecurity landscape by expanding attack surfaces and introducing new risks. Their reliance on extensive computational resources, novel data formats, and vast data processing capabilities, combined with their inherently non-deterministic nature, makes them both a prime target and an enabler of sophisticated cyber threats. AI systems can be primary targets or enabler of the attacks on other assets, targets, infrastructures and business processes. 

#### 3.1.1 AI as a Target: Key Security Risks

AI systems can be directly targeted through various attack vectors, including:
+ Prompt Injection Attacks. Attackers manipulate AI models by injecting indirect or direct prompts that push the system beyond its intended operational boundaries. This can lead to outputs that are misleading, harmful, biased, or in violation of compliance regulations.
+ Supply Chain Attacks on AI Models. AI models and datasets, particularly pre-trained versions sourced from third parties, may contain hidden backdoors, biases, or embedded malicious triggers that can be exploited post-deployment.
+ Data Extraction and Privacy Risks. AI systems process sensitive data, including personally identifiable information (PII), proprietary intellectual property, and authentication tokens. Adversaries can extract this information from AI models during training or inference stages.
+ AI Infrastructure Exploitation
  + Code Execution Vulnerabilities: Attackers may manipulate AI systems to execute arbitrary code, leveraging AI computing resources for malicious purposes.
  + Denial-of-Service (DoS) Attacks: AI systems can be overwhelmed through various DoS techniques, disrupting availability.
  + Protocol Abuse: AI relies on distributed data processing, making it susceptible to adversarial-in-the-middle attacks and data injection threats targeting its communication protocols.

#### 3.1.2 AI as an Enabler of Cyber Attacks on other assets, targets, infrastructures

AI Systems can be leveraged to enhance precision, scalability, and automation in executing sophisticated attacks.
+ Augmenting Existing Attack Strategies
  + Multilingual and Context-Aware Threats: AI allows attackers to craft highly localized phishing campaigns in multiple languages, bypassing traditional detection mechanisms.
  + Adaptive Attacks: AI enhances reconnaissance capabilities, enabling tailored attack strategies against specific targets.
  + Automation of Attack Chains: AI streamlines adversarial workflows, including automation of credential theft, reconnaissance, and social engineering.
+ AI-Driven Denial-of-Service (DoS) Attacks. Attackers can exploit AI systems to initiate and orchestrate large-scale, adaptive DoS attacks against third-party infrastructure.
+ Emerging AI-Enabled Cyber Risks
  + Synthetic Identities & Deepfake-Based risks: AI-generated synthetic identities and deepfake technologies can bypass identity verification, authentication, and fraud detection systems.
  + Circumventing Zero Trust Security Models: AI-generated traffic patterns and behaviors can mimic behavior of legitimate systems and users, diminishing the efficacy of Zero Trust security models.
  + Social Engineering and Misinformation: AI-driven generation of fake text, audio, and video content enables large-scale manipulation of public opinion, reputational damage, and extortion schemes.

#### 3.1.3 AI Risks in Business Processes

AI integration into business operations introduces additional risk that organizations must address.
+ Overreliance on AI in Critical Processes. Excessive dependence on AI-driven automation in mission-critical functions can result in severe operational disruptions if the system fails or is compromised.
+ Reputational and Compliance Risks. Organizations deploying AI for customer interactions, regulatory compliance, or decision-making must consider non-deterministic nature of AI and additional risks of AI interacting on behalf of the organisation or business entity.
+ AI's Non-Deterministic Nature. AI's probabilistic decision-making processes can introduce significant variations in outcomes. For instance, minor data variations in AI-driven quality control in the pharmaceutical sector can impact product safety and efficacy of the final product.
+ Legal and Non-Repudiation Challenges. AI-driven decision-making raises accountability concerns, particularly in cases where AI autonomously makes business-critical or legally binding decisions.

### 3.2. AI Defender Frameworks Overview

The rapidly evolving landscape of AI systems demands a comprehensive and multi-layered approach to security, which necessitates a thorough understanding and cordinated implemention of various defender frameworks. These frameworks have emerged from different sectors - including government, industry, and academia - each bringing unique perspectives and strengths to AI security. The diversity of frameworks reflects the complex nature of AI systems and the varied threats they face, from data poisoning and model extraction to adversarial attacks and privacy breaches.

Defender frameworks operate at multiple levels, addressing technical, operational, and governance aspects of AI security. At the technical level, frameworks provide guidance for secure model development, testing procedures, and deployment practices. Operationally, they establish protocols for monitoring, incident response, and continuous improvement. From a governance perspective, these frameworks help organizations align AI security with broader risk management strategies and compliance requirements.

Modern AI security frameworks encompass various approaches to protecting AI systems. Some focus on risk management and mitigation strategies throughout the AI system lifecycle, while others emphasize regulatory compliance and security requirements specific to certain regions or industries. Additionally, frameworks developed from industry experience offer practical insights and methodologies developed through real-world implementation of AI systems at scale.

Together, these frameworks create a foundation for addressing the complex challenges of securing AI systems. While each framework has its own focus and strengths, they collectively provide comprehensive guidance for protecting AI models, securing sensitive data, and ensuring responsible AI deployment. Their complementary nature reflects the understanding that AI security requires multiple perspectives and approaches to address the full spectrum of potential threats and vulnerabilities.

### 3.3. Change needed for Defenders of AI Systems

MITRE ATLAS, NIST AI RMF, NIST AI AML provide defenders of AI systems with the most AI-specific guidance.  MITRE ATLAS covers adversarial tactics and techniques in detail, specifying attacker general goals against AI systems and the steps in the attack.  NIST CSF, NIST RMF, MITRE CAPEC and CISA Zero Trust Maturity Model provide more general security guidance, but could be expanded to better incorporate AI-specific risks, both for adversarial attacks and for vulnerabilities related to data, models or guardrails for AI systems.  The MIT Risk Repository offers insights for governance stakeholders, but doesn't provide enough low-level detail to inform defenders of AI systems about security measures.  Current defender frameworks require extensions to properly deal with securing AI systems, some themes of which are repeated across frameworks.

| **Gap**               | **What is missing**   |
|---------------------------|-----------------|
| **Threat model for AI** | Specific adversarial techniques including the mechanisms that exploit weaknesses particular to AI systems |
| **Incident Response or Mitigations** | Fine-grain detail on actions for playbooks for incident response, mitigation and prevention |
| **Integration with other Cybersecurity Frameworks** | Map framework details to other frameworks for interoperability |
| **AI Supply Chain Vulnerabilities** | Weaknesses in supply chain regarding data, code and models that create AI system vulnerabilities |
| **Model Behavior Analysis** | Determining nominal behavior, monitoring and analysis of any behavior drift in models to ensure their proper function |

In a new world dominated by AI powered ecosystems defenders of AI systems (CISOs, security architects, SOC teams, threat hunters, and AI governance experts) must adapt new strategies, frameworks, and methodologies to address evolving AI security threats.

![Changes Needed For Defenders Of AI Systems](/frameworks/images/ChangesNeededForDefendersOfAISystems.png "Changes Needed For Defenders Of AI Systems")

#### 3.3.1. AI-Specific Threat Intelligence & Adversarial Detection

**Change Needed:**
Expand MITRE ATT&CK(ATLAS), CAPEC, and STIX 2.1 to include AI-specific attack vectors and adversarial TTPs (Tactics, Techniques, and Procedures).

**Why?**
Existing cyber threat intelligence (CTI) models lack adversarial AI attack patterns, limiting defenders' ability to proactively detect AI-targeted threats.

**Solution:**

+ Develop AI-specific ATT&CK(ATLAS) tactics for adversarial ML threats (model poisoning, prompt injection, evasion).
+ Enhance SIEM and XDR detection with AI-focused threat telemetry.
+ Expand STIX/TAXII threat sharing to cover AI-specific Indicators of Compromise (IoCs).

#### 3.3.2. Zero Trust for AI Systems

**Change Needed:** 
Integrate Zero Trust principles into AI security using ZTMM.

**Why?** 

AI models and APIs lack proper identity verification, access controls, and segmentation, leaving them vulnerable to unauthorized inference attacks.

**Solution:**

+ Implement AI model segmentation and least-privilege access to AI APIs.
+ Require strong identity authentication and authorization for AI MLOps pipelines.
+ Use continuous risk-based monitoring to detect anomalous AI behavior.
  
#### 3.3.3. AI Model & Data Supply Chain Security

**Change Needed:**
Develop AI Software Bill of Materials (SBOM) and secure AI model provenance tracking.

**Why?** 
Pre-trained AI models and datasets introduce hidden security risks (backdoors, poisoned datasets, hidden triggers).

**Solution:**

+ Mandate Software Bill of Materials (SBOM) for AI models to track dependencies and provenance.
+ Implement trusted AI supply chain controls to prevent AI backdoors.
+ Require secure model validation before deployment to detect manipulation.
+ Leverage cryptographic mechanisms such as "AI model signatures", to verify authenticity and integrity of models
  
#### 3.3.4. AI-Specific Incident Response & SOC Automation

**Change Needed** 
Build AI incident response playbooks and integrate AI threat intelligence into SOC operations.

**Why?** 
AI security incidents (e.g., adversarial attacks, data poisoning) require specialized SOC workflows, forensics skills and AI-driven response automation.

**Solution:**

+ Develop SOC playbooks for AI security incidents (e.g., model rollback procedures after poisoning).
+ Enable real-time adversarial attack detection in SIEM/XDR.
+ Implement SOAR automation for AI threat mitigation and remediation.
  
#### 3.3.5. Secure AI Model Deployment & Runtime Protection

**Change Needed:** 
Introduce runtime security controls for AI inference (e.g., adversarial detection, model integrity checks).

**Why?** 
AI models deployed in production are vulnerable to runtime adversarial attacks (e.g., prompt injection, inference manipulation).

**Solution:**

+ Use AI runtime integrity verification to detect unauthorized model modifications.
+ Deploy adversarial input filtering to block real-time adversarial samples.
+ Implement model access control policies to prevent unauthorized API abuse.
+ Implement controls around leveraging user supplied data for re-training. 
  
#### 3.3.6. AI Security Awareness & Red Teaming

**Change Needed:** 
Establish AI Red Teaming exercises and train defenders on adversarial AI techniques.

**Why?** 
AI security remains a knowledge gap for traditional defenders, requiring specialized training on AI attack vectors.

**Solution:**

+ Conduct AI-specific Red Team assessments simulating adversarial AI attacks.
+ Train SOC analysts on AI security monitoring and AI adversarial techniques.
+ Integrate AI security into existing cybersecurity frameworks (NIST, OWASP, MITRE).
+ Train employees and leadership on AI security awarness, responsible AI and best practices.

## 4. Roles Addressed

Key stakeholders in AI systems apply frameworks such as NIST RMF/CSF, MITRE ATT&CK/ATLAS/CAPEC, OWASP and Zero Trust to ensure secure, compliant, and resilient AI deployment. Executives align strategy with regulatory and risk imperatives, while CISOs operationalize security controls and threat monitoring. Architects integrate these frameworks to design robust infrastructures, and IT and SOC teams employ them for system integrity, incident response, and proactive threat hunting. Service operations ensure compliance in deployment, auditors enforce policy adherence, and researchers develop resilient, fair AI models. Practitioners follow these guidelines, contributing to continuous improvement. Together, these roles enable responsible, secure AI adoption.

### 4.1. Persona

| **Role**               | **Key Focus**   |
|------------------------|-----------------|
| ***Executives*** | 1. Define the organization's risk tolerance and ensure alignment with business objectives.<br>2. Oversee governance frameworks for AI and cybersecurity.<br>3. Allocate resources for implementing and maintaining secure AI systems.<br>4. Ensure compliance with regulatory and legal requirements related to AI. |
| ***CISO/SSO*** | 1. Implement and oversee security strategies specific to AI-enabled systems<br>2. Develop policies for handling sensitive data and mitigating privacy risks<br>3. Engage in threat modeling and risk assessments for AI systems |
| ***Service Architects*** | 1. Design secure AI service architectures that mitigate risks during deployment and operation.<br>2. Ensure integration of AI systems aligns with organizational policies and goals.<br>3. Plan for scalability and resilience in AI service designs. |
| ***IT Architects*** | 1. Align AI and IT infrastructure to organizational needs while mitigating associated risks.<br>2. Establish secure pipelines for data handling, processing, and model deployment.<br>3. Collaborate with service architects to ensure interoperability of AI systems. |
| ***Security Architects*** | 1. Identify vulnerabilities specific to AI models and infrastructure.<br>2. Implement technical controls and mitigations for adversarial threats and attacks.<br>3. Integrate AI security measures into broader organizational cybersecurity frameworks. |
| ***IT Operations*** |1. Maintain AI systems and ensure secure day-to-day operations.<br>2. Monitor system performance and detect anomalous behavior that might indicate security breaches.<br>3. Respond to incidents and ensure system recovery in case of attacks. |
| ***SOC Operations*** | 1. Monitor AI systems for active threats and ongoing attacks.<br>2. Utilize tools such as MITRE ATT&CK and ATLAS to understand and mitigate AI-specific adversarial tactics.<br>3. Report and escalate AI security incidents in real time. <br>4. Monitor for threats, adversarial attacks, vulnerabilities, and incidents|
| ***Service Operations*** | 1. Ensure AI services meet security, resilience, and reliability standards during deployment<br>2. Oversee compliance and adherence to operational policies.<br>3. Support pre-deployment testing and post-deployment monitoring. |
| ***Auditors/Policy Makers*** | 1. Develop policies and standards for secure AI adoption.<br>2. Conduct audits to ensure compliance with established frameworks and guidelines.<br>Promote ethical and responsible AI use across sectors. |
| ***Researchers/Data Scientists*** | 1. Develop robust AI models that can resist adversarial attacks.<br>2. Investigate vulnerabilities and propose mitigations.<br>3. Work on explainability, fairness, and trustworthiness of AI systems. |
| ***Users/Practitioners*** | 1. Use AI systems according to organizational policies and ethical standards.<br>2. Report any suspicious behavior or potential vulnerabilities to the appropriate teams.<br>3. Provide feedback on the effectiveness and usability of AI systems for continuous improvement. |

<br><br>

### 4.2. Relevant Frameworks

| Target Audience                | Frameworks                                                                                             |
|--------------------------------|--------------------------------------------------------------------------------------------------------|
| **Executives**                 | NIST AI RMF, NIST CSF 2.0, Zero Trust Maturity Model (ZTMM) |
| **CISO/SSO**                   | NIST SP 800-37 (RMF), MITRE ATT&CK, MITRE ATLAS, NIST AI RMF, Zero Trust Maturity Model (ZTMM), OWASP Top 10 for LLMs, STIX |
| **Service Architects**         | NIST AI RMF, OWASP Top 10 for LLMs, Zero Trust Maturity Model (ZTMM), MITRE D3FEND, OCSF          |
| **IT Architects**              | NIST SP 800-37 (RMF), Zero Trust Maturity Model (ZTMM), OWASP Top 10 for LLMs, MITRE D3FEND, OCSF       |
| **Security Architects**        | MITRE ATT&CK, MITRE ATLAS, MITRE D3FEND, NIST AI AML, MITRE CAPEC, OWASP Top 10 for LLMs, Zero Trust Maturity Model (ZTMM) |
| **IT Operations**              | NIST CSF 2.0, NIST SP 800-37 (RMF), OWASP Top 10 for LLMs, Zero Trust Maturity Model (ZTMM), OCSF |
| **SOC Operations**             | MITRE ATT&CK, MITRE ATLAS, NIST AI AML, STIX, OCSF, OWASP Top 10 for LLMs |
| **Service Operations**         | NIST CSF 2.0, OWASP Top 10 for LLMs, Zero Trust Maturity Model (ZTMM)                      |
| **Auditors/Policy Makers**     | NIST AI RMF, NIST SP 800-37 (RMF), OWASP Top 10 for LLMs, NIST AI AML                 |
| **Researchers/Data Scientists**| OWASP Top 10 for LLMs, NIST AI RMF, MITRE ATT&CK, MITRE ATLAS, MITRE CAPEC, NIST AI AML, NIST AI GAI                   |
| **Users/Practitioners**        | NIST CSF 2.0, OWASP Top 10 for LLMs, NIST AI GAI                                                   |


### 4.3. Activities and Responsibilities

| Activity            | Executives | CISO/SSO | Service Architects | IT Architects | Security Architects | IT Operations | SOC Operations | Service Operations | Auditors/Policy Makers | Researchers / Data Scientists | Users / Practitioners |
|---------------------------|------------|----------|-------------------|--------------|-------------------|--------------|--------------|----------------|---------------------|-------------------------|------------------|
| AI Governance & Strategy  | **A**          | R        | C                 | C            | C                 | I            | I            | I              | C                   | I                         | I                |
| Risk Management & Compliance | **A**      | R        | C                 | C            | C                 | I            | C            | I              | R                   | C                         | I                |
| Security Policy Definition | C          | **A**        | C                 | I            | R                 | I            | C            | C              | R                   | C                         | I                |
| AI System Architecture    | I          | C        | R                 | **A**            | C                 | I            | I            | C              | I                   | C                         | I                |
| Threat Modeling & Assessment | I       | **A**        | C                 | C            | R                 | I            | R            | C              | C                   | C                         | I                |
| Incident Response & Monitoring | I     | **A**        | I                 | I            | C                 | R            | R            | I              | I                   | I                         | I                |
| Secure Deployment & Operations | I     | C        | **A**                 | R            | C                 | R            | C            | R              | I                   | I                         | I                |
| Compliance Auditing       | C          | C        | I                 | I            | C                 | I            | I            | I              | **A**                   | I                         | I                |
| AI Model Development      | I          | **A**        | C                 | C            | C                 | I            | I            | I              | I                   | R                         | I                |
| AI Ethics & Fairness      | **A**          | **A**        | C                 | C            | R                 | I            | I            | I              | R                   | R                         | I                |
| User Training & Awareness | C          | R        | C                 | I            | C                 | C            | C            | C              | I                   | I                         | **A**                |
| Continuous Improvement & Feedback | **A** | C        | R                 | C            | C                 | C            | C            | C              | R                   | C                         | C                |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

<br><br>

## 5. Takeaways and Conclusion

### 5.1. Key Takeaways:

1. **Framework Adaptation**: 
   - Existing frameworks like MITRE ATT&CK, NIST, and the AWS Generative AI Security Scoping Matrix provide a strong foundation but require specific adaptations to address AI-specific threats, such as adversarial attacks, prompt injection, and data poisoning. These adaptations should include developing AI-specific adversarial tactics and techniques to handle challenges unique to AI systems.

2. **AI-Specific Threats**: 
   - AI systems introduce vulnerabilities that traditional security frameworks do not entirely cover, such as adversarial machine learning, model theft, and data integrity issues. Addressing these threats requires developing tailored security solutions that focus on protecting AI models and their training data.

3. **Integration and Interoperability**: 
   - There is a need for seamless integration of AI security with existing cybersecurity frameworks. This integration ensures that AI systems do not operate in silos but are part of an organization's overall security posture. Frameworks should provide guidance on how AI-specific security solutions can be layered with traditional security practices.

4. **Role of Standardization**: 
   - Standardized frameworks like OCSF facilitate consistent threat detection and response by standardizing security data and improving interoperability across tools. This standardization is crucial for effective AI system security management.

5. **Holistic Security Approach**: 
   - A comprehensive approach that includes securing the AI supply chain, ensuring model integrity verification, and implementing continuous monitoring is essential for robust AI defense. This holistic strategy ensures that all aspects of AI system security are addressed, from development and deployment to operation and maintenance.

6. **Dynamic Risk Management**: 
   - The rapid evolution of AI technology and associated threats necessitates continuous updates and adaptations to existing frameworks. Risk management strategies must be dynamic, incorporating real-time threat intelligence and adaptive security measures to counter new and emerging threats effectively.

### 5.2. Conclusion:

To effectively defend AI systems, it is essential to address the identified gaps by enhancing existing frameworks with AI-specific threat models and integrating AI security into broader cybersecurity practices. This entails several key actions and considerations:

1. **Development of AI-Focused Security Measures**:
   - **AI-Specific Threat Models**: Frameworks need to develop detailed AI-specific threat models that encompass the unique vulnerabilities of AI systems, such as adversarial attacks, model inversion, and data poisoning. These threat models should guide the creation of security controls tailored to mitigate these risks.
   - **Adversarial Robustness**: Implementing adversarial robustness measures, such as adversarial training and anomaly detection, is critical to protect AI models from manipulation and exploitation by attackers.

2. **Integration into Broader Cybersecurity Practices**:
   - **Layered Security Approaches**: AI security should be integrated with traditional cybersecurity measures, creating a multi-layered defense strategy. This involves aligning AI-specific controls with existing security frameworks like MITRE ATT&CK, NIST, and Zero Trust models to ensure comprehensive protection.
   - **Cross-Framework Collaboration**: Encouraging collaboration between different framework developers and stakeholders will enhance the interoperability of security solutions, allowing organizations to adopt a more cohesive and unified approach to AI security.

3. **Promotion of Standardization**:
   - **Standardized Security Data**: Establishing standards for AI security data, such as logging formats and threat intelligence sharing, will improve data consistency and interoperability across different tools and platforms.
   - **Compliance and Regulation Alignment**: Ensuring that AI security practices align with existing regulatory requirements and industry standards will facilitate compliance and promote trust in AI systems.

4. **Continuous Adaptation and Risk Management**:
   - **Dynamic and Adaptive Risk Strategies**: AI security strategies must be dynamic, incorporating real-time threat intelligence and adaptive security measures to counter new and evolving threats effectively. This includes regular updates to threat models and security controls to reflect the latest advancements in AI technology and attack methods.
   - **Ongoing Monitoring and Feedback Loops**: Implementing continuous monitoring and feedback loops will enable organizations to promptly detect and respond to security incidents, ensuring that AI systems remain resilient and secure.

5. **Stakeholder Collaboration and Education**:
   - **Interdisciplinary Collaboration**: Bringing together stakeholders from various disciplines, including cybersecurity, AI development, risk management, and legal compliance, will foster a more comprehensive understanding of AI security challenges and solutions.
   - **Education and Awareness**: Raising awareness and providing education on AI security risks and best practices will empower organizations to better protect their AI systems and make informed decisions regarding their deployment and use.

This comprehensive approach to AI security will ensure that AI technologies can be securely adopted and managed across various applications, safeguarding them against an increasingly sophisticated threat landscape. By addressing the unique challenges posed by AI systems and continuously evolving security practices, organizations can build resilient AI systems that inspire confidence and drive innovation.

<br>


## 6. Appendix

### 6.1. Deep Dive in Frameworks

<br><br>

#### 6.1.1. NIST

##### 6.1.1.1. NIST CSF 2.0

###### 6.1.1.1.1. Overview

The NIST Cybersecurity Framework (CSF) 2.0, released in February 2024, is a flexible and non-prescriptive framework designed to help organizations manage cybersecurity risks effectively. It applies to entities of all sizes and across sectors, various missions, technologies (including AI), and regulatory environments, integrating cybersecurity with enterprise risk management.

<br><br>

###### 6.1.1.1.2. Scoping of AI system and/or cybersecurity purview

The NIST CSF 2.0 provides a flexible structure for scoping cybersecurity efforts, including AI systems, by integrating governance, risk management, and technical safeguards into a unified framework.

*By using the NIST CSF 2.0, organizations can effectively:*

1. *Define and document the scope of AI systems, aligning with organizational risk management practices.*
2. *Ensure that cybersecurity safeguards and monitoring mechanisms address the unique challenges of AI technologies.*
3. *Establish clear roles and responsibilities for managing risks associated with AI and other scoped systems.*
4. *Continuously improve scoping practices to adapt to emerging threats, technologies, and regulatory changes.*

<br><br>

###### 6.1.1.1.3. Persona addressed

***Target Audience***

+ **Executives:** Strategic alignment of cybersecurity with business goals.
+ **CISO/SSO:** Enterprise-wide cybersecurity governance and policy enforcement.
+ **Service Architects:** Designing secure AI systems in alignment with organizational policies.
+ **Security Architects:** Integrating security controls and risk management into AI architecture.
+ **IT Operations:** Implementing operational security controls and incident response.
+ **Service Operations:** Maintaining operational resilience and compliance in AI services.
+ **Auditors/Policy Makers:** Auditing cybersecurity policies and regulatory compliance.

<br><br>

***Roles and Activities***

| **Activity**                | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
| ------------------------------------------ | -------------- | ------------ | ---------------------- | ----------------- | ----------------------- | ----------------- | ------------------ | ---------------------- | -------------------------- | ------------------------------- | ----------------------- |
| **Govern (GV)**                            |                |              |                        |                   |                         |                   |                    |                        |                            |                                 |                         |
| Define AI cybersecurity governance scope   | **A**              | R            | C                      | C                 | C                       | I                 | I                  | I                      | C                          | C                               | I                       |
| Establish AI risk management strategy      | **A**              | R            | C                      | C                 | C                       | I                 | I                  | I                      | C                          | C                               | I                       |
| Develop supply chain risk policies for AI  | R              | **A**            | C                      | C                 | C                       | I                 | I                  | I                      | C                          | C                               | I                       |
| Define ethical AI usage guidelines         | **A**              | C            | R                      | C                 | C                       | I                 | I                  | I                      | C                          | C                               | I                       |
| **Identify (ID)**                          |                |              |                        |                   |                         |                   |                    |                        |                            |                                 |                         |
| Inventory AI systems and dependencies      | R              | C            | C                      | C                 | **A**                       | I                 | I                  | I                      | C                          | C                               | I                       |
| Conduct AI-specific risk assessments       | C              | R            | C                      | C                 | C                       | I                 | I                  | I                      | **A**                          | C                               | I                       |
| Map AI data flow and privacy risks         | R              | C            | C                      | C                 | C                       | I                 | I                  | I                      | **A**                          | C                               | I                       |
| Evaluate third-party AI components         | R              | C            | C                      | C                 | C                       | I                 | I                  | I                      | **A**                          | C                               | I                       |
| **Protect (PR)**                           |                |              |                        |                   |                         |                   |                    |                        |                            |                                 |                         |
| Implement access controls for AI systems   | I              | R            | C                      | C                 | C                       | **A**                 | R                  | C                      | C                          | C                               | I                       |
| Secure training data and models            | R              | C            | C                      | C                 | C                       | I                 | I                  | I                      | C                          | **A**                               | I                       |
| Encrypt data in AI pipelines               | I              | R            | C                      | C                 | C                       | **A**                 | R                  | C                      | C                          | C                               | I                       |
| Enforce secure software development        | C              | R            | C                      | C                 | **A**                       | I                 | I                  | I                      | C                          | C                               | I                       |
| **Detect (DE)**                            |                |              |                        |                   |                         |                   |                    |                        |                            |                                 |                         |
| Monitor AI models for adversarial inputs   | I              | R            | C                      | C                 | C                       | **A**                 | R                  | C                      | C                          | C                               | I                       |
| Detect anomalies in AI behavior            | I              | R            | C                      | C                 | C                       | **A**                 | R                  | C                      | C                          | C                               | I                       |
| Monitor AI supply chain for threats        | I              | R            | C                      | C                 | C                       | **A**                 | R                  | C                      | C                          | C                               | I                       |
| Analyze cybersecurity incidents in AI      | I              | **A**            | C                      | C                 | C                       | R                 | R                  | C                      | C                          | C                               | I                       |
| **Respond (RS)**                           |                |              |                        |                   |                         |                   |                    |                        |                            |                                 |                         |
| Activate incident response for AI attacks  | I              | **A**            | C                      | C                 | C                       | R                 | R                  | C                      | C                          | C                               | I                       |
| Mitigate data poisoning or model tampering | I              | R            | C                      | C                 | C                       | **A**                 | R                  | C                      | C                          | C                               | I                       |
| Report AI-related incidents to regulators  | I              | R            | C                      | C                 | C                       | I                 | I                  | C                      | **A**                          | C                               | I                       |
| Share threat intelligence with partners    | I              | R            | C                      | C                 | C                       | I                 | I                  | C                      | **A**                          | C                               | I                       |
| **Recover (RC)**                           |                |              |                        |                   |                         |                   |                    |                        |                            |                                 |                         |
| Rebuild or retrain compromised models      | I              | R            | C                      | C                 | C                       | I                 | I                  | C                      | C                          | **A**                               | I                       |
| Validate integrity of restored AI systems  | I              | R            | C                      | C                 | C                       | **A**                 | R                  | C                      | C                          | C                               | I                       |
| Communicate recovery progress              | I              | R            | C                      | C                 | C                       | I                 | I                  | C                      | **A**                          | C                               | I                       |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

<br><br>

###### 6.1.1.1.4. Guidance provided

The NIST Cybersecurity Framework (CSF) 2.0 provides guidance for organizations to manage cybersecurity risks effectively and integrate cybersecurity practices with broader enterprise risk management strategies. 

The NIST CSF 2.0 serves as a foundational tool to:

1. Standardize cybersecurity practices across organizations, sectors, and regions.
2. Integrate cybersecurity into business strategies and risk management frameworks.
3. Adapt to emerging challenges in technology, supply chains, and global threats.
4. Foster a culture of proactive risk management and continuous improvement.

<br><br>

###### 6.1.1.1.5. Detail on current framework

CSF consists of three core sections:

1. ***CSF Core:*** A hierarchy of cybersecurity outcomes categorized into six Functions: Govern, Identify, Protect, Detect, Respond, and Recover.
2. ***Profiles:*** Mechanisms to describe an organization's current and target cybersecurity postures.
3. ***Tiers:*** Four levels (Partial, Risk Informed, Repeatable, Adaptive) for evaluating the rigor of cybersecurity governance and risk management.
   
<br><br>

**CSF functions and key concepts applicable to scoping AI systems**

<br><br>

***1. Govern (GV): Defining Scope and Strategy***

| Function | Details |
| --- | --- |
| **GV.OC (Organizational Context)** | 1. Understand the mission and objectives of the AI system. |
| | 2. Assess internal and external stakeholders expectations, such as customers or regulatory bodies. |
| | 3. Document legal, regulatory, and contractual requirements related to AI systems, such as GDPR or AI-specific laws. |
| **GV.RM (Risk Management Strategy)** | 1. Define the organization's risk appetite and tolerance specific to AI and cybersecurity risks. |
| | 2. Develop a strategy to address risks from AI systems, such as adversarial attacks, model drift, and data poisoning. |
| | 3. Align AI system goals with broader enterprise risk management (ERM) strategies. |
| **GV.SC (Supply Chain Risk Management)** | 1. Integrate supply chain considerations for AI, such as third-party datasets, pre-trained models, and cloud services. |
| | 2. Establish roles, responsibilities, and contractual requirements with suppliers managing AI components. |

<br><br>

***2. Identify (ID): Mapping Scope and Risks***

| Function | Details |
| --- | --- |
| **ID.AM (Asset Management)*** | 1. Create an inventory of AI system components, including data sources, algorithms, hardware, and cloud services. |
|  | 2. Maintain a list of critical assets across the cybersecurity domain, ensuring dependencies are mapped. |
| **ID.RA (Risk Assessment)** | 1. Assess potential threats to the AI system, such as adversarial manipulation or data breaches. |
| | 2. Evaluate vulnerabilities in AI lifecycle stages (e.g., training, deployment) and external dependencies. |
| | 3. Quantify the likelihood and impact of risks, such as model exploitation or ethical violations. |
| **ID.IM (Improvement)** | 1. Use lessons learned from AI system incidents or evaluations to refine scoping. |
| | 2. Identify gaps in cybersecurity coverage or governance that impact AI-specific risks. |

<br><br>

***3. Protect (PR): Defining Safeguards Within Scope***

| Function | Details |
| --- | --- |
| **PR.AA (Identity Management and Access Control)** | 1. Enforce access controls to safeguard AI models, training data, and outputs. |
| | 2. Ensure identity management practices for users accessing AI systems are robust. |
| **PR.DS (Data Security)** | 1. Protect AI data at rest, in transit, and in use from unauthorized access and tampering. |
| | 2. Secure sensitive datasets used for training and inference processes. |
| **PR.PS (Platform Security)** | 1. Implement secure configurations for AI infrastructure, including cloud environments and hardware accelerators. |
| | 2. Prevent unauthorized software installation or execution within AI pipelines. |

<br><br>

***4. Detect (DE): Monitoring for Threats***


| Function | Details |
| --- | --- |
| **DE.CM (Continuous Monitoring)** | 1. Monitor AI system performance for anomalies, such as adversarial inputs or unexpected outputs. |
| | 2. Track network activity and system logs for indicators of compromise in AI components. |
| **DE.AE (Adverse Event Analysis)** | 1. Analyze anomalies in AI behavior to determine root causes, such as training data corruption or adversarial manipulation. |
| | 2. Correlate information from multiple sources, including threat intelligence, to understand incidents affecting AI systems. |

<br><br>

***5. Respond (RS): Taking Action Within Scope***


| Function | Details |
| --- | --- |
| **RS.MA (Incident Management)** | 1. Execute incident response plans for AI-related events, such as data breaches or system exploitation. |
| | 2. Coordinate responses with external stakeholders, including cloud providers and AI model vendors. |
| **RS.CO (Incident Communication)** | 1. Communicate incident details to internal teams, partners, and customers to mitigate downstream impacts. |
| | 2. Share lessons learned with stakeholders to improve future scoping efforts. |

<br><br>

***6. Recover (RC): Post-Incident Adjustments***


| Function | Details |
| --- | --- |
| **RC.RP (Incident Recovery Plan Execution)** | 1. Restore AI systems to operational status while ensuring the integrity of restored components, such as data and models. |
| | 2. Validate backups before using them for recovery to avoid reintroducing vulnerabilities. |
| **RC.CO (Incident Recovery Communication)** | 1. Inform stakeholders about recovery progress and measures taken to prevent recurrence. |
| | 2. Update scoping documents and risk assessments based on lessons learned. |

<br><br>

###### 6.1.1.1.6. What is missing for defenders of AI systems

The NIST CSF 2.0 provides a strong general framework but could be enhanced for AI system defenders by:

1. Incorporating AI-specific risks, such as adversarial attacks, model drift, and poisoning.
2. Addressing supply chain vulnerabilities unique to AI.
3. Providing detailed guidance for AI-focused incident response, recovery, and monitoring.
4. Integrating AI ethics, explainability, and transparency into governance practices.
5. Explicitly aligning with NIST AI RMF for a holistic approach to AI risk management.

<br><br>

##### 6.1.1.2. NIST RMF

###### 6.1.1.2.1. Overview
 
The NIST Risk Management Framework (RMF) is a structured framework, that integrates security and privacy into the lifecycle of information systems (including AI systems). It is widely used in federal agencies and private organizations to ensure a consistent, scalable, and effective method for protecting sensitive information.

The RMF is mandatory for federal agencies under laws like FISMA (Federal Information Security Modernization Act) and is recommended for private organizations seeking robust risk management practices. It aligns closely with the NIST Cybersecurity Framework (CSF) for broader risk management.

<br><br>

###### 6.1.1.2.2. Scoping of AI system and/or cybersecurity purview

In the NIST RMF, scoping is critical to the Prepare, Categorize, and Select steps. It ensures that the boundaries of the system, its operational context, and applicable controls are well-defined to align with organizational objectives, compliance requirements, and risk management strategies.

| **RMF Step**       | **Scoping Objective**                                                                                           |
|---------------------|----------------------------------------------------------------------------------------------------------------|
| **Prepare**         | Define the scope of the system, including boundaries, stakeholders, critical assets, and risk management strategies. |
| **Categorize**      | Identify the scope of information and systems to be categorized based on their confidentiality, integrity, and availability impact. |
| **Select**          | Determine the scope of security and privacy controls required to address identified risks and tailor them to system needs. |
| **Implement**       | Apply controls to all scoped system components and document how they address the defined security and privacy boundaries. |
| **Assess**          | Validate that scoped controls operate effectively within the defined boundaries and meet security/privacy objectives. |
| **Authorize**       | Ensure the scoped system and its components are evaluated for residual risks within the defined authorization boundary. |
| **Monitor**         | Continuously monitor scoped assets and controls to detect changes, emerging threats, and ensure compliance with security objectives. |

<br><br>

###### 6.1.1.2.3. Persona addressed

***Target Audience***

+ **Executives:** Risk management strategy and governance alignment.
+ **CISO/SSO:** Enterprise risk management and security compliance.
+ **IT Architects:** Secure infrastructure design and risk categorization.
+ **Security Architects:** Control selection, threat modeling, and risk assessment.
+ **IT Operations:** Implementation and monitoring of security controls.
+ **Auditors/Policy Makers:** Compliance auditing and regulatory risk management.

<br><br>

***Roles and Activities***

| **Activity**                  | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|------------------------------------------|------------|----------|--------------------|---------------|---------------------|---------------|---------------|--------------------|---------------------------|-----------------------------|-----------------------|
| **Prepare**                              | **A**          | R        | C                 | C             | I                   | I             | I             | I                  | C                         | I                           | I                     |
| • Assign Roles and Responsibilities        | **A**          | R        | C                 | -             | -                   | -             | -             | -                  | C                         | -                           | -                     |
| • Risk Management Strategy                | **A**          | R        | C                 | C             | -                   | -             | -             | -                  | C                         | -                           | -                     |
| • Organization-Wide Risk Assessment        | **A**          | R        | C                 | -             | -                   | -             | -             | -                  | C                         | -                           | -                     |
| **Categorize**                           | **A**          | R        | C                 | C             | -                   | -             | -             | -                  | C                         | -                           | -                     |
| • Information System Categorization        | **A**          | R        | C                 | C             | R                   | -             | -             | -                  | C                         | -                           | -                     |
| **Select**                               | **A**          | R        | C                 | C             | R                   | -             | -             | -                  | C                         | -                           | -                     |
| • Select Security and Privacy Controls      | **A**          | R        | C                 | C             | R                   | -             | -             | -                  | C                         | -                           | -                     |
| • Tailor Controls                           | **A**          | R        | C                 | C             | R                   | -             | -             | -                  | C                         | -                           | -                     |
| **Implement**                            | **A**          | R        | -                 | R             | R                   | R             | C             | C                  | C                         | -                           | -                     |
| • Implement Controls                        | **A**          | R        | -                 | R             | R                   | R             | C             | C                  | C                         | -                           | -                     |
| **Assess**                               | **A**          | R        | C                 | C             | R                   | C             | C             | -                  | R                         | -                           | -                     |
| • Assess Control Effectiveness             | **A**          | R        | C                 | C             | R                   | C             | C             | -                  | R                         | -                           | -                     |
| **Authorize**                            | **A**          | R        | C                 | C             | R                   | -             | -             | -                  | R                         | -                           | -                     |
| • Risk-Based Authorization Decision         | **A**          | R        | C                 | C             | R                   | -             | -             | -                  | R                         | -                           | -                     |
| **Monitor**                              | **A**          | R        | -                 | C             | R                   | R             | R             | R                  | C                         | -                           | -                     |
| • Continuous Monitoring                     | **A**          | R        | -                 | C             | R                   | R             | R             | R                  | C                         | -                           | -                     |
| • Document Changes to System and Controls   | **A**          | R        | -                 | C             | R                   | R             | R             | R                  | C                         | -                           | -                     |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

<br><br>

###### 6.1.1.2.4. Guidance provided

The NIST RMF provides general risk management principles that can be tailored to address the unique risks associated with AI systems. 

<br><br>

###### 6.1.1.2.5. Detail on current framework

Applying the NIST Risk Management Framework (RMF) to AI systems involves tailoring the framework's steps to address the unique challenges and risks associated with AI technologies. AI systems introduce complexities such as data bias, model integrity, adversarial vulnerabilities, and explainability requirements, which must be integrated into the RMF process.

<br><br>

| **RMF Step**       | **Objective**                                                                                   | **AI-Specific Tasks**                                                                                                  | **Output**                                                                                 |
|---------------------|-----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| **Prepare**         | Establish readiness to manage AI-specific risks.                                              | Define AI system boundaries, identify stakeholders, develop AI-specific risk management strategy.                      | AI-specific risk strategy and system inventory.                                           |
| **Categorize**      | Determine the AI system's security impact level.                                              | Evaluate sensitivity of data, assess impact of model failures, identify AI-specific vulnerabilities (e.g., adversarial). | Categorization documentation that includes AI-specific risks.                            |
| **Select**          | Choose controls to mitigate AI risks.                                                         | Tailor controls for privacy, bias, adversarial robustness, and explainability. Integrate supply chain risk management.  | Control baselines tailored for the AI system.                                             |
| **Implement**       | Deploy controls within the AI system's lifecycle.                                             | Apply data governance policies, implement runtime protections, document model and data lineage.                        | Evidence of implemented controls (e.g., secure pipelines, data protection measures).      |
| **Assess**          | Validate that controls mitigate AI-specific risks effectively.                                | Test for model robustness, bias detection, performance validation, and incident response readiness.                    | Security Assessment Report (SAR) with AI-specific findings.                              |
| **Authorize**       | Approve the AI system for operation after evaluating residual risks.                          | Review ethical and regulatory compliance, evaluate residual risks with input from data scientists and legal advisors.   | Authorization decision (ATO or denial).                                                  |
| **Monitor**         | Continuously track AI system risks and update controls as needed.                             | Monitor for model drift, detect adversarial attacks, maintain data usage logs, automate monitoring processes.           | Updated risk assessments and monitoring reports.                                          |

<br><br>

###### 6.1.1.2.6. What is missing for defenders of AI systems

While the RMF is adaptable, it lacks AI-specific extensions that address unique risks, such as adversarial threats, explainability, bias, and dynamic system behaviors. 

Defenders need:
1. Tailored threat models for AI.
2. Explicit controls for adversarial robustness, fairness, and privacy.
3. Enhanced guidance for real-time monitoring, secure AI development, and incident response.
4. Focus on training and interdisciplinary collaboration for AI and cybersecurity teams.

<br><br>

##### 6.1.1.3. NIST AI RMF 1.0

###### 6.1.1.3.1. Overview

The NIST AI RMF 1.0, published in January 2023, is a voluntary framework designed to help organizations manage risks associated with artificial intelligence (AI) systems. It aims to promote the responsible design, development, deployment, and use of AI technologies while mitigating potential harms. 

The NIST AI RMF serves as a comprehensive tool for organizations to navigate the complexities of managing AI risks, ensuring their systems are secure, reliable, and aligned with ethical and societal standards.

<br><br>

###### 6.1.1.3.2. Scoping of AI system and/or cybersecurity purview

In the AI RMF, cybersecurity plays a key role in ensuring the confidentiality, integrity, and availability of AI systems. Scoping for cybersecurity purview involves identifying specific areas of focus to protect the AI system and its data.

<br><br>

| **Category**            | **Description**                                                                                                   | **Examples**                                                                                     |
|--------------------------|-------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| **Threat Landscape**     | Identifying cybersecurity threats specific to AI systems.                                                       | Adversarial attacks, data poisoning, model theft, system exploitation, inference attacks.        |
| **Security Requirements**| Establishing security objectives to protect AI systems and their data.                                           | Secure data storage, protect model infrastructure, safeguard APIs, control third-party access.    |
| **System Boundaries**    | Defining components and scope for cybersecurity measures.                                                        | Data storage, model infrastructure, APIs, third-party tools.                                     |
| **Cybersecurity Controls**| Applying technical and organizational measures to secure the AI system.                                          | Access control, encryption, monitoring, resilience planning.                                     |
| **Regulatory Compliance**| Ensuring adherence to legal and regulatory standards related to cybersecurity.                                   | FISMA, GDPR, CCPA, HIPAA, NIST SP 800-53, SP 800-171.                                            |
| **Incident Response**    | Planning for and responding to cybersecurity incidents affecting AI systems.                                     | Addressing model poisoning, adversarial attacks, recovery from data corruption.                  |
| **Governance and Oversight**| Integrating cybersecurity considerations into organizational governance and risk management practices.           | Assigning roles, monitoring risks, ensuring accountability.                                      |

<br><br>

###### 6.1.1.3.3. Persona addressed

***Target Audience***

+ **Executives:** Strategic governance, ethical AI, risk management alignment.
+ **CISO/SSO:** Implementing AI-specific risk management policies and compliance.
+ **Service Architects:** Designing AI systems with integrated risk controls.
+ **Security Architects:** Threat modeling and security design for adversarial resilience.
+ **Auditors/Policy Makers:** Ensuring AI governance, risk, and compliance reporting.
+ **Researchers/Data Scientists:** Ethical AI development and risk mitigation research.

<br><br>

***Roles and Activities***

| **Activity**                  | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|---------------------------------------|---------------|--------------|------------------------|-------------------|------------------------|------------------|------------------|------------------|----------------------|------------------------|------------------|
| **1. Govern**                        |              |             |                       |                  |                       |                 |                 |                 |                     |                       |                 |
| Establish governance framework        | **A**             | R            | C                      | C                 | C                      | -                | -                | -                | R                    | -                      | -                |
| Define AI risk tolerance levels       | **A**             | R            | C                      | C                 | C                      | -                | -                | -                | R                    | -                      | -                |
| Establish policies and procedures     | **A**             | R            | C                      | C                 | R                      | -                | -                | -                | R                    | -                      | -                |
| Assign risk management roles          | **A**             | R            | C                      | -                 | R                      | -                | -                | -                | R                    | -                      | -                |
| **2. Map**                           |              |             |                       |                  |                       |                 |                 |                 |                     |                       |                 |
| Identify AI-specific risks            | C             | R            | **A**                      | C                 | R                      | -                | -                | -                | R                    | R                      | -                |
| Identify societal impacts of AI       | C             | R            | C                      | -                 | R                      | -                | -                | -                | **A**                    | C                      | I                |
| Map risks across AI lifecycle stages  | C             | R            | **A**                      | C                 | R                      | C                | -                | -                | -                    | -                      | -                |
| Contextualize risks to applications   | C             | R            | **A**                      | C                 | R                      | C                | -                | -                | R                    | C                      | -                |
| **3. Measure**                       |              |             |                       |                  |                       |                 |                 |                 |                     |                       |                 |
| Assess system performance risks       | C             | C            | **A**                      | R                 | R                      | R                | -                | -                | -                    | R                      | -                |
| Validate trustworthiness criteria     | C             | R            | **A**                      | R                 | R                      | -                | -                | -                | -                    | C                      | -                |
| Monitor emergent risks                | C             | R            | C                      | C                 | R                      | -                | **A**                | -                | -                    | -                      | -                |
| Conduct TEVV (Testing, Evaluation)    | I             | R            | -                      | R                 | **A**                      | -                | C                | -                | -                    | R                      | -                |
| Document risk measurement processes   | I             | R            | C                      | -                 | **A**                      | -                | C                | -                | -                    | -                      | -                |
| **4. Manage**                        |              |             |                       |                  |                       |                 |                 |                 |                     |                       |                 |
| Develop mitigation strategies         | C             | R            | C                      | R                 | **A**                      | -                | C                | -                | -                    | -                      | -                |
| Prioritize risks for action           | C             | R            | -                      | -                 | **A**                      | -                | -                | -                | R                    | -                      | -                |
| Implement risk mitigation controls    | I             | R            | -                      | R                 | **A**                      | R                | R                | R                | -                    | -                      | -                |
| Monitor effectiveness of actions      | I             | R            | -                      | -                 | **A**                      | R                | R                | -                | -                    | -                      | -                |
| Communicate residual risks            | C             | R            | -                      | -                 | R                      | -                | -                | -                | **A**                    | -                      | -                |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement



<br><br>

###### 6.1.1.3.4. Guidance provided

The NIST AI RMF 1.0 provides actionable guidance to manage AI risks effectively, ensuring systems are trustworthy, safe, and aligned with organizational goals and societal values. It emphasizes flexibility, continuous improvement, and stakeholder collaboration to address the complexities of deploying AI responsibly.

<br><br>

###### 6.1.1.3.5. Detail on current framework

AI RMF framework structure consists of two main sections: Framing Risk and Core Functions.

<br><br>

***Framing Risk***


| **Aspect**              | **Description**                                                                                                                                                                     |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Risk Identification** | AI risks are identified across technical and socio-technical dimensions, considering both anticipated and emergent risks throughout the AI lifecycle.                                |
| **Dynamic Risks**        | AI risks evolve over time due to changing data, deployment contexts, and interactions with other systems or users, requiring continuous assessment and adaptation.                   |
| **Trustworthiness Characteristics** | Trustworthy AI must demonstrate attributes such as being valid and reliable, safe, privacy-enhanced, secure, accountable, transparent, explainable, and fair.                        |
| **Key Challenges**       | Challenges include managing emergent risks, addressing biases, ensuring transparency and explainability, and balancing trade-offs between trustworthiness attributes (e.g., fairness vs. accuracy). |
| **Stakeholders**         | Includes developers, operators, end users, impacted communities, and regulators who contribute to or are affected by AI systems.                                                   |
| **Ethical and Societal Risks** | Risks include harm to civil liberties, discrimination, inequities, and environmental impacts, requiring socio-technical alignment to mitigate potential negative outcomes.                          |

<br><br>

***Core Functions***

| **Function**   | **Purpose**                                                                                                   | **Key Activities**                                                                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Govern**     | Establishes governance structures and processes for AI risk management.                                      | 1. Define roles and accountability. |
|  |  | 2. Align AI development with organizational values. |
|  |  | 3. Integrate AI risks into enterprise risk management (ERM). |
| **Map**        | Identifies and contextualizes AI risks throughout the AI lifecycle.                                          | 1. Identify risks across design, build, deployment, and operation stages. |
|  |  | 2. Assess societal, ethical, and operational impacts of AI systems. |
| **Measure**    | Evaluates risks and trustworthiness using quantitative and qualitative metrics.                              | 1. Conduct TEVV (Testing, Evaluation, Verification, Validation). |
|  |  | 2. Assess trustworthiness attributes like bias, fairness, and robustness. |
| **Manage**     | Prioritizes and mitigates risks to minimize harm and enhance AI system reliability.                          | 1. Implement mitigation strategies. |
|  |  | 2. Monitor systems for emergent risks. |
|  |  | 3. Communicate residual risks to stakeholders. |

<br><br>

###### 6.1.1.3.6. What is missing for defenders of AI systems

While the NIST AI Risk Management Framework (AI RMF 1.0) provides comprehensive guidance for managing AI risks, there are areas where it could be enhanced to better address cybersecurity concerns, such as adversarial threats, malicious use, and other vulnerabilities. 

<br><br>

##### 6.1.1.4. NIST AI RMF 1.0 for Generative AI (GAI)

###### 6.1.1.4.1. Overview

NIST AI RMF 1.0 for Generative AI (GAI) provides guidance on managing risks associated with generative AI (GAI) systems. The framework offers a structured approach to managing GAI risks through proactive governance, lifecycle management, and continuous improvement based on empirical evidence and stakeholder feedback​. It is a companion resource to the NIST AI Risk Management Framework (AI RMF 1.0), addressing risks unique to generative AI.

<br><br>

###### 6.1.1.4.2. Scoping of AI system and/or cybersecurity purview

As an extension of the NIST AI RMF 1.0 this framework inherits most of the characteristics of its parent. However there are some key scoping deferences specific to Generative AI.


| **Aspect**                 | **NIST AI RMF**    | **NIST AI RMF GAI**      |
|----------------------------|--------------------|-----------------------------------|
| **Purpose**                | A broad framework for managing risks across all types of AI systems, regardless of specific applications.             | Focused specifically on risks unique to or exacerbated by Generative AI (GAI) systems.   |
| **Scoping Applicability**  | Covers AI systems across sectors and use cases without being specific to any particular AI technology.  | Tailored to cross-sectoral risks and specific GAI use cases, such as those involving LLMs, multimodal models, or fine-tuned systems. |
| **Focus on AI Lifecycle**  | Covers all lifecycle stages but emphasizes high-level principles for governance, design, deployment, and monitoring. | Addresses risks specific to GAI at each stage of the lifecycle, including risks during training (e.g., data quality), deployment, and operation. |
| **Dual-Use Considerations**| General acknowledgment of dual-use risks (e.g., misuse of AI tools). | Detailed focus on GAI misuse risks, such as generating harmful content (e.g., deepfakes, CBRN design, disinformation). |
| **Cybersecurity Scope**    | Cybersecurity considered as a subset of AI risks, with focus on general vulnerabilities. | Addresses specific cybersecurity risks in GAI, such as prompt injection, data poisoning, adversarial misuse, and reverse engineering. |
| **Transparency and Provenance** | Recommends transparency and documentation of AI system components and decision-making processes.  | Focuses extensively on content provenance, emphasizing tracing training data, generated outputs, and model lineage to ensure transparency. |
| **Third-Party Integration**| Broad recommendation to assess and manage risks from third-party data or models.  | Emphasizes the scale of third-party reliance in GAI systems (e.g., datasets, pre-trained models) and risks from non-transparent integration. |
| **Data Privacy**           | General principles for protecting user data and complying with privacy regulations.  | Focuses on data memorization and inference risks in GAI, which could expose sensitive personal data from training datasets. |
| **Environmental Impacts**  | Brief mention of energy efficiency and resource usage in AI systems.  | Explicit concern about resource-intensive training and inference in GAI systems and their carbon footprints.       |
| **Bias and Homogenization**| Broad treatment of bias in AI systems and mitigation through diverse datasets and inclusive design.  | Highlights specific GAI issues, such as amplifying societal biases, representational harms, and risks of algorithmic monoculture. |
| **Incident Response**      | General recommendations for incident monitoring and response.   | Detailed guidance for incident response plans specific to third-party components, adversarial attacks, and provenance failures in GAI. |
| **Governance**             | High-level governance principles applicable to various organizational contexts. | Emphasizes governance tailored to GAI risks, including independent evaluations, human-AI configuration, and critical thinking policies. |

<br><br>

###### 6.1.1.4.3. Persona addressed

***Target Audience***

+ **Executives:** Strategic governance, risk management, and compliance for Generative AI deployment.
+ **CISO/SSO:** Establishing AI-specific security policies, risk controls, and compliance standards for GAI systems.
+ **Service Architects:** Designing secure Generative AI services, including LLMs, with integrated risk controls.
+ **IT Architects:** Secure infrastructure design and deployment pipelines for GAI models.
+ **Security Architects:** Implementing adversarial defense against prompt injection, model inversion, membership inference, and model theft.
+ **IT Operations:** Maintaining secure deployment, operational integrity, and incident response for GAI systems.
+ **SOC Operations:** Monitoring for adversarial attacks, anomalies, and threats specific to GAI models.
+ **Service Operations:** Ensuring operational security and resilience for Generative AI services.
+ **Auditors/Policy Makers:** Auditing compliance with GAI-specific security, ethical guidelines, and regulatory requirements.
+ **Researchers/Data Scientists:** Developing secure GAI models with adversarial robustness, privacy-preserving techniques, and ethical AI design.
+ **Users/Practitioners:** Adhering to security policies, ethical guidelines, and reporting security incidents in GAI usage.

<br><br>

***Roles and Activities***

| **Activity**                 | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|--------------------------------------------|---------------|--------------|----------------------|----------------|-------------------|--------------|---------------|-----------------|----------------------|----------------------|------------------|
| **1. Govern**                        |              |             |                       |                  |                       |                 |                 | 
| Data privacy compliance                   | **A**             | R            | C                    | C              | C                 | I            | I             | I               | R                    | -                    | I                |
| Third-party vendor assessment             | **A**             | R            | C                    | C              | R                 | I            | I             | I               | R                    | I                    | -                |
| Compliance with regulations               | **A**             | R            | C                    | I              | I                 | -            | -             | -               | R                    | -                    | -                |
| Policy development & governance           | **A**             | R            | C                    | I              | I                 | -            | -             | -               | R                    | -                    | -                |
| Transparency & explainability             | **A**             | R            | C                    | C              | I                 | -            | -             | -               | R                    | C                    | I                |
| Legal compliance auditing                 | I             | R            | C                    | -              | -                 | -            | -             | -               | **A**                   | -                    | -                |
| Ethical AI practices & policy alignment   | **A**             | R            | C                    | I              | I                 | -            | -             | -               | R                    | C                    | I                |
| **2. Map**                        |              |             |                       |                  |                       |                 |                 | 
| Define AI system scope                     | **A**             | R            | C                    | R              | C                 | I            | I             | I               | C                    | C                    | I                |
| Identify risks across lifecycle stages     | **A**             | R            | C                    | C              | R                 | I            | I             | I               | C                    | C                    | I                |
| System architecture design                 | **A**             | C            | R                    | R              | C                 | -            | -             | -               | C                    | C                    | -                |
| **3. Measure**                        |              |             |                       |                  |                       |                 |                 | 
| Model training & validation               | I             | C            | C                    | C              | C                 | -            | -             | **A**               | C                    | R                    | -                |
| Post-deployment monitoring                | I             | R            | C                    | C              | R                 | **A**            | R             | C               | C                    | C                    | I                |
| Security vulnerability management         | I             | R            | C                    | C              | **A**                 | R            | R             | C               | C                    | -                    | -                |
| Provenance & accountability               | **A**             | R            | C                    | C              | C                 | -            | -             | -               | C                    | C                    | -                |
| Feedback & continuous improvement         | **A**             | R            | C                    | C              | C                 | I            | I             | I               | C                    | R                    | I                |
| **4. Manage**                        |              |             |                       |                  |                       |                 |                 | 
| Risk mitigation strategy development      | **A**             | R            | C                    | C              | R                 | -            | -             | -               | C                    | R                    | -                |
| Incident response planning                | I             | R            | C                    | C              | R                 | C            | **A**             | C               | C                    | -                    | -                |
| System deployment                         | I             | C            | C                    | R              | R                 | **A**            | -             | R               | -                    | -                    | -                |
| Stakeholder communication                 | **A**             | R            | C                    | I              | C                 | -            | -             | -               | R                    | C                    | C                |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

<br><br>

###### 6.1.1.4.4. Guidance provided

The NIST AI 600-1 (GUI) provides a structured framework for managing risks unique to generative AI (GAI) systems, emphasizing transparency, accountability, and adaptability. It identifies and addresses technical, misuse, and societal risks associated with GAI, such as confabulation, bias amplification, disinformation, and cybersecurity vulnerabilities. 

The guidance aligns with NIST AI RMF 1.0 functions—Govern, Map, Measure, and Manage—and emphasizes trustworthy AI attributes, including fairness, safety, and privacy. Organizations are encouraged to implement robust governance, transparency in content provenance, independent evaluations, and effective risk mitigation strategies throughout the AI lifecycle. 

This evolving framework ensures organizations can navigate the complex and rapidly advancing generative AI landscape while adhering to ethical and regulatory standards.

<br><br>

###### 6.1.1.4.5. Detail on current framework

The NIST AI 600-1 Framework is a specialized companion resource to the NIST AI RMF 1.0, tailored to address risks specific to Generative Artificial Intelligence (GAI). This document provides actionable guidance for organizations to manage the unique challenges posed by generative AI systems, such as large language models (LLMs) and multimodal generative tools.

<br><br>

***Key Risks Associated with GAI***


| **Risk Category**    | **Description**  |
|----------------------|------------------|
| **Technical Risks**   | **1. Confabulation**: GAI systems generating inaccurate or false content, leading to user deception. |
|                       | **2. Data Privacy**: Potential for GAI to leak sensitive personal data through memorization or inferencing. |
|                       | **3. Bias and Homogenization**: Amplification of systemic biases and reduced diversity in outputs, leading to societal harms. |                           |
|                       | **4. Environmental Impact**: High computational resource usage for training and inference, contributing to significant carbon footprints.                |
| **Misuse Risks**      | **1. Malicious Content**: Use of GAI to create harmful content such as disinformation, deepfakes, or illegal materials. |
|                       | **2. Cybersecurity Exploitation**: Automation of cyberattacks, such as phishing, malware creation, and vulnerabilities to prompt injection or data poisoning. |
| **Societal Risks**    | **1. Erosion of Public Trust**: Disinformation campaigns undermining confidence in institutions and facts. |
|                       | **2. Representational Harms**: Reinforcing harmful stereotypes in GAI outputs, particularly in text-to-image models. |
|                       | **3. Economic Disruption**: Long-term impacts on labor markets, intellectual property, and creative industries. |

<br><br>

***NIST AI RMF Functions Applied to GAI***


| **Function** | **Key Actions**  |
|--------------|------------------|
| **Govern**   | 1. Align GAI development with legal and regulatory requirements (e.g., data privacy, intellectual property).                                               |
|              | 2. Foster accountability by establishing organizational risk tolerances and governance structures.                                                         |
|              | 3. Develop policies for transparency, including documenting training data provenance and model decisions.                                                   |
|              | 4. Ensure robust oversight through independent evaluations proportional to system risks.                                                                   |
| **Map**      | 1. Identify and document risks throughout the AI lifecycle, including technical, operational, and societal dimensions.                                      |
|              | 2. Analyze dependencies on third-party components, such as datasets, libraries, and pre-trained models.                                                    |
|              | 3. Define roles and responsibilities for stakeholder engagement across teams and external parties.                                                         |
| **Measure**  | 1. Conduct pre-deployment testing for robustness, fairness, and safety, including red-teaming and validation.                                              |
|              | 2. Monitor and evaluate system performance for biases, confabulation, and environmental impacts.                                                               |
|              | 3. Implement tools for assessing content provenance, such as watermarking or cryptographic methods, to trace AI-generated outputs.                         |
| **Manage**   | 1. Develop incident response plans to address adversarial attacks (e.g., data poisoning, prompt injection).                                                |
|              | 2. Establish protocols for safe decommissioning of systems, addressing dependencies and user interactions.                                                 |
|              | 3. Engage stakeholders, including end users and policymakers, to address ethical and societal impacts associated with GAI.                                 |

<br><br>

###### 6.1.1.4.6. What is missing for defenders of AI systems

While the NIST AI 600-1 Framework provides a comprehensive approach for managing risks associated with generative AI, several aspects critical for defenders of AI systems (e.g., cybersecurity teams, incident responders, and risk managers) are either missing or could benefit from additional detail.

<br><br>

##### 6.1.1.5. NIST AI Adversarial Machine Learning (AML)

###### 6.1.1.5.1. Overview

The NIST AI 100-2e2023 - Adversarial Machine Learning framework provides a comprehensive taxonomy and terminology for understanding adversarial machine learning (AML), addressing the security, resilience, and trustworthiness of AI systems. It categorizes attacks based on learning stages, attacker objectives, capabilities, and knowledge levels, covering evasion, poisoning, privacy, and abuse threats across predictive and generative AI systems. 

The framework highlights the unique challenges posed by adversarial attacks, such as evasion via adversarial inputs, poisoning training data or models, and extracting sensitive information from large language models or generative systems. 

It proposes mitigation strategies, including adversarial training, differential privacy, and formal verification, while acknowledging inherent trade-offs between robustness, accuracy, and fairness. Emphasizing the dynamic and evolving nature of adversarial threats, the framework advocates for scalable, context-aware defenses and highlights unresolved issues like supply chain risks, multimodal vulnerabilities, and adaptive attack mitigation. 

<br><br>

###### 6.1.1.5.2. Scoping of AI system and/or cybersecurity purview

The NIST AI 100-2e2023 Framework scoping provides a detailed purview of AI systems, adversarial threats, and cybersecurity practices. It establishes clear boundaries around AI lifecycle stages, data modalities, and attack vectors, integrating AML into the broader cybersecurity landscape. 

| **Aspect** | **Scope Description**  |
|------------|------------------------|
| **AI System Categories**       | Covers Predictive AI (PredAI) and Generative AI (GenAI), addressing adversarial risks across all lifecycle stages (design, training, deployment, post-deployment). |
| **Lifecycle Stages**           | 1. Design/Development: Threat modeling and robust architecture. |
|  | 2. Training: Data validation, adversarial training. |
|  | 3. Deployment: Monitoring and real-time defenses. |
|  | 4. Post-Deployment: Updates and anomaly detection. |
| **Data Modalities**            | Includes images, text, audio, video, cybersecurity logs, and multimodal systems requiring specialized defenses and monitoring.                                     |
| **Threat Taxonomy**            | 1. Training-Stage Risks: Poisoning and backdoors. |
|  | 2. Deployment-Stage Risks: Evasion, prompt injection, model extraction. |
|  | 3. Privacy Risks: Membership inference, data leakage. |
| **Supply Chain Security**      | Ensures the integrity of third-party datasets, pre-trained models, and APIs.                                                                                     |
| **Mitigation Strategies**      | 1. Adversarial training and formal verification. |
|  | 2. Real-time anomaly detection. |
|  | 3. Data validation and provenance checks. |
|  | 4. Privacy-preserving methods. |
| **Interdisciplinary Roles**    | Collaboration across AI developers, cybersecurity teams, legal teams, and executive leadership.                                                                 |
| **Threat Intelligence Sharing**| Mechanisms for cross-organization sharing of adversarial incidents and mitigations.                                                                              |
| **Scalability of Defenses**    | Focuses on lightweight, resource-efficient defenses for real-time applications and scalable monitoring.                                                           |
| **Generative AI-Specific Risks**| - Mitigates prompt injection, harmful content, and data leakage. <br> - Monitors model outputs for adversarial manipulation.                                      |
| **Ethical and Legal Considerations** | - Balances robustness with fairness and transparency. <br> - Ensures regulatory compliance in AI operations.                                                  |

<br><br>

###### 6.1.1.5.3. Persona addressed

***Target Audience***

+ **Executives:** Strategic risk management and governance for adversarial AI threats.
+ **CISO/SSO:** Implementing adversarial defense strategies, security policies, and compliance for AML.
+ **Service Architects:** Designing resilient AI systems with adversarial robustness and input validation.
+ **IT Architects:** Secure infrastructure design to protect against adversarial inputs and model theft.
+ **Security Architects:** Implementing advanced threat modeling, defense strategies, and countermeasures against adversarial attacks.
+ **IT Operations:** Securing deployment pipelines and maintaining operational integrity against adversarial threats.
+ **SOC Operations:** Real-time monitoring, detection, and incident response for adversarial attacks, using AI-specific threat intelligence.
+ **Service Operations:** Ensuring resilience and operational security against adversarial manipulation and output integrity attacks.
+ **Auditors/Policy Makers:** Auditing compliance with AML-specific security standards and adversarial defense policies.
+ **Researchers/Data Scientists:** Developing adversarially robust models, implementing adversarial training, and researching adversarial AI behaviors.
+ **Users/Practitioners:** Adhering to security policies and reporting anomalies related to adversarial AI behavior.

<br><br>

***Roles and Activities***

| **Activity**                                | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|--------------------------------------------------|---------------|--------------|-----------------------|-------------------|-----------------------|-----------------|----------------|-------------------|-------------------------|----------------------------|--------------------|
| Define AML strategy and governance framework    | **A**             | R            | C                     | C                 | C                     | -               | -              | -                 | C                         | -                            | -                  |
| Identify and assess adversarial risks           | I             | **A**            | C                     | C                 | R                     | -               | -              | -                 | C                         | R                            | I                  |
| Develop and implement robust AI models          | I             | C            | R                     | C                 | C                     | -               | -              | -                 | -                         | **A**                            | -                  |
| Implement adversarial training                  | I             | C            | C                     | C                 | R                     | -               | -              | -                 | -                         | **A**                            | -                  |
| Perform model security validation               | I             | R            | C                     | C                 | **A**                     | -               | -              | -                 | -                         | R                            | -                  |
| Secure AI supply chain (datasets, models, APIs) | R             | **A**            | C                     | R                 | C                     | -               | -              | -                 | C                         | C                            | -                  |
| Monitor AI systems for adversarial activity     | I             | C            | -                     | -                 | C                     | R               | **A**              | R                 | -                         | I                            | -                  |
| Define regulatory compliance requirements       | C             | **A**            | C                     | -                 | C                     | -               | -              | -                 | R                         | -                            | -                  |
| Conduct AML security audits                     | I             | C            | -                     | -                 | R                     | -               | R              | -                 | **A**                         | -                            | -                  |
| Respond to adversarial attacks                  | I             | C            | -                     | -                 | R                     | R               | **A**              | R                 | -                         | -                            | -                  |
| Define ethical AI usage policies                | **A**             | R            | C                     | C                 | -                     | -               | -              | -                 | **A**                         | -                            | -                  |
| Communicate AML risks to stakeholders           | **A**             | R            | C                     | C                 | -                     | -               | -              | -                 | C                         | I                            | I                  |


---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement


<br><br>

###### 6.1.1.5.4. Guidance provided

NIST AI 100-2e2023 Framework provides comprehensive guidance to enhance the security, robustness, and trustworthiness of AI systems. Its emphasis on lifecycle security, risk assessment, and interdisciplinary collaboration ensures that AI systems are prepared to face both current and emerging adversarial threats.

<br><br>

###### 6.1.1.5.5. Detail on current framework

The NIST AI 100-2e2023 Framework represents a foundational step in addressing the multifaceted challenges posed by adversarial machine learning (AML). By providing a comprehensive taxonomy and terminology, the framework enables a systematic understanding of the diverse threats to AI systems and outlines actionable strategies to mitigate these risks. It establishes a much-needed bridge between the fields of AI development, cybersecurity, and policy, laying the groundwork for designing, deploying, and governing secure and trustworthy AI systems.

<br><br>

***Purpose and Strategic Goals***

| **Purpose/Goal** | **Description** |
|------------------|-----------------|
| **Define AML Threats**       | Establish a standardized taxonomy and terminology for adversarial risks to unify understanding across domains. |
| **Enhance AI Security**      | Equip stakeholders with tools and strategies to mitigate adversarial risks and ensure resilience.              |
| **Support Risk Management**  | Align AML measures with the broader NIST AI Risk Management Framework for trustworthiness and risk-based decisions. |
| **Foster Trust in AI**       | Address vulnerabilities compromising the safety, fairness, and reliability of AI systems.                    |
| **Address Evolving Threats** | Provide a structured and adaptive approach to mitigate new and emerging adversarial risks.                      |

<br><br>

***Core Taxonomy and Dimensions***

| **Dimension** | **Description** | **Examples** |
|---------------|-----------------|--------------|
| **Stages of Learning**      | Categorizes attacks based on when they occur in the AI lifecycle. | 1. Training Stage: Data Poisoning, Model Poisoning.  |
|  |  | 2. Deployment Stage: Evasion Attacks, Privacy Attacks. |
| **Attacker Objectives**     | Identifies the goals adversaries aim to achieve. | 1. Availability Breakdown: Disrupt system functionality or usability. |
|  |  | 2. Integrity Violation: Cause incorrect or malicious outputs. |
|  |  | 3. Privacy Compromises:  Extract sensitive information from models or datasets.|
| **Attacker Capabilities**   | Specifies what attackers can manipulate or control. | 1. Training Data Control: Modifying or injecting training samples.|
|  |  | 2. Model Control: Altering model parameters or inserting backdoors. |
|  |  | 3. Testing Data Control: Manipulating inputs at inference time. |
|  |  | 4. Query Access: Exploiting API access to extract model outputs or confidence scores. |
|  |  | 5. Source Code Control: Tampering with the codebase or libraries. |
|  |  | 6. Label Limit: Restricting adversarial control over labels. |
| **Attacker Knowledge**      | Defines the level of knowledge attackers have about the AI system. | 1. White-Box Attacks (full knowledge). |
|  |  | 2. Black-Box Attacks (limited access). |
|  |  | 3. Gray-Box Attacks (partial knowledge). |
| **Data Modalities**         | Explains the types of data targeted by adversarial attacks. | 1. Images: Commonly targeted for evasion and poisoning attacks. |
|  |  | 2. Text: Manipulating NLP models using adversarial examples. |
|  |  | 3. Audio/Video: Tampering with speech recognition and video classification. |
|  |  | 4. Cybersecurity: Attacking malware classifiers and intrusion detection systems. |
|  |  | 5. Tabular Data: Exploiting systems in healthcare, finance, and business. |
|  |  | 6. Multimodal Systems: Coordinating attacks across integrated data types. |

<br><br>

***Attack Categories***

| **Category** | **Definition** |**Types** | **Examples** | **Mitigations** |
|-----------------------|-------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| **Evasion Attacks**   | Generate adversarial inputs to mislead models during inference.              | White-Box, Black-Box, Transferability.                                                          | Misclassifying road signs in autonomous vehicles; tricking diagnostic tools in healthcare.       | Adversarial Training, Randomized Smoothing, Formal Verification.                                          |
| **Poisoning Attacks** | Manipulate training data or models to degrade performance or embed triggers. | Availability Poisoning, Targeted Poisoning, Backdoor Poisoning, Model Poisoning.                | Corrupting datasets to bias models; embedding triggers in federated learning models.             | Data Validation, Secure Federated Learning Aggregation, Model Provenance Checks.                         |
| **Privacy Attacks**   | Extract sensitive information from datasets or models.                      | Membership Inference, Data Reconstruction, Model Extraction.                                    | Extracting personal data from AI models; determining if specific data was used in training.      | Differential Privacy, Cryptographic Techniques (e.g., Homomorphic Encryption).                           |
| **Generative AI Attacks** | Exploit vulnerabilities in generative models.                             | Prompt Injection, Data Extraction, Supply Chain Attacks.                                        | Manipulating large language models (LLMs) to reveal sensitive information or generate harmful outputs. | Transparent Model Documentation, Prompt Filtering, Secure Pre-trained Model Validation.                  |

<br><br>

***Mitigation Strategies***

| **Strategy**  | **Description** | **Advantages** | **Challenges/Limitations**  |
|---------------|----------------|-----------------|-------------------------|
| **Adversarial Training**   | Incorporates adversarial examples into the training process to improve robustness.                | Enhances resistance to known adversarial attacks.             | Increases computational cost and may reduce accuracy on clean data.                                 |
| **Randomized Smoothing**   | Adds random noise to inputs, creating smoother decision boundaries that are harder to exploit.    | Simple to implement and improves resilience to perturbations. | Limited effectiveness for certain attack types; may degrade performance on clean inputs.            |
| **Formal Verification**    | Uses mathematical methods to prove model robustness under specified conditions.                   | Guarantees robustness within defined parameters.              | Computationally expensive and challenging to scale for large models.                                |
| **Differential Privacy**   | Introduces noise to outputs or gradients, protecting individual data points in the training set.   | Strong protection against privacy attacks.                    | Reduces model utility and accuracy due to added noise.                                              |
| **Cryptographic Methods**  | Employs techniques like homomorphic encryption and secure multiparty computation for data privacy.| Provides robust privacy guarantees.                          | High computational overhead and complexity in implementation.                                       |
| **Data Validation**        | Filters and verifies the integrity of training datasets to detect and remove malicious inputs.    | Prevents poisoning attacks by ensuring data quality.          | Can be difficult to identify sophisticated poisoning attacks.                                       |
| **Secure Aggregation**     | Ensures robustness in federated learning by securely combining model updates from multiple clients.| Reduces risk of model poisoning in distributed settings.      | Computationally intensive and may require trusted infrastructure.                                   |
| **Model Provenance Checks**| Audits and verifies the origins of pre-trained models and datasets to ensure integrity.            | Mitigates risks from supply chain attacks.                    | May not detect subtle or embedded vulnerabilities in third-party models.                            |
| **Prompt Filtering**       | Applies filters to user inputs in generative AI to prevent harmful or manipulative prompt usage.  | Reduces risks of prompt injection attacks.                    | Requires constant updates to account for new and evolving attack methods.                           |

<br><br>

***Challenges and Open Problems***

| **Challenge/Open Problem** | **Description** | **Implications**  |
|---------|-------------------|---------------------|
| **Scalability of Defenses**       | Many mitigation techniques, such as adversarial training and formal verification, are computationally intensive and hard to scale. | Limits applicability in real-world scenarios involving large datasets and models.                   |
| **Adaptive Threats**              | Adversaries continuously evolve their techniques to bypass existing defenses.                        | Requires ongoing updates and innovation in mitigation strategies to stay effective.                 |
| **Theoretical Boundaries**        | Fundamental questions about the provable robustness of machine learning systems remain unanswered.   | Challenges the development of defenses that are both efficient and theoretically sound.              |
| **Multimodal Robustness**         | Ensuring resilience across models handling multiple data types (e.g., image-text) is complex.        | Multimodal systems are increasingly common, making this a critical area for future research.         |
| **Supply Chain Security**         | Third-party datasets and pre-trained models introduce vulnerabilities to the AI pipeline.            | Poses risks for organizations relying on external resources, requiring stringent validation measures. |
| **Trustworthiness Trade-Offs**    | Balancing robustness, fairness, privacy, and explainability remains challenging.                     | Trade-offs may result in systems that prioritize one attribute over others, impacting overall trust.  |
| **Data Validation Complexity**    | Sophisticated poisoning attacks can evade detection during data validation processes.                | Highlights the need for advanced tools to assess and sanitize datasets effectively.                  |
| **Privacy vs. Utility**           | Privacy-preserving techniques, such as differential privacy, often reduce model performance.         | Striking a balance is essential for systems in sensitive domains like healthcare and finance.         |
| **Evolving Generative AI Threats**| New vulnerabilities, such as prompt injection and data extraction from large language models, emerge rapidly. | Generative AI systems require specialized defenses that keep pace with the evolution of attack methods. |
| **Human Factors**                 | Human errors or biases in system design, data curation, or implementation can amplify adversarial vulnerabilities. | Emphasizes the need for training and awareness among AI practitioners and decision-makers.            |

<br><br>

***Generative AI and Emerging Concerns***

| **Concern** | **Description**  | **Implications** |
|-------------|----------------|--------------------|
| **Prompt Injection**             | Adversaries craft malicious inputs to manipulate the outputs of generative AI systems.             | Leads to harmful, biased, or incorrect outputs that undermine trust in the system.                        |
| **Data Extraction**              | Sensitive or proprietary training data can be inferred or reconstructed from generative models.    | Raises privacy and intellectual property concerns, especially for proprietary datasets.                   |
| **Supply Chain Attacks**         | Pre-trained generative models and training pipelines can be tampered with to embed vulnerabilities.| Introduces risks to organizations relying on third-party models and training data.                        |
| **Bias Amplification**           | Generative models may inherit or amplify biases present in training data.                         | Results in discriminatory or unfair outputs, impacting ethical AI adoption.                               |
| **Corporate Data Integration**   | Generative AI tools, such as LLMs, integrated with proprietary data may expose sensitive information.| Risks unintended leakage of corporate secrets or confidential data through AI outputs.                    |
| **Open vs. Closed Models**       | Open models enhance transparency but increase the surface area for attacks, while closed models limit external scrutiny. | Balancing transparency and security is essential to maintain both accountability and resilience.           |
| **Content Authenticity**         | Generative AI systems can create realistic but false content, such as deepfakes or fake news.      | Poses significant risks to public trust, security, and societal stability.                                |
| **Evolving Attack Methods**      | Adversarial techniques targeting generative AI evolve rapidly, making it challenging to maintain defenses. | Requires continuous innovation in security practices tailored to generative systems.                      |
| **Regulation and Governance**    | Lack of comprehensive policies governing generative AI systems exacerbates risks.                  | Calls for the development of ethical guidelines, auditing standards, and legal frameworks for deployment. |

<br><br>

###### 6.1.1.5.6. What is missing for defenders of AI systems

From a defender's perspective, the NIST AI 100-2e2023 Framework provides a solid foundation for understanding adversarial risks but requires enhancements to address practical challenges. Key missing elements include detailed playbooks, incident response protocols, and tools for testing AI robustness. Defenders need more guidance on lightweight, scalable defenses, threat intelligence sharing, and securing the AI supply chain.

<br><br>

#### 6.1.2. MITRE

##### 6.1.2.1. MITRE ATT&CK

###### 6.1.2.1.1. Overview

The MITRE ATT&CK framework is a globally recognized, open-source knowledge base that documents real-world adversary tactics, techniques, and procedures (TTPs) across the cyber-attack lifecycle. It organizes adversary behaviors into tactics (the high level goals attackers intend to achieve), techniques/sub-techniques (the specific methods to accomplish those goals), and procedures (the detailed steps an adversary would take to implement the technique). The TTPs are mapped into an intuitive matrix that spans multiple domains, including enterprise, mobile, cloud, and industrial control systems (ICS). Originally focused on post-attack activities, it now also includes early-stage attacker actions like reconnaissance. 

ATT&CK serves as a practical tool for red teaming, behavioral analytics, threat intelligence enrichment, and defensive gap assessments, linking techniques to adversary groups, software, and mitigations. It provides a practical, data-driven guide to strengthening defenses against real-world threats. Of note, entries in ATT&CK are drawn from publicly reported incidents or offensive research, so that the model is grounded in real-world threats and not theoretical techniques with limited utility. 


###### 6.1.2.1.2. Scoping of AI system and/or cybersecurity purview

The MITRE ATT&CK framework provides a structured approach for identifying, analyzing, and addressing threats in AI systems and cybersecurity. Scoping ATT&CK for AI systems involves adapting the framework's tactics and techniques to the unique aspects of AI, while integrating it into the broader cybersecurity purview.

***Components of AI Systems and Relevant ATT&CK Techniques***

| **Component**       | **Description**                                                  | **Relevant ATT&CK Techniques**                     |
|----------------------|------------------------------------------------------------------|----------------------------------------------------|
| **Data Pipeline**    | Protect data integrity, ensure secure collection and storage.   | Data Destruction (T1485), Data Manipulation (T1565) |
| **ML Models**        | Safeguard against adversarial attacks and model theft.          | Exploitation for Defense Evasion (T1211) |
| **APIs and Interfaces** | Secure endpoints and prevent injection attacks.                | Exploit Public-Facing Applications (T1190) |
| **Infrastructure**   | Secure cloud, edge, and on-prem systems hosting AI.             | Resource Hijacking (T1496), Compromise Accounts (T1586) |


---

***ATT&CK Tactics in Cybersecurity Purview***

| **Tactic**            | **Description**                                                                  | **Relevant Techniques**                                       |
|------------------------|----------------------------------------------------------------------------------|--------------------------------------------------------------|
| **Initial Access**     | Methods used to gain unauthorized access to AI systems.                         | Phishing (T1566), Supply Chain Compromise (T1195), Valid Accounts (T1078) |
| **Defense Evasion**    | Hiding malicious activity or bypassing defenses.                                | Indicator Removal (T1070), Impair Defenses (T1562) |
| **Privilege Escalation** | Techniques to gain elevated permissions in AI systems.                         | Exploitation for Privilege Escalation (T1068), Abuse Elevation Control Mechanism (T1548) |
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

###### 6.1.2.1.3. Persona addressed

***Target Audience***

+ **CISO/SSO:** Strategic threat intelligence integration.
+ **Security Architects:** Adversarial AI threat modeling and defense design.
+ **SOC Operations:** Real-time threat detection, hunting, and incident response.
+ **Researchers/Data Scientists:** Adversarial AI research and TTPs (Tactics, Techniques, Procedures).


<br><br>

***Roles and Activities***

| **Activity**                                | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|---------------------------------------------|---------------|--------------|----------------------|---------------|------------------|---------------|---------------|------------------|-----------------------|----------------------------|------------------|
| Threat Intelligence & Analysis          | I             | **A**            | C                    | C             | R                | -             | C             | -                | I                     | R                          | -                |
| Adversary Emulation & Red Teaming       | I             | **A**            | C                    | C             | R                | -             | R             | -                | -                     | C                          | -                |
| Threat Detection & Monitoring           | I             | **A**            | C                    | R             | R                | C             | R             | C                | I                     | C                          | -                |
| Incident Response & Containment         | I             | R            | C                    | C             | **A**                | C             | R             | R                | -                     | -                          | -                |
| Security Architecture & Design          | I             | **A**            | R                    | R             | R                | -             | -             | -                | -                     | C                          | -                |
| Risk Assessment & Mitigation Planning   | **A**             | R            | C                    | C             | R                | -             | -             | -                | **A**                     | C                          | -                |
| Defensive Gap Assessment                | I             | R            | C                    | C             | **A**                | -             | R             | -                | I                     | C                          | -                |
| SOC Maturity Assessment                 | I             | **A**            | -                    | -             | R                | C             | R             | -                | I                     | -                          | -                |
| Policy & Compliance Mapping             | **A**             | R            | -                    | -             | C                | -             | -             | -                | C                     | -                          | -                |
| Security Awareness & Training           | **A**             | R            | C                    | -             | C                | C             | C             | C                | **A**                     | -                          | R                |
| AI/ML Security Integration              | I             | R            | C                    | R             | R                | -             | -             | -                | I                     | **A**                          | -                |
| Vulnerability & Patch Management        | I             | R            | C                    | C             | R                | **A**             | R             | -                | I                     | -                          | -                |
| Auditing & Regulatory Compliance        | I             | R            | -                    | -             | R                | -             | -             | -                | **A**                     | -                          | -                |
| User Access & Identity Management       | I             | R            | C                    | C             | R                | **A**             | -             | C                | I                     | -                          | R                |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

###### 6.1.2.1.4. Guidance provided

The MITRE ATT&CK framework provides a robust foundation for securing AI systems by aligning traditional cybersecurity practices with AI-specific threats. By mapping adversary behaviors, simulating attacks, and enhancing detection capabilities, ATT&CK ensures AI systems are resilient against both known and emerging threats. Organizations can leverage ATT&CK to build a unified, proactive security posture that addresses the unique challenges posed by AI technology.


###### 6.1.2.1.5. Detail on current framework

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
| **Model-Specific**    | Adversarial inputs misleading AI predictions.            | Exploitation for Defense Evasion (T1211) |
|                       | Model theft through reverse engineering or inference.    | Exploit Public-Facing Applications (T1190) |
| **Infrastructure**    | Resource hijacking for unauthorized use (e.g., cryptomining). | Resource Hijacking (T1496), Compromise Accounts (T1586) |
|                       | API exploitation leading to malicious actions.           | Exploitation of Remote Services (T1210) |
| **Lifecycle Threats** | Reconnaissance for vulnerable AI components.             | Gather Victim Network Information (T1590) |
|                       | Manipulation of AI outputs to disrupt operations.        | Service Stop (T1489), Endpoint Denial of Service (T1499) |


***Application of ATT&CK Tactics to AI Systems***

| **Tactic**            | **Description**                                            | **Example Technique**                              |
|------------------------|------------------------------------------------------------|---------------------------------------------------|
| **Reconnaissance**     | Discovering weak points in AI workflows.                   | Gather Victim Network Information (T1590)         |
| **Initial Access**     | Exploiting APIs or supply chain vulnerabilities.           | Exploit Public-Facing Applications (T1190)        |
| **Execution**          | Triggering malicious actions via adversarial inputs.       | Exploitation of Remote Services (T1210)        |
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



###### 6.1.2.1.6. What is missing for defenders of AI systems

While the MITRE ATT&CK framework provides a robust structure for addressing traditional cybersecurity threats, it lacks several critical elements specific to the unique challenges posed by AI systems. Those gaps are covered by MITRE ATLAS Framework.

***Challenges and Limitations of ATT&CK for AI Systems***

| **Challenge**           | **Description**                                                        |
|--------------------------|------------------------------------------------------------------------|
| **Dynamic Threat Landscape** | AI systems and adversaries evolve rapidly, requiring continuous updates to ATT&CK. |
| **Complexity of Mapping**     | Deep expertise in both cybersecurity and AI is needed for effective ATT&CK mapping. |
| **Operational Integration**   | Customization is required to integrate ATT&CK into existing workflows for AI security. |


##### 6.1.2.2. MITRE ATLAS

###### 6.1.2.2.1. Overview

The MITRE Adversarial Threat Landscape for Artificial-Intelligence Systems (ATLAS) is a knowledge base designed to address threats to AI-enabled systems. It documents adversary tactics, techniques, and real-world attack observations while complementing the MITRE ATT&CK framework.

While MITRE ATT&CK remains the framework for traditional cybersecurity and adversary behaviors, MITRE ATLAS extends this model into the AI domain. ATLAS focuses on the unique adversarial threats faced by AI systems, such as model poisoning, prompt injection, and evasion attacks, complementing the capabilities of ATT&CK for a holistic view of modern cyber and AI threats. Like ATT&CK, ATLAS focuses on real-world documented threats rather than theoretical attacks

ATLAS serves as a critical tool for understanding, simulating, and mitigating threats to AI systems. It helps stakeholders (e.g., analysts, developers, and defenders) prepare for AI-specific security challenges through shared knowledge and practical tools.


###### 6.1.2.2.2. Scoping of AI system and/or cybersecurity purview

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

###### 6.1.2.2.3. Persona addressed

***Target Audience***

+ **CISO/SSO:** Strategic threat intelligence integration.
+ **Security Architects:** Adversarial AI threat modeling and defense design.
+ **SOC Operations:** Real-time threat detection, hunting, and incident response.
+ **Researchers/Data Scientists:** Adversarial AI research and TTPs (Tactics, Techniques, Procedures).


<br><br>

***Roles and Activities***

| **Activity**                    | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|--------------------------------------|--------------|--------------|----------------------|--------------|--------------------|--------------|--------------|------------------|----------------------|------------------------|------------------|
| Identify AI systems and assets       | I            | **A**            | R                    | C            | C                  | I            | -            | -                | -                      | C                      | -                |
| Perform AI threat assessments        | I            | **A**            | C                    | -            | R                  | I            | R            | -                | I                      | C                      | -                |
| Implement data integrity measures    | I            | **A**            | C                    | R            | R                  | R            | R            | R                | I                      | C                      | -                |
| Develop adversarial detection        | I            | **A**            | -                    | -            | R                  | C            | R            | -                | -                      | C                      | -                |
| Conduct adversarial red teaming      | I            | **A**            | -                    | -            | C                  | -            | R            | -                | -                      | C                      | -                |
| Establish monitoring and logging     | I            | **A**            | C                    | R            | R                  | R            | R            | R                | -                      | -                      | -                |
| Create AI security mitigation plans  | I            | **A**            | C                    | C            | R                  | -            | C            | -                | I                      | C                      | -                |
| Document and share AI incidents      | I            | **A**            | C                    | -            | R                  | I            | R            | -                | C                      | C                      | I                |
| Maintain ATLAS framework updates     | I            | **A**            | -                    | -            | R                  | -            | R            | -                | -                      | R                      | -                |
| Train staff on ATLAS principles      | R            | **A**            | -                    | -            | C                  | -            | R            | R                | I                      | C                      | I                |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement



###### 6.1.2.2.4. Guidance provided

ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) provides comprehensive guidance for defending AI systems by addressing unique threats such as data poisoning, adversarial inputs, model theft, API exploitation, and AI misuse. It extends the MITRE ATT&CK framework with AI-specific tactics, techniques, and procedures (TTPs), emphasizing the need to secure AI across its lifecycle—from data preparation and model training to inference and operation. 

ATLAS advocates for robust detection and mitigation strategies, including behavioral analytics, adversarial robustness testing, and strict access controls, while integrating AI into red and blue team exercises and enhancing threat intelligence. It also highlights the importance of securing AI supply chains, protecting pre-trained models and frameworks, and addressing cross-domain risks in cloud, edge, and IoT environments. 


###### 6.1.2.2.5. Detail on current framework

The design and structure of MITRE ATLAS reflect its commitment to providing a comprehensive, adaptable framework for addressing adversarial threats to AI systems. Its integration of tactics, techniques, and real-world procedures, combined with a focus on tools and mitigations, ensures its utility across diverse AI environments. By targeting the unique vulnerabilities of AI systems, ATLAS serves as both a practical resource and a strategic guide for securing the next generation of intelligent technologies.

**ATLAS Matrix**

The ATLAS Matrix provides a visual representation of adversary tactics and techniques, similar to the ATT&CK Matrix but adapted for AI systems. It organizes:

1. Tactics as the top-level categories (e.g., Data Poisoning, Evasion, Extraction).
2. Techniques under each tactic as actionable adversary behaviors.
3. Links to Procedures that document real-world use cases and observed attacks.


**Core Components**

The ATLAS Framework is organized into components that reflect the adversarial threat landscape of AI systems. These components include Tactics, Techniques, and Procedures (TTPs) and are designed to capture adversary behavior in both training and inference stages.

***Tactics***

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

***Techniques***

Techniques describe the methods adversaries use to achieve their tactical objectives. These are highly specific to the AI domain and reflect the different stages of the AI lifecycle. Each technique may apply to one or more tactics. Examples of Techniques:

| **Technique**                  | **Description**                                                                                       |
|--------------------------------|-------------------------------------------------------------------------------------------------------|
| **Training Data Poisoning**    | Introducing malicious or biased data into the training dataset to degrade model accuracy or integrity. |
| **Adversarial Perturbations**  | Modifying inputs slightly to cause the AI model to produce incorrect predictions or classifications.   |
| **API Abuse**                  | Exploiting AI model APIs to manipulate outputs or extract sensitive data.                             |
| **Model Extraction**           | Reverse engineering or stealing the AI model's parameters or architecture via inference queries.      |
| **Overfitting Exploitation**   | Identifying and exploiting a model's reliance on specific patterns in data to induce errors.           |

---

***Procedures***

Procedures represent real-world adversary actions and implementations of techniques. These are based on observed adversarial behavior and case studies. Examples of Adversary Procedures:

| **Procedure**                 | **Description**                                                                                      |
|-------------------------------|------------------------------------------------------------------------------------------------------|
| **Adversarial Input**         | Designing specific inputs (e.g., images or text) to trick AI models into producing incorrect outputs. |
| **LLM Exploitation**          | Using malicious prompts to force large language models (LLMs) to generate unintended responses.      |
| **Steganographic Poisoning**  | Embedding malicious data within seemingly benign files to influence model behavior during training.  |
| **Environmental Manipulation**| Altering real-world conditions (e.g., light, noise) to confuse AI perception systems.                |
| **Dataset Manipulation**      | Subtly modifying public datasets used for training to introduce vulnerabilities into the final model. |

---

**Attack Surface**

| **Aspect**  | **Description**  | **Examples** |
|-------------|------------------|--------------|
| **AI Access Time**    | Stages of the AI lifecycle where attacks can occur. | **1. Training Phase**: Manipulating training data or configurations. |
|  |  | **2. Inference Phase**: Targeting live AI models to manipulate outputs or extract data. |
| **AI Access Points**  | Interfaces through which adversaries interact with the AI system. | **1. Digital Access**: APIs, web services, file inputs. |
|  |  | **2. Physical Access**: Environmental data like sensor inputs. |
| **System Knowledge**  | Levels of understanding adversaries have about the AI system's internals. | **1. White-box Access**: Full access to model architecture, parameters, and training data. |
|  |  | **2. Black-box Access**: Limited to observing inputs and outputs. |

---


**Threat Mitigation**

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


###### 6.1.2.2.6. What is missing for defenders of AI systems

MITRE ATLAS is a strong framework for understanding adversarial tactics and techniques targeting AI systems, but it needs to evolve to cover specific adversarial techniques, AI supply chain risks, and model behavior. Furthermore, defenders of AI systems would benefit from better integration with broader cybersecurity frameworks. Addressing these gaps would enhance ATLAS's ability to support defenders in securing AI systems against increasingly sophisticated and novel threats.

While ATLAS provides detail on adversarial tactics and techniques, its stated goal is a knowledge base, and does not help defenders prioritize mitigations and countermeasures. Its target audience of developers, incident responders, and security analysts means that it is not easily understood by executives and risk compliance, as it focuses on individual tactics rather than helping make decisions based on a higher level risk management framework.


##### 6.1.2.3. MITRE CAPEC

###### 6.1.2.3.1. Overview

The Common Attack Pattern Enumeration and Classification (CAPEC) is a standardized, community-driven framework for understanding, categorizing, and mitigating cyber-attack techniques. It provides a structured taxonomy of attack patterns that describe methods attackers use to exploit software systems. While CAPEC is not designed to defend AI systems it is relevant for AI-based systems focused on cybersecurity, as it provides machine-readable, systematic descriptions of attacks that can be used to enhance threat detection, prevention, and response capabilities.


###### 6.1.2.3.2. Scoping of AI system and/or cybersecurity purview

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


###### 6.1.2.3.3. Persona addressed

***Target Audience***

+ **CISO/SSO:** Implementing adversarial defense strategies and security controls informed by CAPEC attack patterns.
+ **Security Architects:** Advanced threat modeling, risk assessment, and security design using CAPEC AI-specific attack patterns.
+ **SOC Operations:** Real-time monitoring, detection, and incident response for adversarial AI attacks.
+ **Researchers/Data Scientists:** Investigating adversarial attack methodologies and developing adversarially robust models.


<br><br>

***Roles and Activities***

| **Task/Activity**                                 | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|---------------------------------------------------|---------------|--------------|-----------------------|-------------------|----------------------|----------------|----------------|------------------|----------------------|---------------------------|---------------------|
| Integrate CAPEC into AI Systems               | I             | **A**            | R                     | C                 | C                    | I              | I              | I                | C                      | R                         | I                   |
| Threat Modeling Using CAPEC                   | I             | **A**            | R                     | R                 | R                    | I              | C              | I                | C                      | C                         | -                   |
| Train AI Models with CAPEC Data               | I             | C            | **A**                     | C                 | C                    | -              | I              | R                | -                      | R                         | -                   |
| Identify CAPEC Attack Patterns                | I             | **A**            | R                     | C                 | R                    | -              | R              | I                | C                      | C                         | -                   |
| Automate Threat Detection Using CAPEC         | I             | **A**            | C                     | C                 | R                    | I              | R              | I                | C                      | C                         | -                   |
| Vulnerability Assessment and Simulation       | I             | **A**            | C                     | R                 | R                    | -              | R              | I                | C                      | C                         | -                   |
| Incident Response and Mitigation              | I             | **A**            | -                     | -                 | R                    | I              | R              | I                | C                      | -                         | I                   |
| Maintain and Update CAPEC Data                | I             | C            | C                     | C                 | R                    | -              | R              | I                | **A**                      | R                         | -                   |
| Align CAPEC with Threat Intelligence | I         | **A**            | C                     | R                 | R                    | -              | R              | I                | C                      | C                         | -                   |
| Report CAPEC-Based Threat Insights            | I             | **A**            | C                     | C                 | R                    | -              | R              | I                | R                      | C                         | -                   |
| CAPEC Training and Awareness                  | I             | **A**            | C                     | C                 | R                    | I              | C              | I                | R                      | R                         | I                   |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement


###### 6.1.2.3.4. Guidance provided

CAPEC provides a robust foundation for AI systems to improve cybersecurity automation, detection, prediction, and response, making it useful for AI-driven security solutions. However it doesn't provide any guidance for AI systems security.


###### 6.1.2.3.5. Detail on current framework

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


###### 6.1.2.3.6. What is missing for defenders of AI systems

CAPEC focuses primarily on traditional software and system vulnerabilities but does not include AI-specific attack patterns. It integrates with CWE, which is focused on general software vulnerabilities but lacks specificity for AI. While CAPEC is well-suited for traditional IT systems but does not sufficiently address emerging AI-specific security domains.

##### 6.1.2.4. MITRE D3FEND

###### 6.1.2.4.1. Overview

The MITRE D3FEND framework represents a rigorously structured, semantically enriched knowledge base designed to systematically characterize cybersecurity countermeasures in relation to offensive tactics and techniques, as delineated by the MITRE ATT&CK framework. By employing an ontologically grounded knowledge graph, D3FEND elucidates the precise mechanisms by which defensive strategies mitigate adversarial threats, thereby enabling a more nuanced understanding of cybersecurity resilience. Its application extends across security architects, red and blue teams, and threat intelligence analysts, facilitating a more evidence-based, adaptive, and scalable paradigm for cyber threat mitigation and strategic security planning.


###### 6.1.2.4.2. Scoping of AI system and/or cybersecurity purview

D3FEND provides a comprehensive scoping framework for securing AI systems within the broader cybersecurity purview. By defining AI-specific security threats, defensive techniques, cybersecurity controls, and governance alignment, D3FEND enables AI security professionals, threat hunters, and enterprise architects to proactively mitigate AI security risks.

As AI security threats continue evolving, D3FEND's structured, adaptive, and machine-readable approach will remain critical in defining, automating, and enforcing AI security best practices across enterprises, governments, and critical infrastructure sectors. 


###### 6.1.2.4.3. Persona addressed

***Target Audience***

+ **Security Architects:** Defensive countermeasure design against adversarial AI threats.
+ **SOC Operations:** Implementing and monitoring AI defensive measures.
+ **IT Operations:** Ensuring operational deployment of D3FEND countermeasures.
+ **Service Architects:** Integrating countermeasures into AI service design.


<br><br>

***Roles and Activities***

| Activity  | Executives | CISO/SSO | Service Architects | IT Architects | Security Architects | IT Operations | SOC Operations | Service Operations | Auditors/Policy Makers | Researchers/Data Scientists | Users/Practitioners |
|------------------|------------|-----------|--------------------|--------------|---------------------|--------------|---------------|-----------------|---------------------|------------------------|------------------|
| Define cybersecurity strategy using D3FEND | **A**          | R        | C                  | I            | C                   | I            | I             | I               | C                   | C                      | -                |
| Integrate D3FEND into enterprise security architecture | I          | **A**        | R                  | R            | R                   | C            | I             | I               | C                   | C                      | -                |
| Develop AI security countermeasures using D3FEND | I          | I        | C                  | C            | **A**                   | I            | R             | R               | I                   | R                      | -                |
| Align D3FEND security controls with compliance frameworks | I          | **A**        | C                  | I            | R                   | I            | I             | I               | R                   | C                      | -                |
| Threat modeling and mapping ATT&CK to D3FEND | I          | R        | C                  | C            | **A**                   | I            | R             | C               | C                   | C                      | -                |
| SOC implementation of D3FEND-based monitoring | I          | C        | C                  | C            | **A**                   | I            | R             | C               | I                   | I                      | -                |
| Incident response & investigation using D3FEND | I          | C        | C                  | C            | **A**                   | C            | R             | C               | I                   | I                      | -                |
| AI security risk assessment leveraging D3FEND | C          | R        | C                  | C            | **A**                   | I            | I             | I               | C                   | R                      | -                |
| Implementation of D3FEND security controls in AI models | I          | I        | C                  | R            | **A**                   | R            | I             | C               | C                   | R                      | -                |
| Development of AI security best practices with D3FEND | I          | C        | C                  | C            | **A**                   | C            | C             | C               | **A**                   | R                      | -                |
| Research on AI threat detection and mitigation via D3FEND | I          | I        | I                  | C            | **A**                   | C            | C             | C               | C                   | **A**                      | -                |
| Security awareness and training on D3FEND | **A**          | R        | C                  | C            | R                   | C            | C             | C               | C                   | C                      |  I              |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement


###### 6.1.2.4.4. Guidance provided

The MITRE D3FEND framework provides structured defensive cybersecurity guidance that can be directly applied to AI systems, particularly in securing machine learning models, AI-driven decision-making, and autonomous security architectures. Given the unique attack surfaces introduced by AI systems, D3FEND helps organizations map, implement, and automate cybersecurity controls to protect AI models from adversarial attacks, data manipulation, and exploitation.

###### 6.1.2.4.5. Detail on current framework

The MITRE D3FEND framework is an ontology-driven cybersecurity knowledge base designed to systematically categorize, relate, and structure cybersecurity countermeasures in a way that is machine-readable, semantically rigorous, and actionable. It complements MITRE ATT&CK by providing a defensive knowledge model that helps security practitioners map, analyze, and implement cybersecurity defenses.

**Core Design Principles**

| **Design Principle**                     | **Description** |
|-------------------------------------------|--------------------------------------------------------------|
| **Semantic Knowledge Representation**    | Uses an ontology-based structure to define cybersecurity countermeasures in a machine-readable format. |
| **Interoperability with ATT&CK**         | Directly maps defensive techniques to adversarial TTPs from MITRE ATT&CK, enabling structured threat defense strategies. |
| **Scalability and Extensibility**        | Designed for continuous updates to incorporate emerging threats, security controls, and AI-driven enhancements. |
| **Vendor-Agnostic Approach**             | Provides a standardized, neutral cybersecurity framework that integrates with SIEMs, SOAR, and compliance frameworks. |
| **Graph-Based Structure**                | Uses knowledge graph principles to model relationships between threats, countermeasures, and security controls. |
| **Machine Learning and AI Readiness**    | Supports AI-driven security automation, anomaly detection, and adversarial machine learning defense strategies. |

**Core Taxonomy**

D3FEND categorizes cybersecurity defensive techniques into structured domains, which define the different layers of security controls.

| **Category**                          | **Description** |
|---------------------------------------|--------------------------------------------------------------|
| **Identity & Access Management**      | Controls related to authentication, authorization, and user identity protection. |
| **Network Security & Traffic Analysis** | Techniques to monitor, filter, and protect network communications from adversarial activity. |
| **Malware Detection & Analysis**      | Methods for identifying and mitigating malicious software and anomalous behaviors. |
| **Data Protection & Encryption**      | Cryptographic and integrity-based methods to secure sensitive data. |
| **Endpoint Security & Hardening**     | Protection mechanisms that secure devices and applications from exploitation. |
| **Security Monitoring & Threat Detection** | Techniques to detect, log, and analyze cybersecurity threats in real time. |


**D3FEND Knowledge Graph**

D3FEND is structured as a graph-based knowledge model, where nodes represent different security concepts, and edges define relationships between them.

***Graph Nodes (Core Entities)***
+ Defensive Techniques  Security measures used to prevent, detect, or mitigate cyber threats.
+ Adversarial Techniques (ATT&CK) - The offensive methods used by attackers to compromise systems.
+ Security Controls - Specific technical implementations of defensive techniques.
+ Security Policies - Organizational security best practices mapped to defensive techniques.
+ Threat Intelligence Artifacts - Indicators of compromise (IOCs), behavioral patterns, and intelligence reports linked to defensive strategies.

***Graph Edges (Relationships)***
+ Mitigates - Links a D3FEND defensive technique to an ATT&CK adversarial technique it counteracts.
+ Implements - Connects a defensive technique to a specific security control.
+ Requires - Defines dependencies between security measures (e.g., MFA requires Identity Management).
+ Enhances - Shows how a technique strengthens another defense (e.g., AI-driven anomaly detection enhances traditional log analysis).
+ Correlates - Establishes links between threat intelligence indicators and defensive techniques.


**Data Model and Schema**

| **Attribute**            | **Description** |
|--------------------------|--------------------------------------------------------------|
| **Technique Name**       | Unique identifier of the defensive technique. |
| **Description**          | Brief summary of the countermeasure and its application. |
| **Mapped ATT&CK Techniques** | List of adversarial techniques that this defensive technique mitigates. |
| **Implementation Details** | Steps required to deploy and configure the technique effectively. |
| **Security Controls**     | Specific technologies or configurations that implement the defensive technique. |
| **Effectiveness**        | Metrics, evidence, and case studies demonstrating the technique's effectiveness. |
| **Data Sources**         | Required logs, telemetry, or forensic artifacts needed for detection and analysis. |


**D3FEND Deployment and Integration**

***Security Architecture Integration***

D3FEND can be used to enhance security architectures by integrating structured defensive knowledge into enterprise security operations:
+ SOC Operations - Improves threat detection and incident response workflows.
+ SIEM & SOAR Platforms - Automates security monitoring by mapping defensive techniques to log sources.
+ Threat Intelligence Platforms - Provides context-aware defensive insights.
+ Zero Trust Security Models - Enables adaptive security measures based on dynamic risk evaluation.

***AI and Machine Learning Applications***

D3FEND is particularly valuable in AI-driven cybersecurity, where it enables:
+ Automated anomaly detection using structured defensive mappings.
+ Adversarial AI defense techniques for machine learning security.
+ Intelligent security automation for self-adaptive cyber defenses.



###### 6.1.2.4.6. What is missing for defenders of AI systems

D3FEND is primarily designed for mapping defensive cybersecurity techniques to known adversarial TTPs from MITRE ATT&CK, focusing on traditional cybersecurity defenses rather than AI security. At this point D3FEND does not yet integrate AI-specific threat mappings covered by MITRE ATLAS. There are no current D3FEND techniques explicitly addressing adversarial ML, model robustness, AI compliance, or LLM security, indicating gaps in AI security defense strategies.

| What is Missing?                           | Details |
|--------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| Comprehensive Adversarial ML Defense      | D3FEND does not currently provide structured defensive techniques for mitigating adversarial ML attacks, including perturbation-based evasion and data poisoning. |
| AI-Specific Threat Intelligence Mapping   | D3FEND lacks mappings to AI-related attack techniques from MITRE ATLAS or AI-specific threat intelligence sources, limiting AI defenders' ability to track adversarial tactics. |
| LLM Security & Prompt Injection Protection | D3FEND does not cover security mechanisms for mitigating prompt injection attacks, adversarial instruction manipulation, or harmful AI-generated outputs in large language models (LLMs). |
| AI Supply Chain Security                  | D3FEND does not define security techniques for verifying AI model provenance, cryptographic signing of AI models, or securing the AI model supply chain. |
| Real-Time AI Model Telemetry & Monitoring | The framework does not provide techniques for continuously monitoring AI model behavior, detecting adversarial drift, or preventing inference manipulation. |
| Model Robustness & Integrity Verification | There are no defined defensive techniques in D3FEND for verifying AI model robustness against adversarial ML attacks, including model evasion and inversion attacks. |
| Secure AI Model Access & API Protections  | D3FEND does not outline access control mechanisms specific to AI models, including protections against API abuse, unauthorized access, and model inversion attacks. |

#### 6.1.3. CISA

##### 6.1.3.1. Zero Trust Maturity Model 2.0

###### 6.1.3.1.1. Overview

The US Cybersecurity and Infrastructure Security Agency (CISA) published the second version of the Zero Trust Maturity Model (ZTMM) in Apr 2023.  "This ZTMM is one of many paths that an organization can take in designing and implementing their transition plan to zero trust architectures in accordance with Executive Order (EO) 14028 'Improving the Nation's Cybersecurity,' which requires that agencies develop a plan to implement a Zero Trust Architecture (ZTA).".  CISA provides a roadmap for incremental adoption of ZTA, clarifying requirements to advance maturity in Zero Trust adoption and thereby improve security.

###### 6.1.3.1.2. Cybersecurity Purview

The Zero Trust Maturity Model provides guidance on how to enforce accurate, least privilege access decisions across information systems by assuming that any part of the system may be viewed as compromised. It provides requirements for system governance, access and use that rely on a principle of "don't trust; verify."  This notion of not trusting identities, data, network communications, workloads and even hardware until they are authenticated provides a comprehensive trusted system.  The ZTMM provides a set of levels describing the maturity of an organization's ZTA adoption, from Traditional security (no ZTA), to Initial, Advanced and Optimal ZTA maturity.  With clear best practices and a tiered system encouraging self-evaluation and improvement, the ZTMM provides a system that can characterize and systematically assist improving the security effectiveness of defenders.

###### 6.1.3.1.3. Persona Addressed

Zero Trust Architecture is a requirement for US Federal agencies.  CISA directly addresses the security stakeholders of these agencies.  Organizations implementing a Zero Trust Architecture will have similar roles and responsibilities.  The division of responsibilities may vary from organization to organization, but they will generally require executives accountable for driving implementation, architects informing proper implementation, and operators responsible for many implementation details.

***Roles:***  CT/R/IO, CISO, Security Architect, Data Architect, Service Architect, Network Architect, IT, SOC<br> 
***Activities:***  Comply with EO, Enterprise security architecture, Security tooling and deployment, Incident response, Data governance, Identity governance, Asset governance<br>
***Level of responsibility***
+ ***Accountable*** - highest, final authority for the task
+ ***Responsible*** - high, one who completes the task
+ ***Consulted*** - medium, provide input to complete the task
+ ***Informed*** - low, informed about the task

| Activity\Role | C[T/R/I]O | CISO | Security Architect | Data Architect | Service Architect | Network Architect | IT Operator | SOC Operator | 
| ------------- | --------- | ---- | ------------------ | -------------- | ----------------- | ----------------- | ----------- | ------------ |
| Comply with EO | R | **A** | C | C | C | C | I | I |
| Enterprise Security Architecture | I | R | **A** | C | C | C | I | I |
| Security Tooling and Deployment | C | **A** | R | C | C | C | R | R |
| Incident Response | I | **A** | C | C | C | C | I | R |
| Data Governance | I | **A** | C | R | C | C | R | I |
| Identity Governance | I | **A** | C | C | C | R | R | I |
| Asset Governance | I | **A** | C | C | C | C | R | I |

###### 6.1.3.1.4. Guidance Provided

The Zero Trust Maturity model informs security stakeholders about their level of Zero Trust Architecture adoption.  It promotes the principle of least privileged access across the domains of data, identity, network, devices and application workloads.  The Zero Trust Maturity model identifies 4 levels of adoption for each of these domains, or pillars.  Traditional maturity implies Zero Trust has not yet been adopted for that domain.  Initial, Advanced and Optimal maturity reflect subsequent levels of ZTA adoption, according to specific features for that domain.  There are also 3 cross-cutting features, apply to all of these pillars individually and across pillar boundaries.  These include Governance as a foundation, Automation and Orchestration above this, and Visibility and Analytics resting on top of these.  This Zero Trust Maturity Model framework provides a roadmap for stakeholders to implement Zero Trust Architecture.

###### 6.1.3.1.5. Detail on current framework

**Zero Trust Principles**

***NIST SP 800-207 defines the tenets of Zero Trust:***
1. All data sources and computing services are considered resources.
2. All communication is secured regardless of network location.
3. Access to individual enterprise resources is granted on a per-session basis.
4. Access to resources is determined by dynamic policy—including the observable state of client identity, application/service, and the requesting asset—and may include other behavioral and environmental attributes.
5. The enterprise monitors and measures the integrity and security posture of all owned and associated assets.
6. All resource authentication and authorization are dynamic and strictly enforced before access is allowed.
7. The enterprise works with the Organizations to catalog and inventory existing Cyber Security policies and standards. Policies are updated and created in cross pillar activities as needed to meet critical ZT Target functionality.

Throughout, the principle that no asset nor identity has any inherent trust is reiterated; defenders should assume there is a current breach and take extra steps to establish trust. This applies to all assets and identities within an organization.  The context of an identity's access to a resource should be rich enough to conclude that authorization is warranted, e.g. using multi-factor authentication combined with network and device attestation signals.  These tenets guide the best practices for the different pillars the ZTA uses to specify architectural components.


**Zero Trust Pillars**

The Zero Trust Architecture defines enterprise architectures as comprised of 5 pillars: Data, Identity, Devices, Network Communications, and Application Workloads.
+ Data includes all digital artifacts from files, metadata and fragments to databases to all data in transit, archived, or used at some point
+ Identity refers to the attributes that uniquely define a human or non-human user
+ Devices include all the organizations compute assets, including servers, laptops, network edge devices, printers, and IoT devices
+ Network refers to all communication media, including internal networks, wireless, the global Internet, and other channels for communicating digital information
+ Application Workloads includes programs and services running on organization assets - on-premise, on mobile or in the cloud

The ZTMM maps security implementations for each of the pillars to 4 levels of maturity, based on specific security features required for that pillar to adhere to the Zero Trust principles. The granularity of recommendations enable stakeholders to assess their Zero Trust maturity across these domains and provide steps to Optimal ZTA maturity.  For each pillar, these are the pillar specific features:
+ Data:  Data Inventory Management, Data Categorization, Data Availability, Data Access, and Data Encryption
+ Identity: Authentication, Identity Storage, Risk Assessment, Access Management
+ Devices: Policy and Compliance, Supply Chain Risk Management, Resource Access, Device Threat Protection
+ Network: Segmentation, Traffic Management, Traffic Encryption, Network Resilience
+ Application Workload: Application Access, Application Threat Protection, Application Accessibility, Secure Development Lifecycle, Application Security Testing

<img src="./frameworks/images/Zero-Trust-Maturity-Model-Pillars-from-CISA-2156918887.jpg" alt="Zero Trust Pillars" style="width:40%; height:auto;">

**Zero Trust Cross-Cutting Features**

The ZTMM identifies 3 features that cut across the pillars:  Governance, Automation and Orchestration, and Visibility and Analytics.  Governance serves as the foundation of the Zero Trust pillars.  Organizations must govern their assets and identities, fully aware of all data,, network communication, and application workloads.  Compliance with external and internal policy enforces governance.  This requires Automation and Orchestration of tooling required for the pillar or pillars, enabling comprehensive processes for governance.  Visibility and Analytics, whether from simple measurements and detection rules or complicated behavioral analytics, provide the mechanisms for ensuring that each pillar complies with governance.

"These three cross-cutting capabilities highlight activities to support interoperability of functions across pillars based on the following descriptions: 
+ Visibility and Analytics: Visibility refers to the observable artifacts that result from the characteristics of and events within enterprise-wide environments. The focus on cyber-related data analysis can help inform policy decisions, facilitate response activities, and build a risk profile to develop proactive security measures before an incident occurs.  
+ Automation and Orchestration: Zero trust makes full use of automated tools and workflows that support security response functions across products and services while maintaining oversight, security, and interaction of the development process for such functions, products, and services.  
+ Governance: Governance refers to the definition and associated enforcement of agency cybersecurity policies, procedures, and processes, within and across pillars, to manage an agency's enterprise and mitigate security risks in support of zero trust principles and fulfillment of federal requirements."

###### 6.1.3.1.6. What is missing for defenders of AI systems

The Zero Trust Maturity Model explicitly excludes recommendations on best practices for incorporating machine learning and artificial intelligence capabilities with Zero Trust. However, the fundamental concepts introduced by Zero Trust---least privilege, assumption of breach, and continuous authentication and authorization---are relevant for developers of AI systems that have access to sensitive data sets.

***AI Data Access Patterns***
The Zero Trust Maturity Model does not address typical deployments of AI systems, including Retrieval Augmented Generation.  AI is data driven, and vector databases are built for speed and not with Zero Trust access and encryption standards in mind.  The data access patterns for AI systems must implement the controls for proper Zero Trust Architecture, and this guidance is missing.

***AI Training Data Provenance***
If the training data for models is unknown, and the models can reproduce this data, then it is considered ungoverned data in the Zero Trust Architecture. This means that data used to train models must be known and available in order to ensure it complies with policy.  Building trust in that data requires some authentication of it, to verify that it is reputable data.

***AI Authorization Patterns***
Observing the principle of least-privileged access is often ignored in AI adoption, in order to facilitate AI access to data or tools.  The identity of AI application workloads should respect this principle by minimizing access to the least privilege among the AI user and the AI system privileges itself.  User access should not trampoline through AI system use, nor should AI systems provide more authority to users than they are otherwise allowed.

***AI Agency***
The Zero Trust Maturity Model emphasizes that no asset has inherent trust, and therefore, any access to resources must be gated through an authorization mechanism to re-validate the asset's ability to access that resource. While this approach can, and should, be applied to AI systems, there is no explicit mention of constraining the agency of AI systems to make authorization decisions in the ZTMM. The ZTMM does not call out the 

***AI Model Visibility and Analytics***
The behavior of AI systems must be established through monitoring its use.  Since these are stochastic systems, they are prone to produce unpredictable results (hallucinations).  Behavior can change as model versions are updated, and even as prompt templates are modified.  Establishing baseline behavior for AI models is required to understand when they are producing anomalous results.

***AI Driven Conclusions***
Governance for AI driven conclusions is required to ensure that automations comply with internal and external policies.  Determining what conclusions require humans-in-the-loop and what automations are resource limited will mitigate many risks.  Increasing the transparency and explainability of AI systems and requiring them in some use cases will also reduce opaque decision making.

***AI Resilience from Adversarial Attacks***
Vulnerability management for AI systems is a new and changing domain.  Novel attacks against AI systems continue, and the resilience of these systems needs to be increased.  ZTA adoption requires better characterization of AI system attack surface and weaknesses, so that proper defenses may be deployed.

#### 6.1.4. OASIS

##### 6.1.4.1. OASIS STIX 2.1

###### 6.1.4.1.1. Overview

The Structured Threat Information Expression (STIX) 2.1 framework is a robust standard designed to facilitate the exchange and representation of Cyber Threat Intelligence (CTI) in a structured, machine-readable format. As artificial intelligence becomes increasingly integrated into cybersecurity systems, defenders require robust frameworks to analyze, respond to, and prevent cyber threats. STIX 2.1, with its structured approach to Cyber Threat Intelligence (CTI), offers key advantages for AI systems defending against advanced threats. 


<br><br>

###### 6.1.4.1.2. Scoping of AI system and/or cybersecurity purview


| **Aspect**               | **AI System Scope**   | **Cybersecurity Purview**   |
|--------------------------|-----------------------|-----------------------------|
| **Threat Modeling**      | Building predictive models using STIX objects and relationships.                | Defining comprehensive threat profiles and attack chains.                       |
| **Data Integration**     | Ingesting STIX data from diverse sources for machine learning.                  | Aggregating intelligence into a centralized repository for operational use.      |
| **Pattern Matching**     | Translating STIX patterns into detection rules for AI-driven automation.        | Deploying STIX patterns in security tools for proactive threat identification.   |
| **Graph Analytics**      | Using graph neural networks (GNNs) for attack path analysis.                   | Employing graph-based relationships to map real-world attack vectors.           |
| **Automation**           | Automating detection, classification, and response actions.                    | Streamlining incident response workflows with automated threat analysis.         |
| **Governance**           | Applying confidence scoring and marking definitions to filter intelligence.     | Ensuring adherence to compliance requirements and protecting sensitive data.     |


<br><br>

###### 6.1.4.1.3. Persona addressed

***Target Audience***

+ **CISO/SSO:** Strategic threat intelligence sharing and collaboration.
+ **Security Architects:** Integrating AI-specific threat intelligence for proactive defense.
+ **SOC Operations:** Real-time AI-specific threat detection and incident response.
+ **Researchers/Data Scientists:** Utilizing threat intelligence for adversarial AI research.

<br><br>

***Roles and Activities***


| **Task/Responsibility**                                    | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|------------------------------------------------------------|---------------|-------------|---------------------|--------------|-------------------|--------------|---------------|----------------|--------------------|-------------------------|--------------------|
| Define AI and ML Security Strategy                     | **A**             | R           | C                   | I            | R                 | -            | -             | -              | C                  | C                         | -                  |
| Develop AI/ML Security Policies and Compliance         | R             | R           | I                   | C            | R                 | -            | -             | -              | **A**                  | C                         | -                  |
| Design AI/ML Secure Architectures                      | I             | C           | R                   | **A**            | R                 | I            | -             | I              | I                  | C                         | -                  |
| Implement AI-Specific Threat Intelligence in STIX 2.1  | I             | R           | C                   | C            | **A**                 | I            | C             | -              | I                  | R                         | -                  |
| Monitor AI/ML System for Security Threats             | I             | -           | -                   | -            | C                 | R            | **A**             | C              | I                  | I                         | -                  |
| Respond to AI-Specific Cyber Threats                  | I             | -           | -                   | -            | R                 | C            | **A**             | C              | I                  | -                         | -                  |
| Ensure AI Model Integrity and Trustworthiness          | I             | **A**           | I                   | C            | R                 | I            | -             | -              | C                  | R                         | I                  |
| Prevent AI Adversarial Attacks                         | I             | R           | C                   | C            | **A**                 | I            | R             | -              | I                  | R                         | -                  |
| Secure AI Training Data from Poisoning Attacks         | I             | C           | C                   | I            | **A**                 | -            | -             | -              | R                  | R                         | -                  |
| Audit and Assess AI/ML Security Measures               | I             | **A**           | C                   | I            | R                 | -            | -             | -              | **A**                  | C                         | -                  |
| Incident Response for AI-Specific Cybersecurity Events | I             | -           | -                   | -            | R                 | R            | **A**             | -              | I                  | -                         | -                  |
| Regulatory Compliance for AI/ML Systems               | R             | **A**           | I                   | C            | R                 | -            | -             | -              | C                  | -                         | -                  |
| Integrate AI-Specific Security into IT and Business Ops| I             | R           | C                   | C            | **A**                 | R            | -             | R              | I                  | C                         | -                  |
| Evaluate and Enhance AI Threat Detection Models        | I             | C           | C                   | I            | **A**                 | -            | R             | -              | I                  | **A**                         | -                  |
| Training and Awareness for AI Security Practices       | **A**             | R           | C                   | C            | R                 | I            | -             | R              | I                  | C                         | R                  |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

<br><br>

###### 6.1.4.1.4. Guidance provided


| **Feature**    | **Guidance**        | **Relevance for AI Systems**   |
|----------------|---------------------|--------------------------------|
| **Structured and Machine-Readable Data** | STIX objects are serialized in UTF-8 JSON, ensuring consistency and standardization.          | Enables seamless ingestion and pre-processing of structured data for training and inference.                     |
| **Comprehensive Threat Representation** | Provides Domain Objects (SDOs) for high-level CTI and Cyber-observable Objects (SCOs) for technical details. | Allows AI to model complex attack chains and conduct graph-based analytics for uncovering threat patterns.       |
| **STIX Patterning for Detection Logic** | Defines a domain-specific language (DSL) for describing detection rules and patterns.         | Translates STIX patterns into actionable detection logic for automated systems.                                  |
| **Confidence Scoring**                | Assigns confidence levels to objects and relationships to indicate data reliability.          | Supports probabilistic decision-making and prioritization of high-confidence intelligence.                       |
| **Open Vocabularies for Standardization** | Uses predefined vocabularies for Threat Actor sophistication, Malware types, and Attack Motivations. | Improves accuracy in AI model classification and ensures interoperability across datasets.                       |
| **Extensibility for Customization**   | Allows the addition of new attributes and creation of custom object types.                    | Enables customization for AI-specific metadata like anomaly scores or unique threat landscapes.                  |
| **Relationship Mapping**              | Defines connections between objects (e.g., "Indicator indicates Malware").                   | Enables graph-based analytics and prediction of attack paths.                                                   |
| **Real-Time Intelligence Sharing**    | Integrates with TAXII to enable live data transport and updates.                              | Ensures AI systems receive up-to-date threat intelligence for dynamic adaptation.                                |
| **Data Markings for Governance**      | Includes marking definitions for sharing restrictions and handling guidelines.                | Helps AI systems comply with data governance and process sensitive data securely.                                |
| **Historical Context with Versioning** | Tracks changes to objects through versioning.                                                | Provides historical data for training models and analyzing threat evolution.                                     |
| **Integration with Complementary Standards** | Aligns with MITRE ATT&CK, ATLAS and CAPEC for tactics, techniques, and attack patterns.             | Enriches AI-based threat modeling by mapping observed activity to known attacker behavior.                       |
| **Supporting Graph-Based Models**     | Represents CTI as a graph of nodes (objects) and edges (relationships).                       | Facilitates the use of graph neural networks (GNNs) and advanced analytics for anomaly detection and prediction. |
| **Examples and Schema for Implementation** | Includes JSON examples and validation schemas for all STIX object types.                     | Accelerates AI model development and ensures data integrity for training and inference.                          |


<br><br>


###### 6.1.4.1.5. Detail on current framework

**Core Architecture**

STIX models CTI as a graph comprising:
* Nodes: STIX Domain Objects (SDOs) and Cyber-observable Objects (SCOs).
* Edges: STIX Relationship Objects (SROs) link nodes to define their relationships.

This approach allows organizations to model complex threat environments by interconnecting key aspects such as threat actors, campaigns, vulnerabilities, and observed data.

<br><br>

***Object Categories and Their Functions***


| **Category**                | **Object Type**               | **Description**                                                                 |
|-----------------------------|------------------------------|---------------------------------------------------------------------------------|
| **STIX Domain Objects (SDOs)** | Attack Pattern               | Defines known patterns of adversarial behavior.                                 |
|                             | Campaign                     | Represents a coordinated set of malicious activities over time.                |
|                             | Malware                      | Describes malicious software, its behaviors, and its targets.                  |
|                             | Indicator                    | Provides patterns that suggest the presence of malicious activity.             |
|                             | Threat Actor                 | Profiles the entity behind attacks, including motivations and capabilities.     |
|                             | Vulnerability                | Details security weaknesses that attackers can exploit.                        |
|                             | Course of Action             | Suggests remediation or mitigation steps for threats.                          |
|                             | Infrastructure               | Describes systems or tools used by attackers to conduct operations.            |
|                             | Report                       | Aggregates threat intelligence into a narrative or summary document.           |
| **STIX Cyber-observable Objects (SCOs)** | IPv4/IPv6 Address         | Represents network IP addresses used in attacks.                               |
|                                          | File                      | Documents file details such as name, size, and hashes.                         |
|                                          | Network Traffic           | Records observed communications, such as protocols and endpoints.             |
|                                          | Process                   | Details processes executed on a system.                                       |
|                                          | Domain Name               | Represents domain names involved in an attack.                                |
|                                          | URL                       | Tracks observed or malicious URLs.                                            |
|                                          | Artifact                  | Represents raw data or binary artifacts associated with an attack.            |
| **STIX Relationship Objects (SROs)**    | Indicates                  | Links an Indicator to an observable that it detects.                          |
|                                          | Uses                      | Links Threat Actors to the tools or malware they utilize.                     |
|                                          | Targets                   | Defines the target (e.g., a sector or organization) of a Campaign or Threat Actor. |
|                                          | Related-to                | Establishes generic connections between objects.                              |
|                                          | Sighting                  | Captures instances of observables or indicators being seen in a specific context. |
| **STIX Meta Objects (SMOs)**            | Marking Definition         | Specifies how shared data can be used or distributed.                         |
|                                          | Language Content           | Adds language-specific translations or details to objects.                    |
|                                          | Extension Definition       | Defines custom properties or objects to extend STIX capabilities.            |
| **STIX Bundle**                         | Bundle                     | Groups multiple STIX objects for transport, sharing, or analysis.             | 

<br><br>

***Advanced Features***

| **Feature**               | **Description**    | **Benefits**  |
|---------------------------|--------------------|---------------|
| **Confidence Scoring**    | Assigns confidence levels to objects and relationships to indicate their reliability.            | Helps prioritize actions based on the trustworthiness of data.                                |
| **STIX Patterning**       | A language to describe detection rules and match observable activity against cyber threat data.  | Automates detection and response by identifying malicious behaviors in real-time telemetry.   |
| **Graph-Based Model**     | Represents CTI as interconnected nodes (objects) and edges (relationships).                      | Enables comprehensive mapping of threats and their interdependencies.                         |
| **Open Vocabularies**     | Standardized terms for properties like malware types, attack motivations, and actor roles.       | Ensures consistency, interoperability, and clarity across organizations and tools.            |
| **Extension Mechanisms**  | Allows new attributes or object types to be added in a standardized way.                        | Supports customization and adaptation to emerging threats without sacrificing interoperability.|
| **Object Versioning**     | Tracks changes to objects over time by maintaining a version history.                           | Enhances traceability and ensures integrity in CTI sharing.                                   |
| **Data Markings**         | Specifies handling and sharing rules for sensitive threat intelligence data.                    | Protects confidentiality and ensures compliance with data-sharing agreements or regulations.  |

<br><br>

**Application for AI Systems**


| **Application**               | **Key Focus**   | **Details**   |
|---------------------------|-----------------|---------------|
| **AI-Driven Threat Detection and Response** | ***Role of STIX in AI Systems***: Provides machine-readable, structured data for AI.               | 1. Enables training of machine learning models.<br>2. Automates threat detection and responses.|
|                           | ***Real-Time Threat Intelligence Integration***: Facilitates dynamic threat monitoring and action. | 1. Detects Indicators of Compromise (IOCs) like IPs or file hashes.<br>2. Automates mitigations.|
| ***Enhanced Context for AI Models*** | ***Leveraging Domain and Observable Objects***: Builds a comprehensive threat model.              | 1. SDOs provide strategic context (e.g., motivations).<br>2. SCOs offer technical-level details.|
|                           | ***Patterning for Detection Rules***: Defines standardized logic for detection.                     | 1. Translates patterns into detection rules.<br>2. Matches threat behaviors to telemetry data. |
| ***Strengthening Automation with Relationships*** | ***Graph-Based Data Representation***: Maps nodes and edges of cyber threats.                   | 1. Links attack components like Threat Actor to Malware.<br>2. Enables advanced graph analytics.|
|                           | ***Relationship Objects for Contextual Decision-Making***: Adds depth to automated responses.      | 1. Prioritizes actions based on relationships (e.g., "indicates" vs. "targets").              |
| ***Advanced Features Benefiting AI Defenders*** | ***Confidence Scoring***: Assigns reliability levels to intelligence.                           | 1. Enables AI models to weigh and prioritize data.<br>2. Improves accuracy of automated decisions. |
|                           | ***Open Vocabularies for Standardization***: Provides consistent terms for key concepts.            | 1. Improves accuracy of AI-driven categorization.<br>2. Standardizes data for interoperability.|
|                           | ***Extension Mechanisms***: Adds flexibility to meet custom needs.                                 | 1. Tailors intelligence for unique AI systems.<br>2. Allows seamless updates for emerging threats. |


###### 6.1.4.1.6. What is missing for defenders of AI systems

While STIX 2.1 is a powerful framework for sharing and representing Cyber Threat Intelligence (CTI), there are several gaps when it comes to AI system-specific threats, including adversarial attacks, model integrity, and real-time learning. Defenders of AI systems need additional tools, object types, and relationships within the STIX framework to represent and address the unique threats posed to AI, especially as these systems become more integral to cybersecurity efforts.

The inclusion of AI-specific elements within STIX 2.1 would provide a more comprehensive approach to protecting AI models and infrastructure from cyberattacks, ensuring that AI-driven cybersecurity solutions can be as secure as possible.

***Key Missing Elements***

1. **Threat Representation for AI:** While STIX 2.1 represents traditional cyber threats well, there are no dedicated constructs for AI-specific threats (e.g., adversarial attacks, data poisoning, model evasion).
2. **AI Model Integrity and Trust:** The architecture doesn't include ways to monitor or assess AI model integrity, making it difficult to track AI-specific weaknesses.
3. **Adversarial Attacks and AI-specific Threat Chains:** Missing definitions for adversarial AI attacks (e.g., adversarial inputs, model inversion) within the STIX model makes it hard to track threats to AI systems.
4. **Dynamic Learning and Real-Time Threat Integration:** AI models evolve over time, and STIX 2.1 does not currently address continuous model updates, leaving defenders without an integrated solution for real-time learning adjustments.
5. **Storage of AI-specific Data in STIX 2.1:** There is a lack of focus on storing, querying, and sharing data about AI models and their associated data streams or continuous learning processes in a way that makes it actionable for defenders.


<br><br>

***Other Challenges and Considerations***

| **Challenge**   | **Description**          | **Impact on AI Systems**   | **Impact on Cybersecurity Operations**   |
|-----------------|--------------------------|----------------------------|------------------------------------------|
| **High Volume Data Streams**                | Managing and processing large amounts of STIX data in real-time or near-real-time scenarios.                  | Performance bottlenecks when ingesting or processing high volumes of STIX data.     | Difficult to maintain real-time detection and response at scale.                   |
|                                             |                                                                                                             | Latency in processing large volumes impacts AI decision-making speed.               | Slower response times and delayed threat detection due to high data volume.        |
| **Accuracy and Relevance of Detection**     | Ensuring that AI models correctly detect and prioritize relevant threats from large datasets.                | High false positive/negative rates if the model is trained on irrelevant data.      | Difficulty in distinguishing relevant from non-relevant threats, impacting response.|
|                                             |                                                                                                             | Misclassification of data could lead to inaccurate automated responses.             | Increased workload for human analysts due to irrelevant alerts.                    |
| **Storage and Querying Efficiency (SQL)**   | Storing and querying graph-based STIX data efficiently in relational databases.                              | SQL databases may struggle with handling highly interconnected data like STIX objects. | Performance degradation when querying for complex relationships in large datasets. |
|                                             |                                                                                                             | Complex joins for relationships can significantly slow down performance.            | Difficulty scaling SQL systems to accommodate the volume and complexity of STIX data. |
| **Storage and Querying Efficiency (NoSQL)** | Handling STIX 2.1 graph data in NoSQL databases that are designed for unstructured data.                      | NoSQL databases may face challenges maintaining relationships in graph-based data.  | Complex querying over unstructured NoSQL data may result in slow responses.       |
|                                             |                                                                                                             | Lack of structured schema leads to difficulties in querying related STIX objects.    | Inconsistent or missing relationships make it difficult to analyze threat connections. |


<br><br>

#### 6.1.5. MIT

##### 6.1.5.1. MIT AI Risk Repository

###### 6.1.5.1.1. Overview

MIT FutureTech along with the University of Queensland developed the AI Risk Repository to provide an accessible and extensible overview of threats from AI.  The Risk Repository includes a website with a growing repository of over 1000 risks taken from other publications, using the corpus of publications to inform taxonomies on AI Risk.  A high level causal taxonomy and a more detailed multi-level domain taxonomy are provided as tools for policy makers, risk evaluators, industry and academic AI users, developers, and defenders.  


###### 6.1.5.1.2. Scoping of AI system and/or cybersecurity purview

The AI Risk Repository addresses risks from the human-level capabilities of AI systems.  The domain taxonomy contains 7 main domains, of which the domain Privacy and Security contains the subdomain AI system security vulnerabilities and attacks.  Other risks MIT identifies including violations of privacy, misuse of AI to conduct fraud or cyberattacks, and misalignment of AI systems also inform defenders of AI systems of additional risks to these systems.  Risks of human overreliance on AI or human loss of agency are worth considering as a great of deal of security becomes automated with AI tools.


###### 6.1.5.1.3. Persona addressed

This work seeks to address all stakeholders of AI risk.  As such it aims for policymakers and regulators with a comprehensive treatment of risks, and comprehensible taxonomies.  It also serves academics and researchers well, synthesizing dozens of other AI risk frameworks and taxonomies, and providing both a starting and landing spot for additional work on AI risk.  Finally it informs industry of risks of AI systems, so that safer systems may be developed.  As such, it does not specifically address cyber defenders nor defenders of AI systems.


###### 6.1.5.1.4. Guidance provided

The causal and domain taxonomies provide common terminology to discuss AI risks.  Tying these risks to a body of knowledge detailing these risks as well as mapping to incidents manifesting the risk make the AI Risk Repository a map to additional detail on risk research.  Providing a database to record new risks and incorporate new frameworks keeps the risk map up to date.



###### 6.1.5.1.5. Detail on current framework

**Causal Taxonomy**

The Causal Taxonomy provides three risk features, each with three values:
+ ***Entity:*** Human, Computer, Other
+ ***Intent:***  Unintentional, Intentional, Other
+ ***Timing:*** Pre-Deployment, Post-Deployment, Other

The simplicity of this enables quick assignment of the cause of a risk, pointing to preventative strategies for what, how and when a risk should be mitigated.  These features are easily explained to a wide audience, and serve as a durable risk taxonomy, with distinctions that will continue to provide value in understanding the causes of AI risk.


| **Category**       | **Level**         | **Description**                                      |
|--------------------|------------------|------------------------------------------------------|
| AI                | Decision-based    | Due to a decision or action made by an AI system    |
| Human             | Decision-based    | Due to a decision or action made by humans         |
| Other             | Ambiguous         | Due to some other reason or ambiguous factors       |
| **Intentionality**| **Type**          | **Description**                                      |
| Intentional       | Expected Outcome  | Due to an expected outcome from pursuing a goal    |
| Unintentional     | Unexpected Outcome| Due to an unexpected outcome from pursuing a goal  |
| Other            | Unspecified       | Without clearly specifying the intentionality      |
| **Timing**       | **Stage**         | **Description**                                      |
| Pre-deployment   | Before Deployment | Before the AI is deployed                          |
| Post-deployment  | After Deployment  | After the AI model has been trained and deployed   |
| Other           | Unspecified       | Without a clearly specified time of occurrence     |


**Domain Taxonomy**

The AI Risk Repository groups risk into 7 major domains, each with subdomains.  This taxonomy was built using experts synthesis of publications on AI risks, with natural language analysis to cluster the topics.  The domains and subdomains are identified in the AI Risk Repository as shown in this table: 


| **Domain**                         | **Subdomain**                                                    |
|------------------------------------|-----------------------------------------------------------------|
| **1. Discrimination & Toxicity**      | 1.1. Unfair discrimination and misrepresentation                    |
|                                    | 1.2. Exposure to toxic content                                      |
|                                    | 1.3. Unequal performance across groups                             |
| **2. Privacy & Security**             | 2.1. Compromise of privacy by obtaining, leaking, or inferring sensitive information |
|                                    | 2.2. AI system security vulnerabilities and attacks                |
| **3. Misinformation**                 | 3.1. False or misleading information                               |
|                                    | 3.2. Pollution of information ecosystem and loss of consensus reality |
| **4. Malicious Actors & Misuse**      | 4.1. Disinformation, surveillance, and influence at scale          |
|                                    | 4.2. Cyberattacks, weapon development or use, and mass harm       |
|                                    | 4.3. Fraud, scams, and targeted manipulation                       |
| **5. Human-Computer Interaction**     | 5.1. Overreliance and unsafe use                                   |
|                                    | 5.2. Loss of human agency and autonomy                            |
| **6. Socioeconomic & Environmental Harms** | 6.1. Power centralization and unfair distribution of benefits      |
|                                    | 6.2. Increased inequality and decline in employment quality       |
|                                    | 6.3. Economic and cultural devaluation of human effort           |
|                                    | 6.4. Competitive dynamics                                         |
|                                    | 6.5. Governance failure                                           |
|                                    | 6.6. Environmental harm                                           |
| **7. AI System Safety, Failures & Limitations** | 7.1. AI pursuing its own goals in conflict with human goals or values |
|                                    | 7.2. AI possessing dangerous capabilities                         |

**Ongoing Monitoring and Integrations**

The approach to create the AI Risk Repository used published data to drive the groupings, collecting a large body of information on AI Risks and determining the repeated themes.  The AI Risk Repository framework was updated in December 2024 to map additional risk frameworks or taxonomies to the AI Risk Repository, including a number of 2024 publications from leading groups on AI safety.  Regular updates such as this are required to keep frameworks applicable in a changing technological landscape.

The AI Risk Repository is mapped to the AI Incident Database, an open public repository for indexing harms or near-harms from AI systems.  The AI Risk Repository promotes a side project, the AI Incident Tracker, that maps new incidents added to the AI Incident Database to the AI Risk Repository.  This approach grounds theoretical risks with real incidents, and provides an extensible methodology to incorporate new information.

The Paris Peace Forum selected the AI Risk Repository as one the of 50 AI Projects they will promote at the 2025 AI Action Summit.  The AI Risk Repository will inform more policy makers, auditors, and AI technologists promoted in this way, and its adoption is likely to increase across the global audience.


###### 6.1.5.1.6. What is missing for defenders of AI systems

The AI Risk Repository implications for Industry states: "As shown in our causal analysis, many risks are presented as being about AI, while in reality the mitigation of these risks requires a human doing something differently during conceptualisation, design, development, governance, or use."  While the guidance provided does indicate many mitigations to human caused risks for AI, there is little specifically informing defenders of AI systems.

Key items that would help inform defenders of AI systems about risks include:
+ A threat model that shows increased risks from attacks on AI systems
+ Decomposing AI systems into reference architectures
  + Vulnerabilities are rarely 'system' vulnerabilities, and often apply to a component
  + SPM decomposes systems to ensure their security
  + ZTA decomposes systems to ensure their security
+ Signing or authenticating provenance
  + Model Bill Of Materials, Software Bill Of Materials
  + Human signed content vs AI self-identified content 
+ Mapping Risks to Remediations
  + Associate each of the risks identified to steps that can prevent or resolve the risk


<br><br>

<br><br>

#### 6.1.6. OCSF

##### 6.1.6.1. Open Cybersecurity Schema Framework (OCSF)

###### 6.1.6.1.1. Overview

The Open Cybersecurity Schema Framework (OCSF) is an open-source, vendor-neutral framework designed to standardize security event data across various security products. It was created to address inconsistent log formats, interoperability issues, and complex security analytics caused by disparate security data sources. 

The cybersecurity landscape is evolving at an unprecedented pace, with organizations leveraging multiple security tools, platforms, and technologies to detect, analyze, and respond to threats. However, a lack of standardization in security event data formats has led to significant challenges:

+ ***Inconsistent Log Formats:*** Different security tools (e.g., SIEM, EDR, NDR, IDS, SOAR) generate logs in proprietary formats, making correlation complex.
+ ***Data Silos:*** Security analysts must normalize and map logs manually, delaying threat detection and response.
+ ***High Integration Costs:*** Organizations spend millions of dollars on custom connectors and ETL pipelines to unify data.
+ ***Limited Automation:*** Disparate data structures make it difficult for AI/ML models to detect anomalies efficiently.

The Open Cybersecurity Schema Framework (OCSF) directly addresses these issues by providing a standardized, vendor-neutral schema for cybersecurity event data.


###### 6.1.6.1.2. Scoping of AI system and/or cybersecurity purview

<br><br>

***OCSF Scoping in AI Systems***

OCSF enables AI-driven security analytics by providing structured, standardized security event data. This table outlines key AI use cases and how OCSF supports them.

| **AI Functionality**   | **OCSF Guidance**    | **AI Use Cases**     |
|------------------------|----------------------|----------------------|
| **Data Standardization for AI Models**     | Ensures AI receives well-structured, normalized security event data.                              | 1. AI-driven SIEM/XDR for faster security threat detection. <br> 2. AI-based UEBA for behavioral anomaly detection. |
| **AI-Driven Security Analytics**           | Provides a common security event structure for AI correlation engines.                            | 1. AI-powered SOC automation for real-time log triage and prioritization. <br> 2. AI-enhanced attack pattern recognition. |
| **Threat Intelligence & Correlation**      | Enables AI to cross-correlate security events across multiple domains.                        | 1. AI-based forensic investigations using OCSF event metadata. <br> 2. AI-powered fraud detection for identity compromise analysis. |
| **Real-Time Threat Detection**             | Provides standardized timestamps, severity levels, and categories for ML models.                 | 1. Time-series anomaly detection for detecting security incidents. <br> 2. AI-powered intrusion detection based on OCSF-defined thresholds. |
| **Automated Incident Response**            | Enables AI-driven SOAR platforms to use structured logs for security automation.                 | 1. AI-driven automated playbooks using structured OCSF logs. <br> 2. Automated incident prioritization using AI-based risk scoring. |
| **Predictive Analytics & Threat Forecasting** | Supports AI-based predictive security models with historical event correlation.             | 1. AI-powered attack surface monitoring based on historical OCSF logs. <br> 2. AI-driven attack path prediction using event correlation. |
| **Compliance & Security Auditing**         | Helps AI-driven tools analyze logs for policy violations and regulatory compliance.          | 1. AI-driven automated compliance scanning (e.g., SOC 2, GDPR). <br> 2. AI-based security policy enforcement using NLP models. |

<br><br>

***OCSF Scoping in Cybersecurity***

OCSF enhances cybersecurity operations by providing a standardized approach to security event logging, threat detection, and compliance enforcement. This table outlines key cybersecurity domains and how OCSF supports them.

| **Cybersecurity Domain**   | **OCSF Guidance**     | **Cybersecurity Use Cases**  |
|----------------------------|-----------------------|------------------------------|
| **Security Operations (SOC)**          | Standardizes log ingestion and correlation for SIEM, XDR, and security monitoring.           | 1. Automated log correlation in SIEMs (Splunk, Sentinel, QRadar). <br> 2. Threat detection playbooks using OCSF-defined event categories. |
| Cloud Security & Zero Trust        | Enables consistent security event monitoring across multi-cloud and hybrid environments.      | 1. Cloud security monitoring in AWS GuardDuty, Azure Sentinel. <br> 2. Zero Trust access models using OCSF authentication logs. |
| Threat Intelligence & Incident Response | Maps security events to known adversary techniques for faster detection and response.       | 1. Threat intelligence platforms using OCSF for structured threat feeds. <br> 2. Incident response teams querying OCSF logs for forensic investigations. |
| Policy & Compliance Enforcement    | Simplifies audit logging, security assessments, and compliance reporting.                    | 1. Automated compliance enforcement (SOC 2, GDPR, NIST). <br> 2. Regulatory audits using OCSF event mappings. |
| Security Automation & SOAR         | Provides structured event formats for automated incident handling and response.              | 1. SOAR playbooks using OCSF for automated security workflows. <br> 2. Automated threat mitigation based on OCSF-defined alerts. |
| Forensics & Legal Defensibility    | Structures event logs to improve investigation timelines and digital forensics.              | 1. Legal defensibility through structured event retention. <br> 2. Incident reconstruction using OCSF event sequences. |


<br><br>

###### 6.1.6.1.3. Persona addressed

***Target Audience***

+ **CISO/SSO:** Strategic alignment of security event logging and monitoring.
+ **Security Architects:** Designing structured logging and security monitoring for AI.
+ **SOC Operations:** Implementing OCSF for real-time threat detection and SIEM integration.
+ **IT Operations:** Ensuring consistent logging and monitoring for AI environments.
+ **Service Operations:** Operationalizing security monitoring for AI services.

<br><br>

***Roles and Activities***

| **Activity**                          | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|--------------------------------------------|---------------|-------------|------------------------|-------------------|------------------------|-------------------|-------------------|------------------------|----------------------------|------------------------------|-------------------------|
| Define OCSF Adoption Strategy          | **A**             | R           | C                      | C                 | C                      | I                 | I                 | I                      | C                          | C                            | I                       |
| Schema Design & Customization          | I             | I           | R                      | C                 | **A**                      | I                 | C                 | I                      | I                          | R                            | I                       |
| Integration with Security Tools        | I             | **A**           | R                      | R                 | R                      | R                 | R                 | R                      | I                          | C                            | I                       |
| Event Mapping & Normalization          | I             | C           | C                      | R                 | **A**                      | I                 | R                 | R                      | I                          | C                            | I                       |
| Security Operations & Monitoring       | I             | C           | I                      | I                 | C                      | R                 | **A**                 | C                      | I                          | I                            | C                       |
| Incident Detection & Response          | I             | C           | I                      | I                 | C                      | R                 | **A**                 | R                      | I                          | I                            | C                       |
| Data Analytics & Reporting             | I             | C           | I                      | C                 | C                      | I                 | R                 | I                      | C                          | **A**                            | C                       |
| Compliance & Audit Reporting           | I             | R           | C                      | C                 | C                      | I                 | C                 | I                      | **A**                          | C                            | I                       |
| Threat Intelligence Correlation        | I             | C           | **A**                      | C                 | C                      | I                 | R                 | I                      | C                          | C                            | C                       |
| Training & Awareness Programs          | **A**             | R           | C                      | C                 | C                      | I                 | I                 | I                      | C                          | C                            | R                       |
| Continuous Schema Improvement          | I             | C           | R                      | C                 | **A**                      | I                 | C                 | I                      | C                          | **A**                            | I                       |
| Research & Development                 | I             | C           | I                      | I                 | C                      | I                 | C                 | I                      | C                          | **A**                            | I                       |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

<br><br>

###### 6.1.6.1.4. Guidance provided

The Open Cybersecurity Schema Framework (OCSF) provides a structured and standardized approach to security event data, which directly benefits Artificial Intelligence (AI) and Machine Learning (ML) systems used in cybersecurity. OCSF helps AI-driven security analytics, threat detection, and automation by ensuring consistent, high-quality data ingestion and processing.

The structured, enriched, and extensible data model of OCSF makes it an ideal foundation for AI-driven cybersecurity solutions. By leveraging OCSF, AI models can: 

+ Improve threat detection accuracy
+ Enhance correlation and anomaly detection
+ Automate incident response
+ Support predictive analytics and risk forecasting
+ Enable AI-driven compliance monitoring

OCSF bridges the gap between raw security event data and AI analytics, making security operations more efficient, intelligent, and automated. 



###### 6.1.6.1.5. Detail on current framework

OCSF is designed to normalize security event data while remaining flexible and extensible. The framework is structured into three main layers:

**Architectural Design of OCSF**

OCSF is structured into three primary layers: **Data Model Layer, Processing Layer, and Consumption Layer**, each playing a critical role in standardizing cybersecurity event data.

| **Layer**           | **Description**                                                                                     | **Key Components**                                                                                           |
|---------------------|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| **Data Model Layer** | Defines the **core event schema** and organizes event data into structured formats.               | - **Event Classes** (e.g., Authentication, Network Traffic) <br> - **Categories** (logical grouping of events) <br> - **Profiles** (contextual attributes) <br> - **Extensions** (custom attributes & event types) |
| **Processing Layer** | Manages data ingestion, validation, and transformation processes.                                | - **Event Mapping** (translates raw logs to OCSF format) <br> - **Validation Engine** (ensures schema compliance) <br> - **Event Enrichment** (adds contextual data via profiles) |
| **Consumption Layer** | Enables security teams to analyze, correlate, and automate security events using OCSF-standardized data. | - **Threat Detection & Response** (SIEM, XDR, SOAR) <br> - **Incident Investigation & Forensics** <br> - **Threat Intelligence Correlation** <br> - **Security Automation & AI-driven Analytics** |

**Key Features of OCSF**


OCSF introduces several key features that enhance security data interoperability, threat detection, and automation.

| **Feature**                  | **Description**                                                                                  |
|------------------------------|----------------------------------------------------------------------------------------------|
| **Schema-Agnostic & Extensible** | Works with any storage format (JSON, Parquet, Syslog, etc.) and supports custom extensions.  |
| **Structured Taxonomy**       | Organizes security events into well-defined categories, event classes, and profiles.     |
| **Interoperability**          | Enables seamless integration across SIEM, SOAR, XDR, and cloud security platforms.        |
| **Improved Threat Detection** | Provides structured event attributes that enhance threat correlation & automation.   |
| **Lower Operational Costs**   | Reduces the need for custom log parsers and data transformation pipelines.                |
| **Supports Compliance & Regulations** | Aligns with NIST, ISO 27001, MITRE ATT&CK, and CIS Controls for standardized compliance reporting. |

**Structured Taxonomy of OCSF**

OCSF organizes security event data into six key constructs, ensuring structured classification, extensibility, and interoperability.

| **Construct**          | **Description**                                                                               | **Example Usage** |
|-----------------------|----------------------------------------------------------------------------------------------|-------------------|
| **Data Types & Attributes** | Defines primitive (strings, integers, timestamps) and complex (User, Process, Device) data types. | `IP Address`, `MAC Address`, `Timestamp`, `Process Name` |
| **Objects**           | Represents structured collections of attributes that define entities involved in an event. | `User`, `Process`, `Device`, `Network Connection` |
| **Event Classes**      | Represents specific types of security events. Each class has a unique identifier.         | `Authentication`, `File Access`, `Network Connection` |
| **Categories**         | Groups event classes into logical security domains for organization and searchability.    | `System Activity`, `Findings`, `IAM`, `Network Activity` |
| **Profiles**          | Overlays additional attributes to enrich event data with context.                         | `Malware Detection Profile`, `Cloud Profile` |
| **Extensions**        | Allows customization by adding new attributes, event classes, or categories without modifying the core schema. | Custom `IoT Security Events`, `Industry-Specific Threat Indicators` |



###### 6.1.6.1.6. What is missing for defenders of AI systems

While OCSF (Open Cybersecurity Schema Framework) provides a structured way to standardize security event data, it currently lacks specific provisions for AI system defenders. AI-driven cybersecurity solutions require specialized telemetry, threat models, and security controls that are not fully addressed in OCSF. OCSF needs enhancements to support AI system defenders, focusing on AI-specific threat detection, logging, and governance. This table outlines key gaps, issues, and potential solutions.

| **Category**  | **Issue**   | **Potential Solution**     |
|---------------|-------------|----------------------------|
| **AI-Specific Threat Event Categories** | Lacks event classes for AI security threats (e.g., data poisoning, model evasion, adversarial ML). | 1. Introduce AI-Specific Event Classes in OCSF. <br> 2. Align with MITRE ATLAS for adversarial ML threats. |
| **AI Logging & Telemetry**            | No standard way to log AI security events (e.g., model drift, inference anomalies, training data integrity). | 1. Extend OCSF attribute dictionary to include AI telemetry. <br> 2. Define structured logs for AI model access & modifications. |
| **AI Threat Intelligence & IOCs**     | No support for AI-specific threat intelligence feeds, such as adversarial samples, model scraping, or model inversion attacks. | 1. Introduce AI-related threat intelligence fields. <br> 2. Integrate with MITRE ATLAS and AI-specific IOCs. |



<br><br>

#### 6.1.7. OWASP


##### 6.1.7.1. Top 10 for LLM Applications 2025


###### 6.1.7.1.1. Overview

The OWASP Top 10 for LLM Applications (2025) highlights critical security risks associated with large language model (LLM) applications, emphasizing threats that can compromise confidentiality, integrity, and availability. As name of this paper emplies, it is focusing on top 10 risks:

1. ***Prompt injection*** remains a major concern, allowing attackers to manipulate LLM behavior and bypass safety controls. 
2. ***Sensitive information disclosure*** can lead to unintended exposure of personally identifiable information (PII) and proprietary data. 
3. ***Supply chain risks*** introduce vulnerabilities from third-party models, datasets, and dependencies, making rigorous vetting essential. 
4. ***Insecure output handling*** poses risks of code injection and cross-site scripting (XSS) if LLM-generated content is not properly sanitized. 
5. ***Excessive agency***, where LLMs have unchecked permissions, can lead to unauthorized actions and security breaches. 
6. ***Unbounded resource consumption*** (denial-of-service attacks) can overwhelm systems through excessive query loads, requiring rate limiting and anomaly detection. 
7. ***Data poisoning*** threatens model integrity by injecting manipulated training data, leading to biased or malicious outputs. 
8. ***System prompt leakage*** can expose internal logic, enabling attackers to reverse-engineer security mechanisms. 
9. ***Overly permissive integrations*** pose risks when LLMs are granted excessive API access, increasing the attack surface. 
10. ***Model theft and extraction attacks*** threaten intellectual property by leveraging repeated queries to reconstruct model behavior. 

To mitigate these risks, organizations must enforce strong input/output validation, least privilege principles, robust authentication, adversarial testing, continuous monitoring, and AI-specific security controls to safeguard LLM applications from evolving threats.

<br><br>

###### 6.1.7.1.2. Scoping of AI system and/or cybersecurity purview

***AI System Scoping: Components and Boundaries***

| **AI System Scope**                 | **Description** |
|--------------------------------------|----------------|
| **Model Lifecycle Security**         | Covers pre-training, fine-tuning, deployment, and monitoring of LLMs. Protects against model poisoning, adversarial attacks, and unauthorized modifications. |
| **Data Ingestion & Processing**      | Ensures data integrity, provenance, and compliance with privacy laws (GDPR, CCPA). Implements data sanitization, differential privacy, and access controls. |
| **AI Supply Chain Risks**            | Manages third-party models, dataset security, and dependency vulnerabilities. Introduces Software Bill of Materials (SBOM) for AI and model provenance verification. |
| **Secure Model APIs & Interfaces**   | Covers authentication, authorization, and secure API interactions. Mitigates unauthorized API access, prompt injection, and excessive agency. |
| **End-User Interaction & Prompt Handling** | Implements content moderation, input validation, and prompt filtering to defend against prompt manipulation and malicious injections. |
| **System Prompt & Configuration Protection** | Prevents system prompt leakage, unauthorized configuration changes, and model inversion attacks. |
| **Adversarial & Security Testing**   | Deploys adversarial robustness training, anomaly detection, and penetration testing for AI security validation. |

<br>

***Cybersecurity Purview: AI-Specific Threats and Defenses***

| **Cybersecurity Domain**             | **AI-Specific Considerations** |
|--------------------------------------|--------------------------------|
| **Identity & Access Management (IAM)** | Enforces RBAC, OAuth-based access control, and zero-trust principles for AI APIs and LLM services. |
| **Threat Detection & Incident Response** | Deploys AI-driven anomaly detection, logging, and adversarial attack monitoring. |
| **Data Security & Governance**        | Implements data encryption, secure storage, and regulatory compliance with GDPR, CCPA, and ISO/IEC standards. |
| **Application Security**              | Applies secure output handling, sanitization, and context-aware filtering to prevent SQL injection, XSS, and LLM-based attacks. |
| **Cloud & Edge AI Security**          | Addresses cloud-based LLM deployments, AI supply chain integrity, and edge AI security risks. |


<br>

###### 6.1.7.1.3. Persona addressed

***Target Audience***

+ **CISO/SSO:** Governance of secure AI application development.
+ **Service Architects:** Designing resilient AI services against LLM-specific vulnerabilities.
+ **Security Architects:** Implementing security controls against adversarial LLM threats.
+ **IT Architects:** Securing AI deployment pipelines and infrastructure.
+ **SOC Operations:** Monitoring and detecting AI-specific attacks (e.g., prompt injection).
+ **Researchers/Data Scientists:** Securing LLMs and ensuring adversarial robustness.


<br><br>

***Roles and Activities***

| **Activity**                          | **Executives** | **CISO/SSO** | **Service Architects** | **IT Architects** | **Security Architects** | **IT Operations** | **SOC Operations** | **Service Operations** | **Auditors/Policy Makers** | **Researchers/Data Scientists** | **Users/Practitioners** |
|--------------------------------------------------|--------------|-------------|--------------------|---------------|-------------------|--------------|--------------|-----------------|----------------------|----------------------|------------------|
| Secure Development Lifecycle (SDLC)         | **A**            | R           | R                 | C             | C                 | C            | I            | C               | I                    | C                    | I                |
| Risk-Based Approach to LLM Security         | **A**            | R           | C                 | C             | R                 | I            | C            | I               | R                    | C                    | I                |
| Threat Modeling for LLM Applications        | I            | R           | C                 | C             | **A**                 | I            | C            | I               | R                    | C                    | I                |
| Secure AI Supply Chain Management           | **A**            | R           | R                 | C             | R                 | C            | I            | I               | R                    | C                    | I                |
| Robust Access Control & Data Privacy        | **A**            | R           | C                 | C             | R                 | R            | C            | C               | R                    | C                    | I                |
| Secure Output Handling & Content Moderation | I            | R           | C                 | C             | **A**                 | R            | R            | C               | C                    | C                    | C                |
| AI Model Robustness & Adversarial Defense   | I            | R           | C                 | C             | R                 | C            | **A**            | C               | C                    | R                    | C                |
| Monitoring & Incident Response              | I            | R           | C                 | C             | R                 | R            | **A**            | C               | C                    | C                    | C                |

---

***Legend:***
- **R** = Responsible (Performs the task/work)
- **A** = Accountable (Ultimate authority and decision-maker)
- **C** = Consulted (Provides input and expertise)
- **I** = Informed (Kept in the loop)
- **"-"** = No direct involvement

<br><br>

###### 6.1.7.1.4. Guidance provided

The OWASP Top 10 for LLM Applications (2025) provides structured guidance to ensure secure AI system deployment, mitigate cybersecurity risks, and establish compliance with industry standards. Below is a summary of the key guidance outlined in the framework.


| **Category**       | **Guidance** |
|--------------------|--------------|
| ***Secure Development and Risk Mitigation*** | 1. Adopt a Zero-Trust Approach: Treat the LLM as an untrusted entity and enforce strict input validation and output filtering. <br> 2. Apply OWASP ASVS Standards: Follow Application Security Verification Standards (ASVS) for input validation, sanitization, and authentication. <br> 3. Implement Content Security Policy (CSP): Prevent Cross-Site Scripting (XSS) and code injection via secure encoding mechanisms. <br> 4. Use Parameterized Queries: Protect against SQL injection with prepared statements for database operations. <br> 5. Monitor and Log Model Activity: Deploy anomaly detection to identify suspicious behavior. |
| ***Data Protection and Privacy Considerations*** | 1. Educate Users on Secure AI Usage: Train users on safe LLM interactions and avoiding disclosure of sensitive data. <br> 2. Ensure Transparency in Data Handling: Maintain clear policies on data retention, processing, and deletion. <br> 3. Reference OWASP API Security Best Practices: Prevent API misconfigurations and protect against sensitive data leaks. <br> 4. Use Homomorphic Encryption: Secure AI processing with encrypted computations. <br> 5. Apply Tokenization and Redaction: Sanitize sensitive data before it enters the AI pipeline. |
| ***Model Security and Robustness*** | 1. Guard Against System Prompt Leakage: Conceal system prompts to prevent unauthorized access to model configurations and security rules. <br> 2. Avoid Over-Reliance on System Prompts: Ensure security controls are enforced externally, rather than relying on AI-generated constraints. <br> 3. Employ Adversarial Robustness Training: Defend against data poisoning and model inversion attacks through continuous AI security testing. <br> 4. Use Centralized ML Model Inventory: Maintain an AI Model Bill of Materials (ML SBOM) to track dependencies and security risks. <br> 5. Watermark LLM Outputs: Implement digital watermarking to detect unauthorized use of AI-generated content. |
| ***Secure AI System Operations*** | 1. Limit Model Privileges: Ensure LLMs do not have excessive permissions to execute unintended actions (Excessive Agency risks). <br> 2. Apply Rate Limiting and Quotas: Enforce throttling mechanisms to prevent unbounded resource consumption (Denial-of-Service attacks). <br> 3. Implement Multi-Agent Segregation: Ensure role-based separation for AI agents interacting with external systems. <br> 4. Monitor AI API Calls: Deploy continuous monitoring and anomaly detection for all LLM interactions with backend systems. |
| ***Incident Response and Compliance*** | 1. Define an AI Security Incident Response Plan: Establish predefined actions to contain, analyze, and remediate AI-related security breaches. <br> 2. Ensure Compliance with Global AI Security Standards: Align with NIST AI RMF, MITRE ATLAS, ISO/IEC 42001, and OWASP ML Security Top 10. <br> 3. Perform Regular Security Audits: Conduct periodic AI system assessments to ensure continued alignment with cybersecurity best practices. |


<br><br>

###### 6.1.7.1.5. Detail on current framework

OWASP Top 10 for LLM Applications (2025) document for each risk follows a consistent structure:
+ Title & Risk Identifier (LLM01 - LLM10)
+ Description of the Risk
+ Common Vulnerability Examples
+ Prevention & Mitigation Strategies
+ Example Attack Scenarios
+ Reference Links to Related Frameworks & Research

Document aligns security best practices with MITRE ATLAS tactics and provides detailed mitigation measures using "Zero Trust Model for AI", "RBAC and OAuth-Based Access Controls", "Adversarial Robustness Training", "Watermarking and Secure AI Supply Chain Management​".


###### 6.1.7.1.6. What is missing for defenders of AI systems

AI security requires continuous adaptation as adversaries develop new attack techniques. The OWASP Top 10 for LLM Applications must expand its scope by integrating MITRE ATLAS threat intelligence, red teaming methodologies, and AI-specific security controls. By addressing gaps in AI supply chain security, adversarial attack prevention, and incident reporting, defenders can better protect LLM applications in enterprise, cloud, and military environments.

<br><br>

#### 6.1.8. Amazon


##### 6.1.8.1. The AWS Generative AI Security Scoping Matrix


###### 6.1.8.1.1. Overview

The AWS Generative AI Security Scoping Matrix is a comprehensive framework developed to help organizations navigate the complex landscape of generative AI security. This structured approach categorizes AI implementations based on the level of control and ownership an organization has over their AI solutions, ranging from using public services to developing custom AI models from scratch. The matrix serves as a guide for identifying appropriate security measures, governance requirements, and risk management strategies that can vary based on the specific implementation scope. It provides organizations with a systematic way to assess their security needs and responsibilities while offering flexibility to adapt to various use cases across different industries and applications.

The AWS Generative AI Security Scoping Matrix docuements 5 scopes of AI applications based on defining the followoing model use cases (aka - "scopes"):
1. Consumer App
2. Enterprise App
3. Pre-built model 
4. Fine-tuned model
5. Self-trained model

<br><br>

###### 6.1.8.1.2. Scoping of AI system and/or cybersecurity purview

The AWS Generative AI Security Scoping Matrix contains 5 key security domains that defenders must consider when deploying AI systems.  Each security domain contains unqiue requriements depending on the scope of the AI system deployed.

| Security Domain | Description |
|--|--|
| **Governance and compliance** | The policies, procedures, and reporting needed to empower the business while minimizing risk. |
| **Legal and privacy** | The specific regulatory, legal, and privacy requirements for using or creating generative AI solutions. |
| **Risk management** | Identification of potential threats to generative AI solutions and recommended mitigations. |
| **Controls** | The implementation of security controls that are used to mitigate risk. |
| **Resilience** | How to architect generative AI solutions to maintain availability and meet business SLAs. |
<br>

###### 6.1.8.1.3. Persona addressed

The AWS Generative AI Security Scoping Matrix is designed to provide value to many different stakeholders within an organization.  

***Target Audience***

+ **Executives:** Use the matrix to understand the unique security implications across differnt AI use cases and make informed decisions about AI adoption strategies based on risk appetite and control requirements.
+ **CISO/SSO:** Evaluate security controls and develop governance frameworks tailored to different AI deployment models and implementation scopes.
+ **Procurement:** Create evaluation criteria for AI model or solution purchasing to determine how security requirements will be met depending on scope.
+ **Legal:** Understand the EULA, Terms & Conditions, and other contractual implications, including data privacy agreements based on the implelention scope.
+ **Service Architects:** Design secure AI services by selecting appropriate security patterns and controls based on the implementation scope.
+ **IT Architects:** Plan infrastructure security and implement controls aligned with the specific needs of each AI service scope.
+ **Security Architects:** Define security requirements and design defense-in-depth strategies appropriate for each AI implementation scope.
+ **IT Operations:** Implement and maintain security controls appropriate for different AI service scopes while monitoring overall security posture.
+ **SOC Operations:** Monitor AI systems and respond to threats based on scope-specific security requirements and risk profiles.
+ **Service Operations:** Operate AI services within defined security parameters while maintaining scope-specific controls and monitoring.
+ **Auditors/Policy Makers:** Validate that security controls align with implementation scope and ensure compliance requirements are met for each AI service tier.
+ **Researchers/Data Scientists:** Implement appropriate controls during model development and follow security best practices based on the chosen implementation scope.
+ **Users/Practitioners:** Follow security procedures and usage policies appropriate for the AI service scope while reporting any security issues through defined channels.

<br><br>

###### 6.1.8.1.4. Guidance provided

The AWS Generative AI Security Scoping Matrix helps defenders identify and implement appropriate security controls by providing a structured framework that aligns security measures with the organization's level of control over their AI implementation, from using public AI services to developing custom models.


| **Category**       | **Guidance** |
|--------------------|--------------|
| ***Shared Responsibility Model*** | The matrix clarifies the division of security responsibilities between the organization and the service provider. This varies significantly across the five scopes, from minimal organizational responsibility in Scope 1 (Consumer Apps) to full responsibility in Scope 5 (Self-trained Models). Understanding this division is crucial for ensuring comprehensive security coverage without gaps or redundancies. |
| ***Scope-Based Security Controls*** | Security measures should be tailored to the specific implementation scope. The matrix outlines different security considerations for each scope, ranging from basic data protection and user management in Scope 1 to comprehensive model security, training data protection, and infrastructure security in Scope 5. This approach ensures that security investments are proportional to the complexity and risk level of the AI implementation. |
| ***Scope-Based Risk Management*** | Each scope in the matrix presents distinct security challenges and risk profiles that require specific attention. Rather than viewing security as a progressive implementation, organizations should focus on addressing the unique risk characteristics of their chosen scope. This approach ensures that security measures are optimized for the specific implementation model, whether it's managing API access in Scope 2 or protecting proprietary model architectures in Scope 5. |
| ***Balancing Security and Functionality*** | The framework emphasizes the need to balance robust security with operational efficiency and innovation. It provides guidance on implementing security controls that protect AI systems without unduly hindering their functionality or performance. This balance is particularly crucial in higher scopes where organizations have more control but also face greater security challenges. |
| ***Lifecycle Security Approach*** | The matrix advocates for a comprehensive security approach that covers the entire lifecycle of AI systems. This includes securing data ingestion, model training, deployment, and ongoing operations. By addressing security at each stage, organizations can build a more resilient and trustworthy AI ecosystem, regardless of their implementation scope. |


<br><br>

###### 6.1.8.1.5. Detail on current framework

The matrix defines five distinct scopes:

***Scope 1: Consumer App***
At Scope 1, organizations utilize publicly available generative AI services through their standard interfaces or APIs, such as general-purpose chatbots or image generators. In this most basic implementation level, users have no visibility into or control over the underlying model or its training data. The organization simply consumes the service as-is, bound by the provider's terms of service and usage restrictions. This approach offers the lowest barrier to entry but also provides minimal customization options and control over security measures. It's typically suited for non-critical use cases where organizational data sensitivity is low and the focus is primarily on managing user interactions and output filtering.

***Scope 2: Enterprise App***
At Scope 2, organizations use enterprise-grade versions of applications that contain AI services that allow for private data handling and enhanced security controls. While still utilizing pre-built models, these implementations include additional layers of protection through managed services, such as enterprise API endpoints with authentication and data handling controls, and typically can include enterprise agreements and legal commitments. Organizations at this scope can integrate the AI service with their existing security infrastructure and maintain better control over data privacy and governance. This approach balances the convenience of managed services with the need for enterprise-grade security, making it suitable for business applications that require protected data handling while still leveraging the efficiency of pre-built models.

***Scope 3: Pre-trained Models***
At Scope 3, organizations create custom applications by leveraging existing foundation models through managed API services, typically when an organization wants to consume a model within an application it is building. This approach enables deeper integration with organizational systems and allows for enhanced functionality through techniques like RAG, which combines the power of foundation models with proprietary data. While the core model remains unchanged, organizations can significantly customize the AI's behavior and responses through sophisticated prompting and context management. This implementation provides greater control over the application layer while maintaining the efficiency of using established foundation models, making it ideal for organizations that need tailored AI solutions but don't require model-level modifications.

***Scope 4: Fine-tuned Models***
At Scope 4, organizations take a significant step beyond basic model usage by fine-tuning existing foundation models with domain-specific data. This approach creates a specialized version of the base model that's optimized for particular use cases and organizational needs. The organization gains control over both the fine-tuning process and the resulting model, enabling more precise and contextually appropriate outputs. This implementation level requires deeper technical expertise and careful management of training data, but offers substantially improved performance for specialized tasks. While building upon established model architectures, this scope provides organizations with the ability to create truly customized AI solutions that align closely with specific industry requirements and professional standards.

***Scope 5: Self-trained models***
At Scope 5, organizations undertake the most comprehensive level of AI development by creating and training models entirely from scratch. This represents complete ownership and control over every aspect of the AI system, from architecture design to model training and deployment. Organizations at this scope have full authority over the entire AI stack, enabling them to develop novel solutions that may not be possible with existing models. This approach requires the highest level of technical expertise and computational resources, but offers unparalleled flexibility and potential for innovation. Such implementations are typically pursued when organizations aim to develop proprietary AI technology that can serve as a competitive advantage or commercial product in itself.

As organizations progress from Scope 1 to Scope 5, they experience an increase in the level of control and customization over their AI solutions. This progression also brings greater security responsibilities and complexities. For each scope that an organization adopts, the matrix can help prioritize different security measures and risk management strategies unique to each scope.

The matrix serves as a valuable tool for organizations in several ways. It enables them to assess their current and planned AI implementations accurately, identifying relevant security disciplines for each scope. This assessment helps in prioritizing security efforts based on the specific risk profile of each implementation. Furthermore, the matrix guides organizations in making informed decisions about how security controls may differ when you are buying AI solutions or building them, allowing them to scale their security measures effectively as their AI implementations evolve. 


###### 6.1.8.1.6. What is missing for defenders of AI systems

The AWS Generative AI Security Scoping Matrix provides deferenders with a framework and mental model that enables them to more quickly assess the risks associated with various AI systems based on unique scopes of each AI system use case, and the security controls necessary to help mitigate and compensate for those risks.  As a result, it provides broad guidance and approaches organizations can take to understand where to focus their efforts, but it does not provide low level implementation details necessary to implement specific security controls.  Organizations will need to leverage this framework, along with others, to help ensure a comprehensive security control strategy.

<br><br>

### 6.2. References

| Framework | Referenced Material |
| --- | --- |
| NIST CSF 2.0 | [NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) |
| NIST RMF | [NIST RMF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf) |
| NIST AI RMF 1.0 | [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) |
| NIST AI RMF 1.0 for Generative AI (GAI) | [NIST AI RMF 1.0 for Generative AI (GAI)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) |
| NIST AI Adversarial Machine Learning (AML) | [NIST AI Adversarial Machine Learning (AML)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf) |
| MITRE ATT&CK | [MITRE ATT&CK](https://attack.mitre.org/) |
| MITRE ATLAS | [MITRE ATLAS](https://atlas.mitre.org/) |
| MITRE CAPEC | [MITRE CAPEC](https://capec.mitre.org/) |
| MITRE D3FEND | [MITRE D3FEND](https://d3fend.mitre.org/) |
| STIX 2.1 | [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.pdf) |
| Zero Trust Maturity Model | [Zero Trust Maturity Model](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf) |
| MIT AI Risk Repository | [MIT AI Risk Repository](https://airisk.mit.edu/) |
| Open Cybersecurity Schema Framework (OCSF) | [OCSF](https://ocsf.io/) |
| OWASP Top 10 for LLM Applications 2025 | [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) |
| AWS Generative AI Security Scoping Matrix | [AWS Generative AI Security Scoping Matrix](https://aws.amazon.com/ai/generative-ai/security/scoping-matrix/) |

### 6.3. Acknowledgements

#### 6.3.1. Workstream Leads Chairs: 

Josiah Hagen ([josiah_hagen@trendmicro.com](mailto:josiah_hagen@trendmicro.com)), [Trend Micro](https://www.trendmicro.com/)<br>
Vinay Bansal ([vibansal@cisco.com](mailto:vibansal@cisco.com)), [Cisco](https://www.cisco.com/)

#### 6.3.2. Editors: 

Josiah Hagen ([josiah_hagen@trendmicro.com](mailto:josiah_hagen@trendmicro.com)), [Trend Micro](https://www.trendmicro.com/)<br>
Vinay Bansal ([vibansal@cisco.com](mailto:vibansal@cisco.com)), [Cisco](https://www.cisco.com/)<br>
J.R. Rao ([jrrao@us.ibm.com](mailto:jrrao@us.ibm.com)),[IBM](https://www.ibm.com/)<br>
Akila Srinivasan ([akila@anthropic.com](mailto:akila@anthropic.com)),[Anthropic](https://www.anthropic.com/)<br>
Omar Santos ([osantos@cisco.com](mailto:osantos@cisco.com)), [Cisco](https://www.cisco.com/)<br>
Irakle Dzneladze ([irakle.dzneladze@ca.ibm.com](mailto:irakle.dzneladze@ca.ibm.com)), [IBM](https://www.ibm.com/)<br>
Matt Saner ([msaner@amazon.com](mailto:msaner@amazon.com)), [Amazon](https://aws.amazon.com/)<br>
Jiyong Jang ([jjang@us.ibm.com](mailto:jjang@us.ibm.com)),[IBM](https://www.ibm.com/)<br>
Jason Garman ([jason@amazon.com](mailto:jason@amazon.com)), [Amazon](https://aws.amazon.com/)<br>
Michael Rash ([rashmichael90@gmail.com](mailto:rashmichael90@gmail.com)), [Dell](https://www.dell.com/)<br><br>
Vladimir Kropotov ([kropotovn@ieee.org](kropotovn@ieee.org)), [Trend Micro](https://www.trendmicro.com/)<br>
Shrey Bagga ([sbagga@cisco.com](mailto:jsbagga@cisco.com)), [Cisco](https://www.cisco.com/)<br>
Marina Zeldin ([marina.zeldin@dell.com](mailto:marina.zeldin@dell.com)), [Dell](https://www.dell.com/)<br>


#### 6.3.3. List of active contributors:

Josiah Hagen ([josiah_hagen@trendmicro.com](mailto:josiah_hagen@trendmicro.com)), [Trend Micro](https://www.trendmicro.com/)<br>
Vinay Bansal ([vibansal@cisco.com](mailto:vibansal@cisco.com)), [Cisco](https://www.cisco.com/)<br>
J.R. Rao ([jrrao@us.ibm.com](mailto:jrrao@us.ibm.com)),[IBM](https://www.ibm.com/)<br>
Akila Srinivasan ([akila@anthropic.com](mailto:akila@anthropic.com)),[Anthropic](https://www.anthropic.com/)<br>
Omar Santos ([osantos@cisco.com](mailto:osantos@cisco.com)), [Cisco](https://www.cisco.com/)<br>
Irakle Dzneladze ([irakle.dzneladze@ca.ibm.com](mailto:irakle.dzneladze@ca.ibm.com)), [IBM](https://www.ibm.com/)<br>
Matt Saner ([msaner@amazon.com](mailto:msaner@amazon.com)), [Amazon](https://aws.amazon.com/)<br>
Jiyong Jang ([jjang@us.ibm.com](mailto:jjang@us.ibm.com)), [IBM](https://www.ibm.com/)<br>
Jason Garman ([jason@amazon.com](mailto:jason@amazon.com)), [Amazon](https://aws.amazon.com/)<br>
Michael Rash ([rashmichael90@gmail.com](mailto:rashmichael90@gmail.com)), [Dell](https://www.dell.com/)<br><br>
Vladimir Kropotov ([kropotovn@ieee.org](kropotovn@ieee.org)), [Trend Micro](https://www.trendmicro.com/)<br>
Shrey Bagga ([sbagga@cisco.com](mailto:jsbagga@cisco.com)), [Cisco](https://www.cisco.com/)<br>
Marina Zeldin ([marina.zeldin@dell.com](mailto:marina.zeldin@dell.com)), [Dell](https://www.dell.com/)<br>

### 6.4 CoSAI Security Focus
CoSAI is an OASIS Open Project, bringing together an open ecosystem of AI and security experts from industry-leading organizations. The project is dedicated to sharing best practices for secure AI deployment and collaborating on AI security research and product development. The scope of CoSAI is specifically focused on the secure building, integration, deployment, and operation of AI systems, with an emphasis on mitigating security risks unique to AI technologies. Other aspects of Trustworthy AI are deemed important but beyond the scope of the project including, ethics, fairness, explainability, bias detection, safety, consumer privacy, misinformation, hallucinations, deep fakes, or content safety concerns like hateful or abusive content, malware, or phishing generation. By concentrating on developing robust measures, best practices, and guidelines to safeguard AI systems against unauthorized access, tampering, or misuse, CoSAI aims to contribute to the responsible development and deployment of resilient, secure AI technologies.

### 6.5. Guidelines on usage of more advanced AI systems (e.g. large language models (LLMs), multi-modal language models. etc) for drafting documents for OASIS CoSAI:

_tl;dr: CoSAI contributions are actions performed by humans, who are responsible for the content of those contributions, based on their signed OASIS iCLA (and eCLA, if applicable). [Each contributor must confirm whether they are entitled to donate that material under the applicable open source license;  OASIS and the CoSAI Project do not separately confirm that.]  Each contributor is responsible for ensuring that all contributions comply with these AI use guidelines, including disclosure of any use of AI in contributions._

* **Selection of AI systems:** CoSAI recommends the use of reputable AI systems (lowering the risk of inadvertently incorporating infringing material).
* **Model constraints:** Currently, CoSAI or OASIS are not required to have a contract or financial agreement for using AI systems from specific vendors. However, CoSAI editors should consider employing varying tools to avoid potential fairness concerns among vendors.
* **IP infringement:** It is the responsibility of the individual who subscribes/prompts and receives a response from an AI system to confirm they have the right to repost and donate the content to OASIS under our rules.
* **Transparency:** CoSAI’s goal will be to maintain transparency throughout the process by documenting substantial use of AI systems whenever possible (e.g., the prompts and the AI system used), and to ensure that all content, regardless of production by human or AI systems, was reviewed and edited by human experts. This helps build trust in the standards development process and ensures accountability.
* **Human-edited content and quality control:** CoSAI mandates human-reviewed or -edited results for any final outputs.  A robust quality control process should be in place, involving careful review of the generated content for accuracy, relevance, and alignment with CoSAI's goals and principles. Human experts should scrutinize the output of AI systems to identify any errors, inconsistencies, or potential biases.
* **Iterative refinement:** The use of AI systems in drafting standards should be seen as an iterative process, with the generated content serving as a starting point for further refinement and improvement by human experts. Multiple rounds of review and editing may be necessary to ensure the final standards meet the required quality and reliability thresholds.


### 6.6. Copyright Notice
Copyright © OASIS Open 2025\. All Rights Reserved. All capitalized terms in the following text have the meanings assigned to them in the OASIS Intellectual Property Rights Policy (the "OASIS IPR Policy"). The full Policy may be found at the OASIS website: \[https://www.oasis-open.org/policies-guidelines/ipr/\]. This document and translations of it may be copied and furnished to others, and derivative works that comment on or otherwise explain it or assist in its implementation may be prepared, copied, published, and distributed, in whole or in part, without restriction of any kind, provided that the above copyright notice and this section are included on all such copies and derivative works. However, this document itself may not be modified in any way, including by removing the copyright notice or references to OASIS, except as needed for the purpose of developing any document or deliverable produced by an OASIS Technical Committee (in which case the rules applicable to copyrights, as set forth in the OASIS IPR Policy, must be followed) or as required to translate it into languages other than English. The limited permissions granted above are perpetual and will not be revoked by OASIS or its successors or assigns. This document and the information contained herein is provided on an "AS IS" basis and OASIS DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY OWNERSHIP RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. OASIS AND ITS MEMBERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THIS DOCUMENT OR ANY PART THEREOF. The name "OASIS" is a trademark of OASIS, the owner and developer of this document, and should be used only to refer to the organization and its official outputs. OASIS welcomes reference to, and implementation and use of, documents, while reserving the right to enforce its marks against misleading uses. Please see [https://www.oasis-open.org/policies-guidelines/trademark/](https://www.oasis-open.org/policies-guidelines/trademark/) for above guidance.

This is a Non-Standards Track Work Product. The patent provisions of the OASIS IPR Policy do not apply.

4 March 2025 Non-Standards Track Copyright © OASIS Open 2025\. All Rights Reserved. This document was last revised or approved by the CoSAI Open Project on the above date. 
