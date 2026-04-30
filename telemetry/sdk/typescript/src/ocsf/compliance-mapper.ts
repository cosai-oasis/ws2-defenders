/**
 * AITF Compliance Mapper.
 *
 * Maps AI events to eight regulatory framework controls.
 * Based on the compliance mapper from the AITelemetry project.
 */

import { randomUUID } from "crypto";
import { AIBaseEvent, ComplianceMetadata } from "./schema";

/** Full compliance mappings (reused from AITelemetry project). */
export const FRAMEWORK_MAPPINGS: Record<
  string,
  Record<string, Record<string, unknown>>
> = {
  nist_ai_rmf: {
    model_inference: {
      controls: ["MAP-1.1", "MEASURE-2.5"],
      function: "MAP",
    },
    agent_activity: {
      controls: ["GOVERN-1.2", "MANAGE-3.1"],
      function: "GOVERN",
    },
    tool_execution: {
      controls: ["MAP-3.5", "MANAGE-4.2"],
      function: "MANAGE",
    },
    data_retrieval: {
      controls: ["MAP-1.5", "MEASURE-2.7"],
      function: "MAP",
    },
    security_finding: {
      controls: ["MANAGE-2.4", "MANAGE-4.1"],
      function: "MANAGE",
    },
    supply_chain: {
      controls: ["MAP-5.2", "GOVERN-6.1"],
      function: "GOVERN",
    },
    governance: {
      controls: ["GOVERN-1.1", "MANAGE-1.3"],
      function: "GOVERN",
    },
    identity: {
      controls: ["GOVERN-1.5", "MANAGE-2.1"],
      function: "GOVERN",
    },
  },
  mitre_atlas: {
    model_inference: {
      techniques: ["AML.T0040"],
      tactic: "ML Attack Staging",
    },
    agent_activity: {
      techniques: ["AML.T0048"],
      tactic: "ML Attack Staging",
    },
    tool_execution: {
      techniques: ["AML.T0043"],
      tactic: "ML Attack Staging",
    },
    data_retrieval: {
      techniques: ["AML.T0025"],
      tactic: "Exfiltration",
    },
    security_finding: {
      techniques: ["AML.T0051"],
      tactic: "Initial Access",
    },
    supply_chain: {
      techniques: ["AML.T0010"],
      tactic: "Resource Development",
    },
    identity: {
      techniques: ["AML.T0052"],
      tactic: "Initial Access",
    },
  },
  iso_42001: {
    model_inference: { controls: ["6.1.4", "8.4"], clause: "Operation" },
    agent_activity: {
      controls: ["8.2", "A.6.2.5"],
      clause: "Operation",
    },
    tool_execution: { controls: ["A.6.2.7"], clause: "Annex A" },
    data_retrieval: { controls: ["A.7.4"], clause: "Annex A" },
    security_finding: {
      controls: ["6.1.2", "A.6.2.4"],
      clause: "Planning",
    },
    supply_chain: { controls: ["A.6.2.3"], clause: "Annex A" },
    governance: { controls: ["5.1", "9.1"], clause: "Leadership" },
    identity: { controls: ["A.6.2.6"], clause: "Annex A" },
  },
  eu_ai_act: {
    model_inference: {
      articles: ["Article 13", "Article 15"],
      risk_level: "high",
    },
    agent_activity: {
      articles: ["Article 14", "Article 52"],
      risk_level: "high",
    },
    tool_execution: { articles: ["Article 9"], risk_level: "high" },
    data_retrieval: { articles: ["Article 10"], risk_level: "high" },
    security_finding: {
      articles: ["Article 9", "Article 62"],
      risk_level: "high",
    },
    supply_chain: {
      articles: ["Article 15", "Article 28"],
      risk_level: "high",
    },
    governance: {
      articles: ["Article 9", "Article 61"],
      risk_level: "high",
    },
    identity: { articles: ["Article 9"], risk_level: "high" },
  },
  soc2: {
    model_inference: {
      controls: ["CC6.1"],
      criteria: "Common Criteria",
    },
    agent_activity: {
      controls: ["CC7.2"],
      criteria: "Common Criteria",
    },
    tool_execution: {
      controls: ["CC6.3"],
      criteria: "Common Criteria",
    },
    data_retrieval: {
      controls: ["CC6.1"],
      criteria: "Common Criteria",
    },
    security_finding: {
      controls: ["CC7.2", "CC7.3"],
      criteria: "Common Criteria",
    },
    supply_chain: {
      controls: ["CC9.2"],
      criteria: "Common Criteria",
    },
    governance: {
      controls: ["CC1.2"],
      criteria: "Common Criteria",
    },
    identity: {
      controls: ["CC6.1", "CC6.2"],
      criteria: "Common Criteria",
    },
  },
  gdpr: {
    model_inference: {
      articles: ["Article 5", "Article 22"],
      lawful_basis: "legitimate_interest",
    },
    agent_activity: {
      articles: ["Article 22"],
      lawful_basis: "legitimate_interest",
    },
    tool_execution: {
      articles: ["Article 25"],
      lawful_basis: "legitimate_interest",
    },
    data_retrieval: {
      articles: ["Article 5", "Article 6"],
      lawful_basis: "legitimate_interest",
    },
    security_finding: {
      articles: ["Article 32", "Article 33"],
      lawful_basis: "legal_obligation",
    },
    supply_chain: {
      articles: ["Article 28"],
      lawful_basis: "contractual",
    },
    governance: {
      articles: ["Article 5"],
      lawful_basis: "legal_obligation",
    },
    identity: {
      articles: ["Article 32"],
      lawful_basis: "legal_obligation",
    },
  },
  ccpa: {
    model_inference: {
      sections: ["1798.100"],
      category: "personal_information",
    },
    data_retrieval: {
      sections: ["1798.100"],
      category: "personal_information",
    },
    security_finding: { sections: ["1798.150"], category: "breach" },
    governance: { sections: ["1798.185"], category: "rulemaking" },
    identity: {
      sections: ["1798.140"],
      category: "personal_information",
    },
  },
  csa_aicm: {
    model_inference: {
      controls: [
        "MDS-01", "MDS-02", "MDS-03", "MDS-04", "MDS-05", "MDS-06",
        "MDS-07", "MDS-08", "MDS-09", "MDS-10", "MDS-11", "MDS-13",
        "AIS-03", "AIS-04", "AIS-05", "AIS-06", "AIS-07", "AIS-08",
        "AIS-09", "AIS-12", "AIS-14", "AIS-15", "LOG-07", "LOG-08",
        "LOG-13", "LOG-14", "LOG-15", "GRC-13", "GRC-14", "GRC-15",
        "TVM-11", "DSP-07",
      ],
      domain: "Model Security",
    },
    agent_activity: {
      controls: [
        "AIS-02", "AIS-11", "AIS-13", "IAM-04", "IAM-05", "IAM-16",
        "IAM-19", "GRC-09", "GRC-10", "GRC-15", "LOG-05", "LOG-11",
        "MDS-10",
      ],
      domain: "Application & Interface Security",
    },
    tool_execution: {
      controls: [
        "AIS-01", "AIS-04", "AIS-08", "AIS-09", "AIS-10", "AIS-13",
        "IAM-05", "IAM-16", "LOG-05", "LOG-11", "TVM-05", "TVM-11",
      ],
      domain: "Application & Interface Security",
    },
    data_retrieval: {
      controls: [
        "DSP-01", "DSP-02", "DSP-03", "DSP-04", "DSP-05", "DSP-06",
        "DSP-07", "DSP-08", "DSP-09", "DSP-10", "DSP-11", "DSP-12",
        "DSP-13", "DSP-14", "DSP-15", "DSP-16", "DSP-17", "DSP-18",
        "DSP-19", "DSP-20", "DSP-21", "DSP-22", "DSP-23", "DSP-24",
        "CEK-03", "LOG-07", "LOG-10",
      ],
      domain: "Data Security & Privacy",
    },
    security_finding: {
      controls: [
        "SEF-01", "SEF-02", "SEF-03", "SEF-04", "SEF-05", "SEF-06",
        "SEF-07", "SEF-08", "SEF-09", "TVM-01", "TVM-02", "TVM-03",
        "TVM-04", "TVM-06", "TVM-07", "TVM-08", "TVM-09", "TVM-10",
        "TVM-11", "TVM-12", "TVM-13", "LOG-02", "LOG-03", "LOG-04",
        "LOG-12", "MDS-06", "MDS-07",
      ],
      domain: "Security Incident Management",
    },
    supply_chain: {
      controls: [
        "STA-01", "STA-02", "STA-03", "STA-04", "STA-05", "STA-06",
        "STA-07", "STA-08", "STA-09", "STA-10", "STA-11", "STA-12",
        "STA-13", "STA-14", "STA-15", "STA-16", "CCC-01", "CCC-02",
        "CCC-03", "CCC-04", "CCC-05", "CCC-06", "CCC-07", "CCC-08",
        "CCC-09", "MDS-08", "MDS-09", "MDS-12", "MDS-13",
        "DCS-01", "DCS-02", "DCS-03", "DCS-04", "DCS-05", "DCS-06",
        "DCS-07", "DCS-08", "DCS-09", "DCS-10", "DCS-11", "DCS-12",
        "DCS-13", "DCS-14", "DCS-15",
        "IPY-01", "IPY-02", "IPY-03", "IPY-04",
        "I&S-01", "I&S-02", "I&S-03", "I&S-04", "I&S-05",
        "I&S-06", "I&S-07", "I&S-08", "I&S-09",
      ],
      domain: "Supply Chain Management",
    },
    governance: {
      controls: [
        "GRC-01", "GRC-02", "GRC-03", "GRC-04", "GRC-05", "GRC-06",
        "GRC-07", "GRC-08", "GRC-09", "GRC-10", "GRC-11", "GRC-12",
        "GRC-13", "GRC-14", "GRC-15", "A&A-01", "A&A-02", "A&A-03",
        "A&A-04", "A&A-05", "A&A-06", "BCR-01", "BCR-02", "BCR-03",
        "BCR-04", "BCR-05", "BCR-06", "BCR-07", "BCR-08", "BCR-09",
        "BCR-10", "BCR-11", "HRS-01", "HRS-02", "HRS-03", "HRS-04",
        "HRS-05", "HRS-06", "HRS-07", "HRS-08", "HRS-09", "HRS-10",
        "HRS-11", "HRS-12", "HRS-13", "HRS-14", "HRS-15",
        "LOG-01", "LOG-06", "DSP-01",
      ],
      domain: "Governance, Risk & Compliance",
    },
    identity: {
      controls: [
        "IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06",
        "IAM-07", "IAM-08", "IAM-09", "IAM-10", "IAM-11", "IAM-12",
        "IAM-13", "IAM-14", "IAM-15", "IAM-16", "IAM-17", "IAM-18",
        "IAM-19", "CEK-01", "CEK-02", "CEK-03", "CEK-04", "CEK-05",
        "CEK-06", "CEK-07", "CEK-08", "CEK-09", "CEK-10", "CEK-11",
        "CEK-12", "CEK-13", "CEK-14", "CEK-15", "CEK-16", "CEK-17",
        "CEK-18", "CEK-19", "CEK-20", "CEK-21", "LOG-04", "LOG-09",
        "UEM-01", "UEM-02", "UEM-03", "UEM-04", "UEM-05", "UEM-06",
        "UEM-07", "UEM-08", "UEM-09", "UEM-10", "UEM-11", "UEM-12",
        "UEM-13", "UEM-14",
      ],
      domain: "Identity & Access Management",
    },
  },
};

/**
 * Maps AI events to compliance framework controls.
 *
 * Usage:
 *   const mapper = new ComplianceMapper({ frameworks: ["nist_ai_rmf", "eu_ai_act"] });
 *   const compliance = mapper.mapEvent("model_inference");
 */
export class ComplianceMapper {
  private readonly _frameworks: string[];

  constructor(options: { frameworks?: string[] } = {}) {
    const allFrameworks = Object.keys(FRAMEWORK_MAPPINGS);
    this._frameworks = options.frameworks ?? allFrameworks;
  }

  /**
   * Map an event type to compliance frameworks.
   *
   * @param eventType - One of 'model_inference', 'agent_activity',
   *   'tool_execution', 'data_retrieval', 'security_finding',
   *   'supply_chain', 'governance', 'identity'.
   * @returns ComplianceMetadata with active framework mappings.
   */
  mapEvent(eventType: string): ComplianceMetadata {
    const result: Record<string, unknown> = {};

    for (const framework of this._frameworks) {
      const frameworkMap = FRAMEWORK_MAPPINGS[framework];
      if (!frameworkMap) continue;
      const eventMap = frameworkMap[eventType];
      if (eventMap) {
        result[framework] = eventMap;
      }
    }

    return result as ComplianceMetadata;
  }

  /** Add compliance metadata to an OCSF event. */
  enrichEvent(event: AIBaseEvent, eventType: string): AIBaseEvent {
    event.compliance = this.mapEvent(eventType);
    return event;
  }

  /** Generate a coverage matrix showing which controls apply per event type. */
  getCoverageMatrix(): Record<string, Record<string, string[]>> {
    const eventTypes = [
      "model_inference",
      "agent_activity",
      "tool_execution",
      "data_retrieval",
      "security_finding",
      "supply_chain",
      "governance",
      "identity",
    ];

    const matrix: Record<string, Record<string, string[]>> = {};

    for (const eventType of eventTypes) {
      matrix[eventType] = {};
      for (const framework of this._frameworks) {
        const frameworkMap = FRAMEWORK_MAPPINGS[framework];
        if (!frameworkMap) continue;
        const eventMap = frameworkMap[eventType];
        if (!eventMap) continue;

        for (const key of [
          "controls",
          "techniques",
          "articles",
          "sections",
        ]) {
          if (key in eventMap) {
            matrix[eventType][framework] = eventMap[key] as string[];
            break;
          }
        }
      }
    }

    return matrix;
  }

  /**
   * Generate an audit record from compliance mappings.
   */
  generateAuditRecord(
    eventType: string,
    options: {
      actor?: string;
      model?: string;
      riskScore?: number;
    } = {}
  ): Record<string, unknown> {
    const compliance = this.mapEvent(eventType);
    const allControls: string[] = [];
    const complianceDetails: Record<string, string[]> = {};

    for (const framework of this._frameworks) {
      const frameworkData = (compliance as Record<string, unknown>)[
        framework
      ] as Record<string, unknown> | undefined;
      if (!frameworkData) continue;

      for (const key of [
        "controls",
        "techniques",
        "articles",
        "sections",
      ]) {
        if (key in frameworkData) {
          const controls = frameworkData[key] as string[];
          complianceDetails[framework] = controls;
          allControls.push(...controls);
          break;
        }
      }
    }

    return {
      audit_id: `aud-${randomUUID().replace(/-/g, "").slice(0, 12)}`,
      timestamp: new Date().toISOString(),
      event_type: eventType,
      frameworks_mapped: Object.keys(complianceDetails).length,
      controls_mapped: allControls.length,
      violations_detected: 0,
      risk_score: options.riskScore ?? 0.0,
      actor: options.actor ?? null,
      model: options.model ?? null,
      compliance_details: complianceDetails,
    };
  }
}
