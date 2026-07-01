//! OCSF AI event schema, crosswalk, mapper, and the Claude Compliance mapper.
//!
//! AITF follows OCSF's "reuse existing objects and profiles" approach (OCSF PR
//! #1641 / issue #1640): data-plane AI activity is emitted under existing OCSF
//! classes enriched with the `ai_operation` profile, while only the agent /
//! delegation control-plane lifecycle uses the proposed "ai" category (uid 9).

pub mod claude_compliance;
#[cfg(feature = "client")]
pub mod claude_compliance_client;
pub mod compliance;
pub mod crosswalk;
pub mod mapper;
pub mod schema;

pub use claude_compliance::{classify, ClaudeComplianceMapper};
pub use compliance::{ComplianceMapper, ComplianceMetadata, FrameworkControls};
pub use crosswalk::{
    build_agent_message, build_ai_agent, build_delegation, build_delegation_lineage,
    canonical_comm_status, ocsf_agent_activity_crosswalk, ocsf_class_crosswalk,
    ocsf_delegation_activity_crosswalk, OCSFClassCrosswalkEntry,
};
pub use mapper::{AttrValue, OcsfMapper, SpanData};
pub use schema::*;
