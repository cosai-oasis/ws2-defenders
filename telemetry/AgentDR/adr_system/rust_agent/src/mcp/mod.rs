//! Model Context Protocol (MCP) support (Tier 1).
//!
//! * `inventory` enumerates MCP server configurations the user has
//!   declared across all common AI runtimes — turning a piece of state
//!   that several comparable OSS telemetry projects explicitly omit
//!   into an AITF OCSF Class-Reuse stream.
//! * `intercept` stdio-proxies a real MCP server: AgentDR sits between the
//!   AI runtime and the server, JSON-RPC frames are decoded on both
//!   directions, and one EventRecord is emitted per method invocation.

pub mod intercept;
pub mod inventory;
