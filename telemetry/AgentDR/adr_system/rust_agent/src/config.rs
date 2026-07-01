//! Configuration loading and defaults.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_watch_dirs")]
    pub watch_directories: Vec<String>,

    #[serde(default)]
    pub file_monitor: FileMonitorConfig,

    #[serde(default)]
    pub network_monitor: NetworkMonitorConfig,

    #[serde(default)]
    pub process_monitor: ProcessMonitorConfig,

    #[serde(default)]
    pub detection: DetectionConfig,

    #[serde(default)]
    pub storage: StorageConfig,

    #[serde(default)]
    pub server_push: ServerPushConfig,

    #[serde(default)]
    pub runtime: RuntimeConfig,

    #[serde(default)]
    pub otlp: OtlpConfig,

    #[serde(default)]
    pub mcp: McpConfig,

    #[serde(default)]
    pub exporters: ExportersConfig,

    #[serde(default)]
    pub policy: PolicyConfig,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub kernel: KernelConfig,

    #[serde(default)]
    pub browser: BrowserConfig,

    #[serde(default)]
    pub watchdog: WatchdogConfig,

    #[serde(default)]
    pub discovery: DiscoveryConfig,

    #[serde(default)]
    pub openshell: OpenShellConfig,

    #[serde(default)]
    pub llm_guard: LlmGuardConfig,
}

// ── Tier 8 — auto-discovery of AI agents on the host ──────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Master switch. When false, no discovery scans run and no
    /// auto-install happens; operators must use `hooks install <agent>`
    /// explicitly.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Decision mode applied to discovered agents that don't have a
    /// recorded decision yet:
    ///   - `off`         — discover & report only; never install
    ///   - `interactive` — prompt the local user (TTY required)
    ///   - `policy`      — apply `discovery.yaml` (default)
    ///   - `automatic`   — install every supported agent that's found
    #[serde(default = "default_discovery_mode")]
    pub mode: String,
    /// Run discovery + apply at agent startup.
    #[serde(default = "default_true")]
    pub scan_on_start: bool,
    /// Periodic re-scan interval in hours (0 = disabled). Default 24h.
    #[serde(default = "default_discovery_interval")]
    pub scan_interval_hours: u64,
    /// Where to persist remembered user decisions. Default
    /// `<root>/runtime/discovery-state.json`.
    #[serde(default = "default_discovery_state")]
    pub state_file: String,
    /// Path to an override discovery-policy YAML. Empty = use the
    /// shipped `cosai-community/policies/discovery.yaml`.
    #[serde(default)]
    pub policy_path: String,
}
impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: default_discovery_mode(),
            scan_on_start: true,
            scan_interval_hours: default_discovery_interval(),
            state_file: default_discovery_state(),
            policy_path: String::new(),
        }
    }
}
fn default_discovery_mode() -> String { "policy".into() }
fn default_discovery_interval() -> u64 { 24 }
fn default_discovery_state() -> String { "runtime/discovery-state.json".into() }

// ── Tier 7 — self-protection / watchdog ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogConfig {
    /// Periodically re-hash AgentDR's own configs, the rule pack, the
    /// binary, and every installed runtime-hook config; emit Compliance
    /// Finding (OCSF 2003) events when an AgentDR marker is removed or a tracked file
    /// disappears (i.e. when a monitored agent attempts to escape
    /// surveillance).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Polling interval (minimum 5s). Default 30s.
    #[serde(default = "default_watchdog_interval")]
    pub interval_seconds: u64,
    /// When true, re-install the AgentDR hook automatically if its
    /// marker disappears from a tracked config (recommended for
    /// production fleets; off for dev/test where operators may want to
    /// remove a hook by hand).
    #[serde(default)]
    pub self_heal: bool,
}
impl Default for WatchdogConfig {
    fn default() -> Self {
        Self { enabled: true, interval_seconds: default_watchdog_interval(), self_heal: false }
    }
}
fn default_watchdog_interval() -> u64 { 30 }

// ── Tier 5 policy + inline proxy ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Load and evaluate policies against each event.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional override path. When empty, the agent searches
    /// `<exe>/../cosai-community/policies/policies.yaml`, then
    /// `cosai-community/policies/policies.yaml`, then `/etc/agentdr/policies.yaml`.
    #[serde(default)]
    pub path: String,
}
impl Default for PolicyConfig {
    fn default() -> Self { Self { enabled: true, path: String::new() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Run the inline blocking HTTP CONNECT proxy.
    #[serde(default)]
    pub enabled: bool,
    /// Bind address, e.g. 127.0.0.1:8080.
    #[serde(default = "default_proxy_bind")]
    pub bind: String,
    /// Optional hostname allow-list (substring match, case-insensitive).
    /// When empty, only the PolicyEngine decides.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Resolve the local process that opened each proxied connection
    /// (PID / executable / command line) and attribute the call to a known
    /// AI agent via the agent-signature table. Adds an `actor` object and
    /// `agent_name` / `agent_framework` to emitted events. Linux-only
    /// (degrades to a peer-address-only record elsewhere). Costs one
    /// `/proc` scan per new connection — leave off for very high request
    /// volumes.
    #[serde(default = "default_true")]
    pub provenance: bool,
    /// Optional static API keys required in the `Proxy-Authorization:
    /// Bearer <key>` (or `X-API-Key`) header. When empty *and* JWT auth is
    /// off, the proxy does not require credentials (observe-only) so it
    /// stays a drop-in for existing clients.
    #[serde(default)]
    pub auth_tokens: Vec<String>,
    /// Optional HS256 JWT verification for `Proxy-Authorization` bearers.
    #[serde(default)]
    pub jwt: JwtConfig,
    /// Per-caller sliding-window rate limiting (keyed by auth subject, or by
    /// process / peer when anonymous). Off by default for the forward proxy
    /// so it does not throttle browsers that legitimately burst.
    #[serde(default = "default_proxy_rate_limits")]
    pub rate_limits: RateLimitConfig,
}
impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_proxy_bind(),
            allowlist: Vec::new(),
            provenance: true,
            auth_tokens: Vec::new(),
            jwt: JwtConfig::default(),
            rate_limits: default_proxy_rate_limits(),
        }
    }
}
fn default_proxy_bind() -> String { "127.0.0.1:8080".into() }
/// Forward-proxy rate limiting defaults to *disabled* (unlike the reverse
/// proxy) to avoid throttling chatty browser/agent clients out of the box.
fn default_proxy_rate_limits() -> RateLimitConfig {
    RateLimitConfig { enabled: false, ..RateLimitConfig::default() }
}

// ── Tier 6 — kernel + browser telemetry ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfig {
    /// Subscribe to OS-native process / file telemetry. Linux uses the
    /// kernel audit netlink (no extra daemon required); macOS and
    /// Windows currently emit a stub event indicating signed-binary
    /// requirements for EndpointSecurity / ETW providers.
    #[serde(default)]
    pub enabled: bool,
    /// Linux only — netlink multicast group, default 1 (matches auditd).
    #[serde(default = "default_audit_group")]
    pub audit_multicast_group: u32,
}
impl Default for KernelConfig {
    fn default() -> Self { Self { enabled: false, audit_multicast_group: default_audit_group() } }
}
fn default_audit_group() -> u32 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserConfig {
    /// Poll Chrome / Edge DevTools Protocol for browser-use agent activity.
    #[serde(default)]
    pub enabled: bool,
    /// CDP endpoint; default Chrome/Edge "remote debugging" port.
    #[serde(default = "default_cdp_endpoint")]
    pub cdp_endpoint: String,
    /// Polling interval in seconds.
    #[serde(default = "default_cdp_poll")]
    pub poll_seconds: u64,
}
impl Default for BrowserConfig {
    fn default() -> Self { Self { enabled: false, cdp_endpoint: default_cdp_endpoint(), poll_seconds: default_cdp_poll() } }
}
fn default_cdp_endpoint() -> String { "http://127.0.0.1:9222".into() }
fn default_cdp_poll() -> u64 { 5 }

// ── Tier 3 exporters ────────────────────────────────────────────────────
//
// All exporters share a small `BatchConfig` and have a per-backend
// settings block. Each block has `enabled = false` by default; an
// operator enables only the destinations they actually use.

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportersConfig {
    #[serde(default)] pub splunk:     SplunkConfig,
    #[serde(default)] pub datadog:    DatadogConfig,
    #[serde(default)] pub elastic:    ElasticConfig,
    #[serde(default)] pub chronicle:  ChronicleConfig,
    #[serde(default)] pub xsiam:      XsiamConfig,
    #[serde(default)] pub snowflake:  SnowflakeConfig,
    #[serde(default)] pub sentinel:   SentinelConfig,
    #[serde(default)] pub wazuh:      WazuhConfig,
    #[serde(default)] pub syslog:     SyslogConfig,
    #[serde(default)] pub ocsf:       OcsfConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    #[serde(default = "default_batch_size_50")]   pub batch_size: usize,
    #[serde(default = "default_flush_interval_5")] pub flush_interval_seconds: u64,
    #[serde(default = "default_timeout_10")]      pub timeout_seconds: u64,
    #[serde(default = "default_max_retries_3")]   pub max_retries: u32,
}
impl Default for BatchConfig {
    fn default() -> Self {
        Self { batch_size: 50, flush_interval_seconds: 5, timeout_seconds: 10, max_retries: 3 }
    }
}
fn default_batch_size_50() -> usize { 50 }
fn default_flush_interval_5() -> u64 { 5 }
fn default_timeout_10() -> u64 { 10 }
fn default_max_retries_3() -> u32 { 3 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SplunkConfig {
    #[serde(default)] pub enabled: bool,
    /// HEC endpoint, e.g. https://splunk.example.com:8088
    #[serde(default)] pub endpoint: String,
    /// HEC token
    #[serde(default)] pub token: String,
    /// Splunk index (optional — falls back to HEC default)
    #[serde(default)] pub index: String,
    /// HEC sourcetype (default `agentdr:aitf`)
    #[serde(default = "default_splunk_sourcetype")] pub sourcetype: String,
    /// Verify TLS certificate (default true)
    #[serde(default = "default_true")] pub verify_tls: bool,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_splunk_sourcetype() -> String { "agentdr:aitf".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatadogConfig {
    #[serde(default)] pub enabled: bool,
    /// API key
    #[serde(default)] pub api_key: String,
    /// Datadog site, e.g. datadoghq.com | datadoghq.eu | us3.datadoghq.com
    #[serde(default = "default_dd_site")] pub site: String,
    /// `service` tag
    #[serde(default = "default_dd_service")] pub service: String,
    /// Static tag list (env:prod, team:secops, ...)
    #[serde(default)] pub tags: Vec<String>,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_dd_site() -> String { "datadoghq.com".into() }
fn default_dd_service() -> String { "agentdr".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElasticConfig {
    #[serde(default)] pub enabled: bool,
    /// Cluster URL, e.g. https://elastic.example.com:9200
    #[serde(default)] pub endpoint: String,
    /// Index name (we append a yyyy.MM.dd suffix automatically)
    #[serde(default = "default_es_index")] pub index: String,
    /// API key (base64 id:key). Mutually exclusive with basic_auth.
    #[serde(default)] pub api_key: String,
    /// `user:password` for basic auth (if api_key is empty)
    #[serde(default)] pub basic_auth: String,
    /// Verify TLS certificate
    #[serde(default = "default_true")] pub verify_tls: bool,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_es_index() -> String { "agentdr-events".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChronicleConfig {
    #[serde(default)] pub enabled: bool,
    /// Customer GUID (Chronicle tenant)
    #[serde(default)] pub customer_id: String,
    /// Ingestion endpoint (region-specific, e.g.
    /// https://malachiteingestion-pa.googleapis.com)
    #[serde(default = "default_chronicle_endpoint")] pub endpoint: String,
    /// OAuth2 access token (operator-supplied; we don't sign JWTs here)
    #[serde(default)] pub access_token: String,
    /// Chronicle namespace
    #[serde(default = "default_chronicle_namespace")] pub namespace: String,
    /// Log type to apply (forwarded with each event)
    #[serde(default = "default_chronicle_log_type")] pub log_type: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_chronicle_endpoint() -> String { "https://malachiteingestion-pa.googleapis.com".into() }
fn default_chronicle_namespace() -> String { "agentdr".into() }
fn default_chronicle_log_type() -> String { "AGENTDR_AITF".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XsiamConfig {
    #[serde(default)] pub enabled: bool,
    /// HTTP Log Collector URL (Cortex XSIAM "Generic HTTPs Collector" address)
    #[serde(default)] pub endpoint: String,
    /// Auth token (XSIAM "API Key")
    #[serde(default)] pub auth_token: String,
    /// Static `vendor` / `product` tags
    #[serde(default = "default_xsiam_vendor")]  pub vendor:  String,
    #[serde(default = "default_xsiam_product")] pub product: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_xsiam_vendor()  -> String { "CoSAI".into() }
fn default_xsiam_product() -> String { "AgentDR".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnowflakeConfig {
    #[serde(default)] pub enabled: bool,
    /// Snowpipe REST endpoint or Snowpipe Streaming insert URL
    #[serde(default)] pub endpoint: String,
    /// Bearer JWT (operator-supplied — generate with snowsql / Snowflake CLI)
    #[serde(default)] pub bearer_jwt: String,
    /// Optional pipe name (Snowpipe classic). Streaming users leave empty.
    #[serde(default)] pub pipe: String,
    #[serde(default)] pub batch: BatchConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default)] pub enabled: bool,
    /// Log Analytics workspace ID (GUID)
    #[serde(default)] pub workspace_id: String,
    /// Shared key (primary or secondary) — base64
    #[serde(default)] pub shared_key: String,
    /// Custom log type (Sentinel appends "_CL")
    #[serde(default = "default_sentinel_log_type")] pub log_type: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_sentinel_log_type() -> String { "AgentDR_AITF".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WazuhConfig {
    #[serde(default)] pub enabled: bool,
    /// Output file path (must be readable by the wazuh-agent's logcollector,
    /// e.g. `/var/ossec/logs/agentdr.json`).
    #[serde(default = "default_wazuh_path")] pub output_path: String,
    /// Rotate after N bytes
    #[serde(default = "default_wazuh_rotate")] pub rotate_bytes: u64,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_wazuh_path() -> String { "/var/ossec/logs/agentdr.json".into() }
fn default_wazuh_rotate() -> u64 { 50 * 1024 * 1024 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyslogConfig {
    #[serde(default)] pub enabled: bool,
    /// "udp" | "tcp"
    #[serde(default = "default_syslog_proto")] pub protocol: String,
    /// host:port (e.g. siem.example.com:514)
    #[serde(default = "default_syslog_addr")] pub address: String,
    /// RFC 5424 facility (1..23)
    #[serde(default = "default_syslog_facility")] pub facility: u8,
    /// RFC 5424 APP-NAME field
    #[serde(default = "default_syslog_appname")] pub appname: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_syslog_proto() -> String { "udp".into() }
fn default_syslog_addr()  -> String { "127.0.0.1:514".into() }
fn default_syslog_facility() -> u8 { 13 } // log audit
fn default_syslog_appname() -> String { "agentdr".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OcsfConfig {
    #[serde(default)] pub enabled: bool,
    /// HTTP endpoint accepting AITF OCSF Class-Reuse JSON
    #[serde(default)] pub endpoint: String,
    /// Optional bearer token
    #[serde(default)] pub bearer_token: String,
    #[serde(default)] pub batch: BatchConfig,
}

// ── Tier 9 — LLM Guard reverse proxy ──────────────────────────────────
//
// A reverse proxy in front of local model backends (Ollama, LM Studio,
// llama.cpp). It authenticates callers (static API keys + optional HS256
// JWTs), applies per-key sliding-window rate limits, records process
// provenance (which local PID / binary issued the call), inspects prompts
// for injection attempts and PII, tracks token usage, and emits OCSF
// findings for every blocked / suspicious request. Disabled by default.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmGuardConfig {
    /// Master switch. When false the reverse proxy never binds a port.
    #[serde(default)]
    pub enabled: bool,
    /// Address the guard listens on, e.g. `127.0.0.1:8011`. Point your
    /// Ollama / LM Studio clients at this instead of the backend directly.
    #[serde(default = "default_llm_guard_listen")]
    pub listen_address: String,
    /// Upstream model backends. Requests are routed by `route_prefix`
    /// (longest match wins); a backend with an empty prefix is the default.
    #[serde(default = "default_llm_guard_backends")]
    pub backends: Vec<BackendConfig>,
    /// Static API keys accepted in `Authorization: Bearer <key>` or the
    /// `X-API-Key` header. When this list is empty *and* JWT auth is off,
    /// the guard runs in observe-only mode (no request is rejected for
    /// missing credentials) so it can be dropped in front of an existing
    /// setup without breaking it.
    #[serde(default)]
    pub auth_tokens: Vec<String>,
    /// Optional HS256 JWT verification (reuses hmac+sha2).
    #[serde(default)]
    pub jwt: JwtConfig,
    /// Per-key sliding-window rate limiting.
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
    /// Prompt-injection / PII / token-usage monitoring.
    #[serde(default)]
    pub monitoring: MonitoringConfig,
    /// Process-based access control — gate requests on which local process
    /// (or attributed agent) is calling. Disabled by default.
    #[serde(default)]
    pub process_acl: ProcessAclConfig,
    /// Periodic upstream health-check interval in seconds (0 = disabled).
    /// A `GET /healthz` endpoint always reports the latest results on demand.
    #[serde(default = "default_llm_guard_health_interval")]
    pub health_check_interval_seconds: u64,
    /// Maximum accepted request body size (bytes). Default 8 MiB.
    #[serde(default = "default_llm_guard_max_body")]
    pub max_body_bytes: usize,
    /// Upstream request timeout in seconds.
    #[serde(default = "default_llm_guard_timeout")]
    pub upstream_timeout_seconds: u64,
}

impl Default for LlmGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_llm_guard_listen(),
            backends: default_llm_guard_backends(),
            auth_tokens: Vec::new(),
            jwt: JwtConfig::default(),
            rate_limits: RateLimitConfig::default(),
            monitoring: MonitoringConfig::default(),
            process_acl: ProcessAclConfig::default(),
            health_check_interval_seconds: default_llm_guard_health_interval(),
            max_body_bytes: default_llm_guard_max_body(),
            upstream_timeout_seconds: default_llm_guard_timeout(),
        }
    }
}

fn default_llm_guard_listen() -> String { "127.0.0.1:8011".into() }
fn default_llm_guard_health_interval() -> u64 { 30 }
fn default_llm_guard_max_body() -> usize { 8 * 1024 * 1024 }
fn default_llm_guard_timeout() -> u64 { 120 }

fn default_llm_guard_backends() -> Vec<BackendConfig> {
    vec![
        BackendConfig {
            name: "ollama".into(),
            kind: "ollama".into(),
            url: "http://127.0.0.1:11434".into(),
            route_prefix: "/ollama".into(),
            health_path: "/api/tags".into(),
        },
        BackendConfig {
            name: "lmstudio".into(),
            kind: "lmstudio".into(),
            url: "http://127.0.0.1:1234".into(),
            route_prefix: "/lmstudio".into(),
            health_path: "/v1/models".into(),
        },
        BackendConfig {
            name: "llamacpp".into(),
            kind: "llamacpp".into(),
            url: "http://127.0.0.1:8080".into(),
            route_prefix: "/llamacpp".into(),
            health_path: "/health".into(),
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Human-readable backend name (used in events / logs).
    #[serde(default)]
    pub name: String,
    /// Backend family: `ollama` | `lmstudio` | `llamacpp`. Currently used
    /// for labelling and provider attribution on emitted events.
    #[serde(default)]
    pub kind: String,
    /// Upstream base URL, e.g. `http://127.0.0.1:11434`.
    #[serde(default)]
    pub url: String,
    /// Path prefix that routes a request to this backend. The prefix is
    /// stripped before forwarding. An empty prefix matches everything
    /// (default backend). Longest matching prefix wins.
    #[serde(default)]
    pub route_prefix: String,
    /// Relative path pinged by the health checker, e.g. `/api/tags`.
    #[serde(default = "default_backend_health_path")]
    pub health_path: String,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: String::new(),
            url: String::new(),
            route_prefix: String::new(),
            health_path: default_backend_health_path(),
        }
    }
}

fn default_backend_health_path() -> String { "/".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Accept HS256 JWTs in addition to (or instead of) static API keys.
    #[serde(default)]
    pub enabled: bool,
    /// Shared secret used to verify the HMAC-SHA256 signature.
    #[serde(default)]
    pub secret: String,
    /// Optional expected `iss` (issuer) claim. Empty = not checked.
    #[serde(default)]
    pub issuer: String,
    /// Optional expected `aud` (audience) claim. Empty = not checked.
    #[serde(default)]
    pub audience: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self { enabled: false, secret: String::new(), issuer: String::new(), audience: String::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enforce per-key sliding-window rate limits.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Sustained request rate allowed per key, per minute.
    #[serde(default = "default_rl_per_minute")]
    pub requests_per_minute: u32,
    /// Maximum burst (number of requests allowed instantaneously before the
    /// sustained rate applies). Defaults to `requests_per_minute` when 0.
    #[serde(default = "default_rl_burst")]
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { enabled: true, requests_per_minute: default_rl_per_minute(), burst: default_rl_burst() }
    }
}

fn default_rl_per_minute() -> u32 { 120 }
fn default_rl_burst() -> u32 { 30 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Inspect request bodies for prompt content. When false the guard only
    /// authenticates / rate-limits / proxies (no content inspection).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Scan prompts for known prompt-injection / jailbreak patterns.
    #[serde(default = "default_true")]
    pub detect_prompt_injection: bool,
    /// Scan prompts for PII (emails, credit cards, SSNs, API keys, ...).
    #[serde(default = "default_true")]
    pub detect_pii: bool,
    /// Track token usage reported by the upstream response.
    #[serde(default = "default_true")]
    pub track_tokens: bool,
    /// Reject (403) requests where a prompt-injection pattern matches.
    /// When false, the request is still forwarded but a Detection Finding
    /// is emitted (observe / alert-only mode).
    #[serde(default)]
    pub block_on_injection: bool,
    /// Reject (403) requests containing PII. When false, a finding is
    /// emitted but the request proceeds.
    #[serde(default)]
    pub block_on_pii: bool,
    /// Maximum number of prompt characters retained in emitted events
    /// (truncated for privacy / log size). The full prompt is never stored.
    #[serde(default = "default_max_prompt_chars")]
    pub max_prompt_chars: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_prompt_injection: true,
            detect_pii: true,
            track_tokens: true,
            block_on_injection: false,
            block_on_pii: false,
            max_prompt_chars: default_max_prompt_chars(),
        }
    }
}

fn default_max_prompt_chars() -> usize { 256 }

/// Process access-control list for the LLM Guard reverse proxy.
///
/// Because the guard resolves the *local process* behind every request
/// (PID / exe / cmdline, plus an attributed agent name — see
/// [`super::proxy::provenance`]), it can gate access on **which process** is
/// calling, not just on credentials. Patterns are case-insensitive substrings
/// matched against a haystack of `name + exe + cmdline + agent_name`, mirroring
/// the agent-signature matching used elsewhere.
///
/// `deny` always wins over `allow`. When neither matches, `default` decides:
/// `"deny"` = allowlist semantics (only listed callers pass), `"allow"` =
/// denylist semantics (everything except blocked callers passes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAclConfig {
    /// Enforce process-based access control. When false the guard still
    /// records provenance on events but never blocks on it.
    #[serde(default)]
    pub enabled: bool,
    /// Decision when no allow/deny rule matches: `"deny"` (allowlist) or
    /// `"allow"` (denylist).
    #[serde(default = "default_acl_default")]
    pub default: String,
    /// Reject callers whose process could not be resolved to a PID. On
    /// non-Linux hosts provenance is peer-address-only today, so leaving this
    /// false avoids blocking every request there. Linux resolves loopback
    /// callers without elevated privileges.
    #[serde(default)]
    pub block_unresolved: bool,
    /// Allow rules — a caller is permitted if its haystack contains ANY of
    /// these substrings (e.g. `"claude-code"`, `"/usr/local/bin/ollama"`).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Deny rules — a caller is rejected if its haystack contains ANY of
    /// these substrings. Takes precedence over `allow`.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for ProcessAclConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default: default_acl_default(),
            block_unresolved: false,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

fn default_acl_default() -> String { "deny".into() }

// ── OpenShell audit-log ingest (NVIDIA OpenShell Gateway OCSF export) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenShellConfig {
    /// Tail NVIDIA OpenShell's OCSF v1.7.0 JSON audit log and re-emit each
    /// Gateway allow/deny decision as an AITF EventRecord. Disabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// Glob for the OpenShell OCSF JSON export. OpenShell rotates daily to
    /// `/var/log/openshell-ocsf.YYYY-MM-DD.log`; the newest match is tailed.
    #[serde(default = "default_openshell_glob")]
    pub log_glob: String,
    /// How often (seconds) to poll the newest matching log file for new lines.
    #[serde(default = "default_openshell_poll")]
    pub poll_interval_seconds: u64,
}

impl Default for OpenShellConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_glob: default_openshell_glob(),
            poll_interval_seconds: default_openshell_poll(),
        }
    }
}

fn default_openshell_glob() -> String { "/var/log/openshell-ocsf*.log".into() }
fn default_openshell_poll() -> u64 { 5 }

// ── OTLP ingest (Tier 1) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_otlp_bind")]
    pub bind: String,
    /// Maximum accepted request body size (bytes). Default 4 MiB.
    #[serde(default = "default_otlp_max_bytes")]
    pub max_body_bytes: usize,
    /// When true, OTLP log records and span attributes that look like
    /// prompts/messages are dropped before storage.
    #[serde(default = "default_true")]
    pub redact_content: bool,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_otlp_bind(),
            max_body_bytes: default_otlp_max_bytes(),
            redact_content: true,
        }
    }
}

fn default_otlp_bind() -> String { "127.0.0.1:4318".into() }
fn default_otlp_max_bytes() -> usize { 4 * 1024 * 1024 }

// ── MCP (Tier 1) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Scan known MCP config locations at startup and emit ai_operation=mcp_operation (API Activity 6003) events.
    #[serde(default = "default_true")]
    pub inventory_on_start: bool,
    /// Periodically re-scan every N seconds (0 = disabled).
    #[serde(default = "default_mcp_rescan")]
    pub rescan_seconds: u64,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            inventory_on_start: true,
            rescan_seconds: default_mcp_rescan(),
        }
    }
}

fn default_mcp_rescan() -> u64 { 600 }

fn default_watch_dirs() -> Vec<String> {
    Vec::new()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorConfig {
    #[serde(default = "default_true")]
    pub recursive: bool,
    #[serde(default = "default_ignore_patterns")]
    pub ignore_patterns: Vec<String>,
}

impl Default for FileMonitorConfig {
    fn default() -> Self {
        Self {
            recursive: true,
            ignore_patterns: default_ignore_patterns(),
        }
    }
}

fn default_true() -> bool { true }

fn default_ignore_patterns() -> Vec<String> {
    vec!["*.tmp".into(), "*.swp".into(), "*.DS_Store".into(), "*.jsonl".into(), "*.log".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    #[serde(default = "default_poll_seconds")]
    pub poll_seconds: u64,
    #[serde(default = "default_ai_endpoints")]
    pub ai_api_endpoints: Vec<String>,
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            poll_seconds: 3,
            ai_api_endpoints: default_ai_endpoints(),
        }
    }
}

fn default_poll_seconds() -> u64 { 3 }

fn default_ai_endpoints() -> Vec<String> {
    vec![
        "api.openai.com".into(),
        "api.anthropic.com".into(),
        "generativelanguage.googleapis.com".into(),
        "api.mistral.ai".into(),
        "api.deepseek.com".into(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    #[serde(default = "default_process_poll")]
    pub poll_interval_seconds: u64,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self { poll_interval_seconds: 2 }
    }
}

fn default_process_poll() -> u64 { 2 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    #[serde(default)]
    pub rapid_file_modifications: ThresholdRule,
    #[serde(default)]
    pub unusual_api_call_volume: ThresholdRule,
    #[serde(default)]
    pub large_file_deletions: LargeDeletionRule,
    #[serde(default)]
    pub malicious_skill_plugin: ThresholdRule,
    #[serde(default)]
    pub unauthorized_messaging: EnabledRule,
    #[serde(default)]
    pub shell_command_execution: ThresholdRule,
    #[serde(default)]
    pub credential_access: EnabledRule,
    #[serde(default)]
    pub cross_platform_relay: WindowRule,
    #[serde(default)]
    pub unvetted_skill_install: EnabledRule,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            rapid_file_modifications: ThresholdRule { enabled: true, threshold_count: 10, window_seconds: 60 },
            unusual_api_call_volume: ThresholdRule { enabled: true, threshold_count: 40, window_seconds: 60 },
            large_file_deletions: LargeDeletionRule::default(),
            malicious_skill_plugin: ThresholdRule { enabled: true, threshold_count: 5, window_seconds: 300 },
            unauthorized_messaging: EnabledRule { enabled: true },
            shell_command_execution: ThresholdRule { enabled: true, threshold_count: 5, window_seconds: 60 },
            credential_access: EnabledRule { enabled: true },
            cross_platform_relay: WindowRule { enabled: true, window_seconds: 300 },
            unvetted_skill_install: EnabledRule { enabled: true },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdRule {
    pub enabled: bool,
    pub threshold_count: usize,
    pub window_seconds: u64,
}

impl Default for ThresholdRule {
    fn default() -> Self {
        Self { enabled: true, threshold_count: 10, window_seconds: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnabledRule {
    pub enabled: bool,
}

impl Default for EnabledRule {
    fn default() -> Self { Self { enabled: true } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowRule {
    pub enabled: bool,
    pub window_seconds: u64,
}

impl Default for WindowRule {
    fn default() -> Self { Self { enabled: true, window_seconds: 300 } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeDeletionRule {
    pub enabled: bool,
    pub single_file_mb: f64,
    pub window_total_mb: f64,
    pub window_seconds: u64,
}

impl Default for LargeDeletionRule {
    fn default() -> Self {
        Self {
            enabled: true,
            single_file_mb: 25.0,
            window_total_mb: 200.0,
            window_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_events_path")]
    pub events_path: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_backup_count")]
    pub backup_count: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            events_path: default_events_path(),
            max_bytes: 5_000_000,
            backup_count: 7,
        }
    }
}

fn default_events_path() -> String { "logs/events.jsonl".into() }
fn default_max_bytes() -> u64 { 5_000_000 }
fn default_backup_count() -> u32 { 7 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPushConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_seconds: u64,
}

impl Default for ServerPushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            api_key: String::new(),
            timeout_seconds: 5,
            batch_size: 10,
            flush_interval_seconds: 5,
        }
    }
}

fn default_timeout() -> u64 { 5 }
fn default_batch_size() -> usize { 10 }
fn default_flush_interval() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_status_file")]
    pub status_file: String,
    #[serde(default = "default_log_file")]
    pub log_file: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            status_file: default_status_file(),
            log_file: default_log_file(),
        }
    }
}

fn default_status_file() -> String { "runtime/status.json".into() }
fn default_log_file() -> String { "logs/agent_runtime.log".into() }

impl Default for Config {
    fn default() -> Self {
        Self {
            watch_directories: Vec::new(),
            file_monitor: FileMonitorConfig::default(),
            network_monitor: NetworkMonitorConfig::default(),
            process_monitor: ProcessMonitorConfig::default(),
            detection: DetectionConfig::default(),
            storage: StorageConfig::default(),
            server_push: ServerPushConfig::default(),
            runtime: RuntimeConfig::default(),
            otlp: OtlpConfig::default(),
            mcp: McpConfig::default(),
            exporters: ExportersConfig::default(),
            policy: PolicyConfig::default(),
            proxy: ProxyConfig::default(),
            kernel: KernelConfig::default(),
            browser: BrowserConfig::default(),
            watchdog: WatchdogConfig::default(),
            discovery: DiscoveryConfig::default(),
            openshell: OpenShellConfig::default(),
            llm_guard: LlmGuardConfig::default(),
        }
    }
}

impl Config {
    /// Load config from a TOML file, falling back to defaults.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => {
                let cfg = Config::default();
                // Write default config for reference
                if let Ok(s) = toml::to_string_pretty(&cfg) {
                    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
                    let _ = std::fs::write(path, s);
                }
                cfg
            }
        }
    }
}
