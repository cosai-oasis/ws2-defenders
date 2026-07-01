//! Tier 5 — inline blocking HTTP CONNECT proxy.
//!
//! Clients (Claude Code, Codex, browsers) point HTTP_PROXY /
//! HTTPS_PROXY at AgentDR's loopback port. For each incoming CONNECT
//! the proxy synthesises a "candidate" EventRecord (ai_operation=inference,
//! API Activity 6003, if the host matches a known AI endpoint, else
//! ai_operation=agent_action) and feeds it to the PolicyEngine. If any
//! matching policy returns Action::Block, the proxy responds `403 Forbidden`
//! and emits a Compliance Finding (OCSF 2003) event. Otherwise it tunnels
//! the TCP bytes through and emits the observation event.
//!
//! No TLS MITM is performed: CONNECT carries the hostname in plaintext,
//! which is sufficient for endpoint-allowlist enforcement without
//! shipping a custom CA.
//!
//! ## Enrichment (shared with the reverse proxy)
//!
//! Beyond the original policy/allowlist enforcement, the forward proxy now
//! optionally:
//!   * **Resolves caller provenance** ([`provenance`]) — the local PID,
//!     executable and command line behind each connection — and attributes
//!     the call to a known AI agent via [`identify_agent`].
//!   * **Authenticates** callers ([`auth`]) via a `Proxy-Authorization:
//!     Bearer <key>` / `X-API-Key` header (static keys or HS256 JWTs),
//!     answering `407` when credentials are required but missing/invalid.
//!   * **Rate-limits** ([`rate_limit`]) per caller (auth subject, else
//!     process / peer), answering `429` when a key exceeds its quota.
//!
//! The heavier body-inspecting capabilities (prompt-injection / PII scanning,
//! token-usage tracking) live in the [`reverse`] reverse-proxy component,
//! which sits *in front of local model backends* where request/response
//! bodies are visible (a forward CONNECT tunnel only sees ciphertext).

pub mod auth;
pub mod health;
pub mod monitor;
pub mod provenance;
pub mod rate_limit;
pub mod reverse;

use crate::config::ProxyConfig;
use crate::models::*;
use crate::policy::{Action, PolicyEngine};
use auth::{AuthOutcome, Authenticator};
use rate_limit::KeyedRateLimiter;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct InlineProxy {
    bind: String,
    engine: Arc<PolicyEngine>,
    /// Hostname allow-list (case-insensitive substring). When non-empty
    /// and the destination host doesn't match any entry, the proxy
    /// short-circuits with a deny before even consulting policies.
    allowlist: Vec<String>,
    /// Resolve the calling process for each connection (Linux-only).
    provenance: bool,
    /// Credential validator (observe-only when no keys/JWT configured).
    auth: Arc<Authenticator>,
    /// Per-caller sliding-window limiter (no-op when disabled).
    limiter: Arc<KeyedRateLimiter>,
    tx: mpsc::UnboundedSender<EventRecord>,
}

impl InlineProxy {
    /// Build the proxy from its [`ProxyConfig`]. The policy engine and event
    /// channel are shared with the rest of the agent.
    pub fn from_config(
        cfg: &ProxyConfig,
        engine: Arc<PolicyEngine>,
        tx: mpsc::UnboundedSender<EventRecord>,
    ) -> Self {
        let auth = Arc::new(Authenticator::new(cfg.auth_tokens.clone(), cfg.jwt.clone()));
        let limiter = Arc::new(KeyedRateLimiter::new(&cfg.rate_limits));
        Self {
            bind: cfg.bind.clone(),
            engine,
            allowlist: cfg.allowlist.clone(),
            provenance: cfg.provenance,
            auth,
            limiter,
            tx,
        }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let listener = match TcpListener::bind(&self.bind).await {
            Ok(l) => l,
            Err(e) => { error!("proxy bind {}: {e}", self.bind); return; }
        };
        info!(
            "inline proxy listening on http://{} (policy mode; auth={}, rate_limit={}, provenance={})",
            self.bind,
            self.auth.is_enforcing(),
            self.limiter.enabled(),
            self.provenance,
        );

        let me = Arc::new(self);
        loop {
            tokio::select! {
                accept = listener.accept() => match accept {
                    Ok((sock, addr)) => {
                        let me = me.clone();
                        tokio::spawn(async move { me.handle(sock, addr).await; });
                    }
                    Err(e) => warn!("proxy accept: {e}"),
                },
                _ = shutdown.changed() => break,
            }
        }
        info!("inline proxy shutting down");
    }

    async fn handle(self: Arc<Self>, mut client: TcpStream, peer: SocketAddr) {
        // Read just enough to get the request line + headers.
        let mut buf = vec![0u8; 8192];
        let n = match client.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        let head = String::from_utf8_lossy(&buf[..n]).to_string();

        let Some((method, target)) = parse_method_target(&head) else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return;
        };

        // Resolve who is calling us (best-effort) so every event for this
        // connection carries actor + agent attribution.
        let prov = if self.provenance {
            Some(provenance::resolve(peer))
        } else {
            None
        };
        let agent = prov
            .as_ref()
            .and_then(|p| identify_agent(&p.haystack()));

        // Resolve the destination host[:port]. CONNECT carries it in the
        // target; plain HTTP requests carry an absolute URI we need to
        // tease apart.
        let (host, port) = match method.as_str() {
            "CONNECT" => split_host_port(&target, 443),
            _ => match host_port_from_url(&target) {
                Some(hp) => hp,
                None => match host_from_headers(&head) {
                    Some(h) => split_host_port(&h, 80),
                    None => {
                        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                        return;
                    }
                },
            },
        };

        // ── 1) Authentication ──
        // Forward proxies present credentials via Proxy-Authorization; we
        // also honour X-API-Key for parity with the reverse proxy.
        let bearer = bearer_token(&head, "proxy-authorization");
        let api_key = header_value(&head, "x-api-key");
        let subject = match self.auth.authenticate(bearer.as_deref(), api_key.as_deref()) {
            AuthOutcome::Allowed { subject, .. } => subject,
            AuthOutcome::Denied { reason } => {
                let _ = client
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Bearer realm=\"AgentDR\"\r\n\
                          Proxy-Agent: AgentDR\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
                let mut ev = self.probe_event(&method, &host, port);
                ev.event_type = "proxy_auth_denied".into();
                ev.set_op(AiOperation::Identity, ACTIVITY_BLOCK);
                ev.activity_id = Some(ACTIVITY_BLOCK);
                ev.status_id = Some(STATUS_BLOCKED);
                ev.risk_level = "high".into();
                ev.severity_id = Some(4);
                ev.message = Some(format!("proxy: auth denied ({reason})"));
                ev.source = Some("proxy".into());
                Self::enrich_event(&mut ev, prov.as_ref(), agent.as_ref());
                let _ = self.tx.send(ev);
                return;
            }
        };

        // ── 2) Rate limiting ──
        // Key by auth subject when authenticated, else by the calling
        // process (PID) or peer address.
        let rl_key = if subject != "anonymous" {
            subject.clone()
        } else {
            prov.as_ref()
                .and_then(|p| p.pid.map(|pid| format!("pid:{pid}")))
                .unwrap_or_else(|| format!("peer:{peer}"))
        };
        if !self.limiter.check(&rl_key) {
            let _ = client
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nProxy-Agent: AgentDR\r\n\
                      Retry-After: 1\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            let mut ev = self.probe_event(&method, &host, port);
            ev.event_type = "proxy_rate_limited".into();
            ev.set_op(AiOperation::GuardrailEvent, ACTIVITY_BLOCK);
            ev.activity_id = Some(ACTIVITY_BLOCK);
            ev.status_id = Some(STATUS_BLOCKED);
            ev.risk_level = "medium".into();
            ev.severity_id = Some(3);
            ev.message = Some(format!(
                "proxy: rate limit exceeded for {} ({}/min)",
                rl_key,
                self.limiter.per_minute()
            ));
            ev.source = Some("proxy".into());
            Self::enrich_event(&mut ev, prov.as_ref(), agent.as_ref());
            let _ = self.tx.send(ev);
            return;
        }

        // ── 3) Policy + allowlist ──
        let probe = self.probe_event(&method, &host, port);
        let decision = self.engine.evaluate(&probe);
        let denied_by_allowlist = !self.allowlist.is_empty()
            && !self.allowlist.iter().any(|a| host.to_lowercase().contains(&a.to_lowercase()));

        let blocked = decision.action == Action::Block || denied_by_allowlist;

        // Emit any policy events (enriched with caller provenance).
        for mut ev in decision.events {
            Self::enrich_event(&mut ev, prov.as_ref(), agent.as_ref());
            let _ = self.tx.send(ev);
        }

        if blocked {
            // 403 + emit a Compliance Finding (OCSF 2003) record if the
            // allowlist (not policy) was the reason, so the trace is complete.
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nProxy-Agent: AgentDR\r\nContent-Length: 0\r\n\r\n").await;
            if denied_by_allowlist {
                let mut ev = self.probe_event(&method, &host, port);
                ev.event_type = "proxy_block".into();
                ev.set_op(AiOperation::ComplianceViolation, ACTIVITY_BLOCK);
                ev.activity_id = Some(ACTIVITY_BLOCK);
                ev.status_id = Some(STATUS_BLOCKED);
                ev.risk_level = "high".into();
                ev.severity_id = Some(4);
                ev.message = Some(format!("proxy: denied {} {}:{} (host not in allowlist)", method, host, port));
                ev.source = Some("proxy".into());
                Self::enrich_event(&mut ev, prov.as_ref(), agent.as_ref());
                let _ = self.tx.send(ev);
            }
            return;
        }

        // Allow path: also emit an observation so SIEM sees who talked to whom.
        let mut obs = self.probe_event(&method, &host, port);
        obs.event_type = "proxy_allow".into();
        obs.message = Some(format!("proxy: allowed {} {}:{}", method, host, port));
        obs.source = Some("proxy".into());
        Self::enrich_event(&mut obs, prov.as_ref(), agent.as_ref());
        let _ = self.tx.send(obs);

        // Now actually proxy.
        if method == "CONNECT" {
            self.tunnel_connect(client, &host, port).await;
        } else {
            self.tunnel_http(client, head.as_bytes(), &host, port).await;
        }
    }

    /// Attach caller provenance (`actor`) and AI-agent attribution
    /// (`agent_name` / `agent_framework` / `agent_detected`) to an event.
    /// Shared by the reverse proxy via [`reverse`].
    pub(crate) fn enrich_event(
        ev: &mut EventRecord,
        prov: Option<&provenance::Provenance>,
        agent: Option<&AgentSignature>,
    ) {
        if let Some(p) = prov {
            ev.actor = Some(p.to_actor());
        }
        if let Some(a) = agent {
            ev.agent_detected = Some(a.name.clone());
            ev.agent_name = Some(a.name.clone());
            ev.agent_framework = Some(a.framework.clone());
            // AITF 0.2 ai_agent object — the caller PID identifies the running
            // instance; the uid is derived from the attributed agent identity.
            let instance = prov.and_then(|p| p.pid).map(|pid| format!("pid:{pid}"));
            ev.build_ai_agent(None, instance.as_deref());
        }
    }

    fn probe_event(&self, method: &str, host: &str, port: u16) -> EventRecord {
        let ai = classify_ai_endpoint(host);
        let messaging = classify_messaging_endpoint(host);
        let op = if ai.is_some() {
            AiOperation::Inference
        } else if messaging.is_some() {
            AiOperation::PermissionEscalation
        } else {
            AiOperation::AgentAction
        };
        let risk = if ai.is_some() { "medium" } else if messaging.is_some() { "high" } else { "low" };

        let mut ev = EventRecord::new("proxy_request", json!({
            "method": method,
            "host":   host,
            "port":   port,
            "ai_provider": ai.as_ref().map(|p| &p.provider),
            "messaging":   messaging,
        }), risk);
        ev.set_op(op, ACTIVITY_EXECUTE);
        ev.activity_id = Some(ACTIVITY_EXECUTE);
        ev.status_id = Some(STATUS_SUCCESS);
        if let Some(a) = ai {
            ev.provider = Some(a.provider);
            ev.model    = Some(a.model);
        }
        ev
    }

    async fn tunnel_connect(self: Arc<Self>, mut client: TcpStream, host: &str, port: u16) {
        let upstream = match TcpStream::connect((host, port)).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").as_bytes()).await;
                debug!("proxy upstream connect {}:{}: {e}", host, port);
                return;
            }
        };
        if client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: AgentDR\r\n\r\n").await.is_err() {
            return;
        }
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        let a = tokio::io::copy(&mut cr, &mut uw);
        let b = tokio::io::copy(&mut ur, &mut cw);
        let _ = tokio::join!(a, b);
    }

    async fn tunnel_http(self: Arc<Self>, mut client: TcpStream, initial: &[u8], host: &str, port: u16) {
        let mut upstream = match TcpStream::connect((host, port)).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                debug!("proxy upstream connect {}:{}: {e}", host, port);
                return;
            }
        };
        if upstream.write_all(initial).await.is_err() { return; }
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        let a = tokio::io::copy(&mut cr, &mut uw);
        let b = tokio::io::copy(&mut ur, &mut cw);
        let _ = tokio::join!(a, b);
    }
}

fn parse_method_target(head: &str) -> Option<(String, String)> {
    let first = head.lines().next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    Some((method, target))
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (s.to_string(), default_port)
}

fn host_port_from_url(target: &str) -> Option<(String, u16)> {
    // Strip scheme://, take everything up to the first '/'
    let rest = target.split_once("://").map(|x| x.1).unwrap_or(target);
    let authority = rest.split_once('/').map(|x| x.0).unwrap_or(rest);
    if authority.is_empty() { return None; }
    let default = if target.starts_with("https://") { 443 } else { 80 };
    Some(split_host_port(authority, default))
}

fn host_from_headers(head: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Case-insensitive lookup of a single header value from the raw head.
fn header_value(head: &str, name: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        if line.is_empty() { break; } // end of headers
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Extract the token from a `Bearer <token>` header value (header named
/// `name`, e.g. `proxy-authorization`). Falls back to the raw value when no
/// scheme prefix is present.
fn bearer_token(head: &str, name: &str) -> Option<String> {
    let raw = header_value(head, name)?;
    let trimmed = raw.trim();
    if let Some(rest) = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
    {
        Some(rest.trim().to_string())
    } else {
        Some(trimmed.to_string())
    }
}
