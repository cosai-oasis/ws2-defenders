//! Authentication for the LLM Guard reverse proxy.
//!
//! Two credential types are supported:
//!   * **Static API keys** — matched in constant time against the
//!     configured `auth_tokens` list. Presented via `Authorization: Bearer
//!     <key>` or the `X-API-Key` header.
//!   * **HS256 JWTs** — verified locally with the shared secret. We
//!     implement the minimal verification path (split, base64url-decode,
//!     recompute HMAC-SHA256, constant-time compare, then validate `exp` /
//!     `nbf` / optional `iss` / `aud`) on top of the crate's existing
//!     `hmac` + `sha2` + `base64` deps, avoiding a heavyweight JWT crate.

use crate::config::JwtConfig;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Outcome of an authentication attempt.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// Credentials were valid (or auth is disabled). `subject` identifies
    /// the caller — the JWT `sub`, a redacted API-key fingerprint, or
    /// `"anonymous"` in observe-only mode. `method` is `api_key` | `jwt` |
    /// `none`.
    Allowed { subject: String, method: &'static str },
    /// Credentials were missing or invalid. `reason` is safe to log.
    Denied { reason: String },
}

/// Authenticator built from the guard's config. Cheap to clone-share via Arc.
pub struct Authenticator {
    api_keys: Vec<String>,
    jwt: JwtConfig,
    /// When true, requests without credentials are allowed (observe-only).
    allow_anonymous: bool,
}

impl Authenticator {
    pub fn new(api_keys: Vec<String>, jwt: JwtConfig) -> Self {
        // Observe-only when no static keys AND JWT verification is off: lets
        // the guard sit in front of an existing setup without breaking it.
        let allow_anonymous = api_keys.is_empty() && !jwt.enabled;
        Self { api_keys, jwt, allow_anonymous }
    }

    /// True when the authenticator will reject anonymous requests (i.e. at
    /// least one static key or JWT verification is configured).
    pub fn is_enforcing(&self) -> bool {
        !self.allow_anonymous
    }

    /// Validate the credential extracted from request headers.
    pub fn authenticate(&self, bearer: Option<&str>, api_key_header: Option<&str>) -> AuthOutcome {
        // Prefer an explicit X-API-Key, then the Authorization bearer value.
        let presented = api_key_header.or(bearer).map(str::trim).filter(|s| !s.is_empty());

        let Some(cred) = presented else {
            return if self.allow_anonymous {
                AuthOutcome::Allowed { subject: "anonymous".into(), method: "none" }
            } else {
                AuthOutcome::Denied { reason: "missing credentials".into() }
            };
        };

        // 1) static API keys (constant-time compare against each).
        for key in &self.api_keys {
            if constant_time_eq(key.as_bytes(), cred.as_bytes()) {
                return AuthOutcome::Allowed { subject: fingerprint(cred), method: "api_key" };
            }
        }

        // 2) HS256 JWT (only if it looks like a JWT and JWT auth is enabled).
        if self.jwt.enabled && cred.matches('.').count() == 2 {
            return match verify_jwt(cred, &self.jwt) {
                Ok(subject) => AuthOutcome::Allowed { subject, method: "jwt" },
                Err(e) => AuthOutcome::Denied { reason: format!("invalid jwt: {e}") },
            };
        }

        AuthOutcome::Denied { reason: "unrecognized credential".into() }
    }
}

/// Verify an HS256 JWT and return its `sub` (or `"jwt"` when absent).
fn verify_jwt(token: &str, cfg: &JwtConfig) -> Result<String, String> {
    if cfg.secret.is_empty() {
        return Err("no jwt secret configured".into());
    }
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or("missing header")?;
    let payload_b64 = parts.next().ok_or("missing payload")?;
    let sig_b64 = parts.next().ok_or("missing signature")?;

    // Header must declare alg=HS256 (we don't support others — and we reject
    // alg=none to avoid the classic JWT bypass).
    let header: Value = serde_json::from_slice(&b64url_decode(header_b64)?)
        .map_err(|_| "bad header json")?;
    match header.get("alg").and_then(|v| v.as_str()) {
        Some("HS256") => {}
        Some(other) => return Err(format!("unsupported alg {other}")),
        None => return Err("missing alg".into()),
    }

    // Recompute and compare the signature.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut mac = HmacSha256::new_from_slice(cfg.secret.as_bytes())
        .map_err(|_| "bad secret")?;
    mac.update(signing_input.as_bytes());
    let expected = mac.finalize().into_bytes();
    let provided = b64url_decode(sig_b64)?;
    if !constant_time_eq(&expected, &provided) {
        return Err("signature mismatch".into());
    }

    // Validate standard claims.
    let claims: Value = serde_json::from_slice(&b64url_decode(payload_b64)?)
        .map_err(|_| "bad payload json")?;
    let now = chrono::Utc::now().timestamp();
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        if now >= exp { return Err("token expired".into()); }
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
        if now < nbf { return Err("token not yet valid".into()); }
    }
    if !cfg.issuer.is_empty()
        && claims.get("iss").and_then(|v| v.as_str()) != Some(cfg.issuer.as_str())
    {
        return Err("issuer mismatch".into());
    }
    if !cfg.audience.is_empty() && !audience_matches(&claims, &cfg.audience) {
        return Err("audience mismatch".into());
    }

    Ok(claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| "jwt".into()))
}

/// `aud` may be a string or an array of strings per RFC 7519.
fn audience_matches(claims: &Value, want: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(s)) => s == want,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(want)),
        _ => false,
    }
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "base64url decode failed".to_string())
}

/// Length-independent constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Short, non-reversible fingerprint of a presented key for logging/events.
fn fingerprint(cred: &str) -> String {
    use sha2::Digest;
    let digest = Sha256::digest(cred.as_bytes());
    format!("key:{}", hex8(&digest))
}

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JwtConfig;

    fn jwt_off() -> JwtConfig {
        JwtConfig { enabled: false, secret: String::new(), issuer: String::new(), audience: String::new() }
    }

    #[test]
    fn anonymous_allowed_when_unconfigured() {
        let a = Authenticator::new(vec![], jwt_off());
        assert!(!a.is_enforcing());
        matches!(a.authenticate(None, None), AuthOutcome::Allowed { .. });
    }

    #[test]
    fn missing_credentials_denied_when_keys_set() {
        let a = Authenticator::new(vec!["secretkey".into()], jwt_off());
        assert!(a.is_enforcing());
        assert!(matches!(a.authenticate(None, None), AuthOutcome::Denied { .. }));
    }

    #[test]
    fn valid_and_invalid_api_keys() {
        let a = Authenticator::new(vec!["good-key".into()], jwt_off());
        assert!(matches!(
            a.authenticate(Some("good-key"), None),
            AuthOutcome::Allowed { method: "api_key", .. }
        ));
        assert!(matches!(a.authenticate(Some("bad-key"), None), AuthOutcome::Denied { .. }));
        // X-API-Key header is honoured too.
        assert!(matches!(
            a.authenticate(None, Some("good-key")),
            AuthOutcome::Allowed { .. }
        ));
    }

    #[test]
    fn verifies_hs256_jwt() {
        let secret = "topsecret";
        let cfg = JwtConfig { enabled: true, secret: secret.into(), issuer: String::new(), audience: String::new() };
        let a = Authenticator::new(vec![], cfg);

        // Build a minimal HS256 token: {"alg":"HS256"} . {"sub":"svc","exp":<far future>} . sig
        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header = enc(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = enc(br#"{"sub":"svc","exp":9999999999}"#);
        let signing_input = format!("{header}.{payload}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = enc(&mac.finalize().into_bytes());
        let token = format!("{signing_input}.{sig}");

        match a.authenticate(Some(&token), None) {
            AuthOutcome::Allowed { subject, method } => {
                assert_eq!(subject, "svc");
                assert_eq!(method, "jwt");
            }
            AuthOutcome::Denied { reason } => panic!("expected allow, got deny: {reason}"),
        }

        // A tampered signature is rejected.
        let bad = format!("{signing_input}.{}", enc(b"not-a-valid-sig"));
        assert!(matches!(a.authenticate(Some(&bad), None), AuthOutcome::Denied { .. }));
    }

    #[test]
    fn rejects_alg_none_jwt() {
        let cfg = JwtConfig { enabled: true, secret: "s".into(), issuer: String::new(), audience: String::new() };
        let a = Authenticator::new(vec![], cfg);
        let enc = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let token = format!("{}.{}.{}", enc(br#"{"alg":"none"}"#), enc(br#"{"sub":"x"}"#), "");
        assert!(matches!(a.authenticate(Some(&token), None), AuthOutcome::Denied { .. }));
    }
}
