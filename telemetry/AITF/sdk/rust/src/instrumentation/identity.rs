//! Identity / auth instrumentation mirroring the Go `instrumentation/identity.go`.
//!
//! The Rust `semconv::identity` module exposes the subset of identity attribute
//! keys used by the mapper / crosswalk (lifecycle, authentication, and
//! delegation), so this instrumentor covers those domains.

use opentelemetry::global::{self, BoxedTracer};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
use opentelemetry::{StringValue, Value};
use opentelemetry::KeyValue;

use crate::semconv::identity;

const TRACER_NAME: &str = "instrumentation.identity";

fn string_array(values: &[String]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|s| StringValue::from(s.clone()))
            .collect::<Vec<_>>()
            .into(),
    )
}

/// Configuration for an identity lifecycle span.
#[derive(Debug, Clone, Default)]
pub struct LifecycleConfig {
    /// Agent identifier.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// Identity type (e.g. `persistent`, `ephemeral`, `delegated`). Defaults to `persistent`.
    pub identity_type: String,
    /// Identity provider.
    pub provider: String,
    /// Credential type.
    pub credential_type: String,
    /// Granted scopes.
    pub scope: Vec<String>,
}

/// Configuration for an authentication span.
#[derive(Debug, Clone, Default)]
pub struct AuthenticationConfig {
    /// Agent identifier.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// Auth method (e.g. `spiffe_svid`, `oauth2`, `mtls`).
    pub method: String,
}

/// Configuration for a delegation span.
#[derive(Debug, Clone, Default)]
pub struct DelegationConfig {
    /// Delegator name.
    pub delegator: String,
    /// Delegator identifier.
    pub delegator_id: String,
    /// Delegatee name.
    pub delegatee: String,
    /// Delegatee identifier.
    pub delegatee_id: String,
    /// Delegation type (e.g. `on_behalf_of`, `token_exchange`). Defaults to `on_behalf_of`.
    pub delegation_type: String,
    /// Delegated scopes.
    pub scope_delegated: Vec<String>,
    /// Optional time-to-live in seconds.
    pub ttl_seconds: Option<i64>,
}

/// Traces AI agent identity operations (lifecycle, authentication, delegation).
pub struct IdentityInstrumentor<T = BoxedTracer> {
    tracer: T,
}

impl IdentityInstrumentor<BoxedTracer> {
    /// Creates an instrumentor using the global tracer provider.
    pub fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

impl Default for IdentityInstrumentor<BoxedTracer> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Tracer> IdentityInstrumentor<T> {
    /// Creates an instrumentor from an explicit tracer.
    pub fn with_tracer(tracer: T) -> Self {
        Self { tracer }
    }

    /// Starts a span for an identity lifecycle operation.
    pub fn trace_lifecycle(
        &self,
        operation: &str,
        mut cfg: LifecycleConfig,
    ) -> IdentityLifecycle<T::Span> {
        if cfg.identity_type.is_empty() {
            cfg.identity_type = "persistent".to_string();
        }
        let mut attrs = vec![
            KeyValue::new(identity::AGENT_ID, cfg.agent_id.clone()),
            KeyValue::new(identity::AGENT_NAME, cfg.agent_name.clone()),
            KeyValue::new(identity::TYPE, cfg.identity_type.clone()),
        ];
        if !cfg.provider.is_empty() {
            attrs.push(KeyValue::new(identity::PROVIDER, cfg.provider.clone()));
        }
        if !cfg.credential_type.is_empty() {
            attrs.push(KeyValue::new(
                identity::CREDENTIAL_TYPE,
                cfg.credential_type.clone(),
            ));
        }
        if !cfg.scope.is_empty() {
            attrs.push(KeyValue::new(identity::SCOPE, string_array(&cfg.scope)));
        }
        let span = self
            .tracer
            .span_builder(format!("identity.lifecycle.{} {}", operation, cfg.agent_id))
            .with_kind(SpanKind::Internal)
            .with_attributes(attrs)
            .start(&self.tracer);
        IdentityLifecycle { span }
    }

    /// Starts a span for an agent authentication attempt.
    pub fn trace_authentication(
        &self,
        cfg: AuthenticationConfig,
    ) -> AuthenticationAttempt<T::Span> {
        let attrs = vec![
            KeyValue::new(identity::AGENT_ID, cfg.agent_id.clone()),
            KeyValue::new(identity::AGENT_NAME, cfg.agent_name.clone()),
            KeyValue::new(identity::AUTH_METHOD, cfg.method.clone()),
        ];
        let span = self
            .tracer
            .span_builder(format!("identity.auth {}", cfg.agent_name))
            .with_kind(SpanKind::Client)
            .with_attributes(attrs)
            .start(&self.tracer);
        AuthenticationAttempt { span }
    }

    /// Starts a span for credential delegation.
    pub fn trace_delegation(&self, mut cfg: DelegationConfig) -> DelegationOperation<T::Span> {
        if cfg.delegation_type.is_empty() {
            cfg.delegation_type = "on_behalf_of".to_string();
        }
        let mut attrs = vec![
            KeyValue::new(identity::DELEGATION_DELEGATOR, cfg.delegator.clone()),
            KeyValue::new(identity::DELEGATION_DELEGATOR_ID, cfg.delegator_id.clone()),
            KeyValue::new(identity::DELEGATION_DELEGATEE, cfg.delegatee.clone()),
            KeyValue::new(identity::DELEGATION_DELEGATEE_ID, cfg.delegatee_id.clone()),
            KeyValue::new(identity::DELEGATION_TYPE, cfg.delegation_type.clone()),
        ];
        if !cfg.scope_delegated.is_empty() {
            attrs.push(KeyValue::new(
                identity::DELEGATION_SCOPE_DELEGATED,
                string_array(&cfg.scope_delegated),
            ));
        }
        if let Some(ttl) = cfg.ttl_seconds {
            attrs.push(KeyValue::new(identity::DELEGATION_TTL_SECONDS, ttl));
        }
        let span = self
            .tracer
            .span_builder(format!(
                "identity.delegate {} -> {}",
                cfg.delegator, cfg.delegatee
            ))
            .with_kind(SpanKind::Internal)
            .with_attributes(attrs)
            .start(&self.tracer);
        DelegationOperation { span }
    }
}

/// Records identity lifecycle attributes.
pub struct IdentityLifecycle<S: Span> {
    span: S,
}

impl<S: Span> IdentityLifecycle<S> {
    /// Completes the lifecycle span.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}

/// Records authentication results.
pub struct AuthenticationAttempt<S: Span> {
    span: S,
}

impl<S: Span> AuthenticationAttempt<S> {
    /// Records the authentication result.
    pub fn set_result(&mut self, result: &str) {
        self.span
            .set_attribute(KeyValue::new(identity::AUTH_RESULT, result.to_string()));
    }

    /// Completes the authentication span.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}

/// Records delegation results.
pub struct DelegationOperation<S: Span> {
    span: S,
}

impl<S: Span> DelegationOperation<S> {
    /// Records the delegation chain and its depth.
    pub fn set_chain(&mut self, chain: &[String]) {
        self.span
            .set_attribute(KeyValue::new(identity::DELEGATION_CHAIN, string_array(chain)));
    }

    /// Records the proof type used for delegation.
    pub fn set_proof(&mut self, proof_type: &str) {
        self.span.set_attribute(KeyValue::new(
            identity::DELEGATION_PROOF_TYPE,
            proof_type.to_string(),
        ));
    }

    /// Completes the delegation span.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}
