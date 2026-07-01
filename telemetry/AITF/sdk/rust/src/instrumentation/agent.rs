//! Agent session instrumentation mirroring the Go `instrumentation/agent.go`.

use opentelemetry::global::{self, BoxedTracer};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
use opentelemetry::KeyValue;

use crate::semconv::agent;

const TRACER_NAME: &str = "instrumentation.agent";
const DEFAULT_AGENT_TYPE: &str = "autonomous";
const DEFAULT_FRAMEWORK: &str = "custom";
const STEP_DELEGATION: &str = "delegation";

/// Configures an agent session span.
#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    /// Human-readable agent name.
    pub agent_name: String,
    /// Stable agent identifier.
    pub agent_id: String,
    /// Agent type (defaults to `autonomous`).
    pub agent_type: String,
    /// Framework (defaults to `custom`).
    pub framework: String,
    /// Optional agent version.
    pub version: String,
    /// Optional description.
    pub description: String,
    /// Session / conversation identifier.
    pub session_id: String,
    /// Optional team name.
    pub team_name: String,
}

impl SessionConfig {
    /// Convenience constructor from an agent name.
    pub fn new(agent_name: impl Into<String>) -> Self {
        Self {
            agent_name: agent_name.into(),
            ..Default::default()
        }
    }
}

/// Traces AI agent operations.
pub struct AgentInstrumentor<T = BoxedTracer> {
    tracer: T,
}

impl AgentInstrumentor<BoxedTracer> {
    /// Creates an instrumentor using the global tracer provider.
    pub fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

impl Default for AgentInstrumentor<BoxedTracer> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Tracer> AgentInstrumentor<T>
where
    T: Clone,
{
    /// Creates an instrumentor from an explicit tracer.
    pub fn with_tracer(tracer: T) -> Self {
        Self { tracer }
    }

    /// Starts an agent session span. The caller must call
    /// [`AgentSession::end`] when done.
    pub fn trace_session(&self, mut cfg: SessionConfig) -> AgentSession<T> {
        if cfg.agent_type.is_empty() {
            cfg.agent_type = DEFAULT_AGENT_TYPE.to_string();
        }
        if cfg.framework.is_empty() {
            cfg.framework = DEFAULT_FRAMEWORK.to_string();
        }

        let mut attrs = vec![
            KeyValue::new(agent::NAME, cfg.agent_name.clone()),
            KeyValue::new(agent::ID, cfg.agent_id.clone()),
            KeyValue::new(agent::TYPE, cfg.agent_type.clone()),
            KeyValue::new(agent::FRAMEWORK, cfg.framework.clone()),
            KeyValue::new(agent::SESSION_ID, cfg.session_id.clone()),
        ];
        if !cfg.version.is_empty() {
            attrs.push(KeyValue::new(agent::VERSION, cfg.version.clone()));
        }
        if !cfg.description.is_empty() {
            attrs.push(KeyValue::new(agent::DESCRIPTION, cfg.description.clone()));
        }
        if !cfg.team_name.is_empty() {
            attrs.push(KeyValue::new(agent::TEAM_NAME, cfg.team_name.clone()));
        }

        let span = self
            .tracer
            .span_builder(format!("agent.session {}", cfg.agent_name))
            .with_kind(SpanKind::Internal)
            .with_attributes(attrs)
            .start(&self.tracer);

        AgentSession {
            span,
            tracer: self.tracer.clone(),
            agent_name: cfg.agent_name,
            step_count: 0,
        }
    }
}

/// Manages spans within an agent session.
pub struct AgentSession<T: Tracer> {
    span: T::Span,
    tracer: T,
    agent_name: String,
    step_count: i64,
}

impl<T: Tracer> AgentSession<T> {
    /// Starts an agent step span as a child of the session.
    pub fn step(&mut self, step_type: &str) -> AgentStep<T::Span> {
        self.step_count += 1;
        let attrs = vec![
            KeyValue::new(agent::NAME, self.agent_name.clone()),
            KeyValue::new(agent::STEP_TYPE, step_type.to_string()),
            KeyValue::new(agent::STEP_INDEX, self.step_count),
        ];
        let span = self
            .tracer
            .span_builder(format!("agent.step.{} {}", step_type, self.agent_name))
            .with_kind(SpanKind::Internal)
            .with_attributes(attrs)
            .start(&self.tracer);
        AgentStep { span }
    }

    /// Starts a delegation span.
    pub fn delegate(
        &mut self,
        target_agent: &str,
        target_agent_id: &str,
        reason: &str,
        strategy: &str,
    ) -> T::Span {
        self.step_count += 1;
        let mut attrs = vec![
            KeyValue::new(agent::NAME, self.agent_name.clone()),
            KeyValue::new(agent::STEP_TYPE, STEP_DELEGATION),
            KeyValue::new(agent::STEP_INDEX, self.step_count),
            KeyValue::new(agent::DELEGATION_TARGET_AGENT, target_agent.to_string()),
            KeyValue::new(
                agent::DELEGATION_TARGET_AGENT_ID,
                target_agent_id.to_string(),
            ),
            KeyValue::new(agent::DELEGATION_STRATEGY, strategy.to_string()),
        ];
        if !reason.is_empty() {
            attrs.push(KeyValue::new(agent::DELEGATION_REASON, reason.to_string()));
        }
        self.tracer
            .span_builder(format!(
                "agent.delegate {} -> {}",
                self.agent_name, target_agent
            ))
            .with_kind(SpanKind::Internal)
            .with_attributes(attrs)
            .start(&self.tracer)
    }

    /// Completes the session span, recording the turn count and status.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        self.span
            .set_attribute(KeyValue::new(agent::SESSION_TURN_COUNT, self.step_count));
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying session span.
    pub fn span_mut(&mut self) -> &mut T::Span {
        &mut self.span
    }
}

/// Records attributes for a single agent step.
pub struct AgentStep<S: Span> {
    span: S,
}

impl<S: Span> AgentStep<S> {
    /// Sets the agent's reasoning.
    pub fn set_thought(&mut self, thought: impl Into<String>) {
        self.span
            .set_attribute(KeyValue::new(agent::STEP_THOUGHT, thought.into()));
    }

    /// Sets the planned action.
    pub fn set_action(&mut self, action: impl Into<String>) {
        self.span
            .set_attribute(KeyValue::new(agent::STEP_ACTION, action.into()));
    }

    /// Sets the observation result.
    pub fn set_observation(&mut self, observation: impl Into<String>) {
        self.span
            .set_attribute(KeyValue::new(agent::STEP_OBSERVATION, observation.into()));
    }

    /// Completes the step span.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying step span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}
