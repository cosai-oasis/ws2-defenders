"""AITF Example: Model Operations (LLMOps/MLOps) Tracing — Healthcare.

Demonstrates the full AI model lifecycle with AITF in a realistic scenario:

    A hospital's ML platform team fine-tunes a clinical-notes summarizer
    on top of Llama-3.1-70B, evaluates it with benchmarks and an LLM
    judge, registers and promotes it through staging → production,
    deploys via canary rollout, serves with routing/fallback/caching,
    monitors for drift and SLA compliance, and manages prompt versions —
    every operation traced for regulatory audit (HIPAA, EU AI Act).

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.

Run:
    pip install opentelemetry-sdk aitf
    python model_ops_tracing.py
"""

from __future__ import annotations

import json
import time

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.model_ops import ModelOpsInstrumentor
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.exporters.ocsf_exporter import OCSFExporter


# ────────────────────────────────────────────────────────────────────
# 1. Simulated MLOps helpers
# ────────────────────────────────────────────────────────────────────

def simulate_training(epochs: int, base_loss: float = 1.8) -> list[dict]:
    """Simulate training loss progression over epochs."""
    results = []
    loss = base_loss
    for e in range(1, epochs + 1):
        loss *= 0.72  # ~28% reduction per epoch
        val_loss = loss * 1.12
        results.append({"epoch": e, "loss": round(loss, 4), "val_loss": round(val_loss, 4)})
        time.sleep(0.02)
    return results


def simulate_evaluation(model_id: str, dataset: str) -> dict:
    """Simulate a benchmark evaluation run."""
    time.sleep(0.04)
    return {
        "model_id": model_id,
        "dataset": dataset,
        "rouge_1": 0.68,
        "rouge_2": 0.42,
        "rouge_l": 0.61,
        "bertscore_f1": 0.89,
        "clinical_accuracy": 0.94,
        "hallucination_rate": 0.03,
        "pii_leakage_rate": 0.00,
    }


def simulate_canary_deploy(model_id: str, canary_pct: float) -> dict:
    """Simulate a canary deployment to production."""
    time.sleep(0.08)
    return {
        "deployment_id": f"deploy-{model_id}-canary",
        "endpoint": f"https://ml-gateway.hospital.internal/v1/{model_id}",
        "canary_percent": canary_pct,
        "replicas": 4,
        "gpu_type": "A100-80GB",
        "health": "healthy",
        "p50_latency_ms": 28.4,
        "p99_latency_ms": 142.0,
    }


# ────────────────────────────────────────────────────────────────────
# 2. AITF Setup
# ────────────────────────────────────────────────────────────────────

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
ocsf_exporter = OCSFExporter(
    output_file="/tmp/aitf_model_ops_events.jsonl",
    compliance_frameworks=["nist_ai_rmf", "eu_ai_act"],
)
provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))
trace.set_tracer_provider(provider)

model_ops = ModelOpsInstrumentor(tracer_provider=provider)
model_ops.instrument()
llm = LLMInstrumentor(tracer_provider=provider)

MODEL_ID = "clinical-notes-llama-70b-v4"
BASE_MODEL = "meta-llama/Llama-3.1-70B"


# ────────────────────────────────────────────────────────────────────
# 3. Full Model Lifecycle
# ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  Healthcare ML Platform — Model Ops Lifecycle")
print("=" * 70)
print(f"\n  Model:      {MODEL_ID}")
print(f"  Base:       {BASE_MODEL}")
print(f"  Use case:   Clinical notes summarization (discharge summaries)")
print(f"  Regulation: HIPAA, EU AI Act (high-risk medical device)\n")


# ── Phase 1: Fine-Tuning ──────────────────────────────────────────

print("─" * 70)
print("  Phase 1: Fine-Tuning (LoRA)")
print("─" * 70)

with model_ops.trace_training(
    training_type="lora",
    base_model=BASE_MODEL,
    framework="pytorch",
    dataset_id="clinical-notes-deidentified-v4",
    dataset_version="4.1.0",
    dataset_size=120_000,
    hyperparameters=json.dumps({
        "learning_rate": 1e-5,
        "lora_rank": 32,
        "lora_alpha": 64,
        "batch_size": 8,
        "gradient_accumulation_steps": 4,
        "warmup_ratio": 0.1,
    }),
    epochs=5,
    experiment_id="exp-clinical-v4-001",
    experiment_name="Clinical Notes Summarizer v4",
) as run:
    run.set_compute(gpu_type="A100-80GB", gpu_count=8, gpu_hours=36.2)
    run.set_code_commit("f8a2c1e9d4b6")

    # Simulate training
    epoch_results = simulate_training(epochs=5)
    for r in epoch_results:
        print(f"    Epoch {r['epoch']}/5: loss={r['loss']:.4f}, val_loss={r['val_loss']:.4f}")

    final = epoch_results[-1]
    run.set_loss(loss=final["loss"], val_loss=final["val_loss"])
    run.set_output_model(
        model_id=MODEL_ID,
        model_hash="sha256:3a7bd2e1c9f4a8b5d6e7f0123456789abcdef0123456789abcdef01234567",
    )

print(f"\n  Training complete: {MODEL_ID}")
print(f"  Final loss: {final['loss']:.4f}, val_loss: {final['val_loss']:.4f}")
print(f"  Compute: 8×A100-80GB, 36.2 GPU-hours\n")


# ── Phase 2: Evaluation ──────────────────────────────────────────

print("─" * 70)
print("  Phase 2: Evaluation (Benchmark + LLM Judge + Bias Audit)")
print("─" * 70)

# 2a: Automated benchmark evaluation
print("\n  [2a] Benchmark evaluation on clinical-eval-suite-v3")
with model_ops.trace_evaluation(
    model_id=MODEL_ID,
    eval_type="benchmark",
    dataset_id="clinical-eval-suite-v3",
    dataset_size=8000,
    baseline_model=BASE_MODEL,
) as eval_run:
    metrics = simulate_evaluation(MODEL_ID, "clinical-eval-suite-v3")
    eval_run.set_metrics({
        "rouge_1": metrics["rouge_1"],
        "rouge_2": metrics["rouge_2"],
        "rouge_l": metrics["rouge_l"],
        "bertscore_f1": metrics["bertscore_f1"],
        "clinical_accuracy": metrics["clinical_accuracy"],
        "hallucination_rate": metrics["hallucination_rate"],
        "pii_leakage_rate": metrics["pii_leakage_rate"],
    })
    eval_run.set_pass(passed=True, regression_detected=False)

print(f"    ROUGE-1: {metrics['rouge_1']:.2f}  ROUGE-L: {metrics['rouge_l']:.2f}")
print(f"    Clinical accuracy:   {metrics['clinical_accuracy']:.0%}")
print(f"    Hallucination rate:  {metrics['hallucination_rate']:.0%}")
print(f"    PII leakage rate:    {metrics['pii_leakage_rate']:.0%}")
print(f"    Result: PASSED")

# 2b: LLM-as-judge evaluation (clinical domain expert)
print("\n  [2b] LLM-as-judge evaluation (GPT-4o as clinical reviewer)")
with model_ops.trace_evaluation(
    model_id=MODEL_ID,
    eval_type="llm_judge",
    dataset_id="clinical-judge-prompts-v2",
    dataset_size=500,
    judge_model="gpt-4o",
) as eval_run:
    with llm.trace_inference(
        model="gpt-4o",
        system="openai",
        operation="chat",
        temperature=0.0,
        max_tokens=512,
    ) as llm_span:
        llm_span.set_prompt(
            "As a clinical documentation expert, evaluate this discharge "
            "summary for medical accuracy, completeness, and readability ..."
        )
        llm_span.set_completion(
            "Score: 4.6/5.0.  The summary correctly captures diagnoses, "
            "medications, and follow-up instructions.  Minor: missing "
            "allergy documentation in 2/500 samples."
        )
        llm_span.set_usage(input_tokens=850, output_tokens=180)

    eval_run.set_metrics({
        "medical_accuracy": 4.7,
        "completeness": 4.5,
        "readability": 4.6,
        "safety": 4.9,
        "overall": 4.6,
    })
    eval_run.set_pass(passed=True)

print(f"    Medical accuracy: 4.7/5  Completeness: 4.5/5")
print(f"    Safety: 4.9/5  Overall: 4.6/5")
print(f"    Result: PASSED")

# 2c: Bias evaluation (fairness across demographics)
print("\n  [2c] Bias audit (fairness across patient demographics)")
with model_ops.trace_evaluation(
    model_id=MODEL_ID,
    eval_type="benchmark",
    dataset_id="clinical-fairness-eval-v1",
    dataset_size=2000,
    baseline_model=BASE_MODEL,
) as eval_run:
    eval_run.set_metrics({
        "demographic_parity_diff": 0.02,
        "equalized_odds_diff": 0.03,
        "accuracy_gap_age": 0.01,
        "accuracy_gap_gender": 0.02,
        "accuracy_gap_ethnicity": 0.03,
    })
    eval_run.set_pass(passed=True, regression_detected=False)

print(f"    Demographic parity diff:  0.02 (threshold: < 0.05)")
print(f"    Equalized odds diff:      0.03 (threshold: < 0.05)")
print(f"    Max accuracy gap:         0.03 (ethnicity)")
print(f"    Result: PASSED — no significant bias detected\n")


# ── Phase 3: Registry ────────────────────────────────────────────

print("─" * 70)
print("  Phase 3: Model Registry (Register → Staging → Production)")
print("─" * 70)

# Register
with model_ops.trace_registry(
    model_id=MODEL_ID,
    operation="register",
    model_version="4.0.0",
    stage="staging",
    model_alias="clinical-summarizer-latest",
    owner="ml-platform-team",
    training_run_id=run.run_id,
    parent_model_id=BASE_MODEL,
) as span:
    span.add_event("model.registered", attributes={
        "registry": "hospital-model-registry",
        "tags": "clinical,summarization,lora,llama-3.1,hipaa",
    })

print(f"\n  Registered {MODEL_ID} v4.0.0 → staging")

# Promote to production (after evaluation gate)
with model_ops.trace_registry(
    model_id=MODEL_ID,
    operation="promote",
    model_version="4.0.0",
    stage="production",
) as span:
    span.add_event("model.promoted", attributes={
        "from_stage": "staging",
        "to_stage": "production",
        "approval": "dr-smith@hospital.org (Chief Medical Informatics Officer)",
    })

print(f"  Promoted to production (approved by CMIO)")
print(f"  Alias: clinical-summarizer-latest\n")


# ── Phase 4: Deployment ──────────────────────────────────────────

print("─" * 70)
print("  Phase 4: Canary Deployment")
print("─" * 70)

with model_ops.trace_deployment(
    model_id=MODEL_ID,
    strategy="canary",
    environment="production",
    endpoint="https://ml-gateway.hospital.internal/v1/clinical-summarizer",
    canary_percent=10.0,
    infrastructure_provider="aws",
) as deployment:
    deploy_info = simulate_canary_deploy(MODEL_ID, 10.0)
    deployment.set_infrastructure(
        gpu_type=deploy_info["gpu_type"],
        replicas=deploy_info["replicas"],
    )
    deployment.set_health(
        status=deploy_info["health"],
        latency_ms=deploy_info["p99_latency_ms"],
    )

print(f"\n  Deployment: {deploy_info['deployment_id']}")
print(f"  Endpoint:   {deploy_info['endpoint']}")
print(f"  Strategy:   canary ({deploy_info['canary_percent']}% traffic)")
print(f"  Infra:      {deploy_info['replicas']}× {deploy_info['gpu_type']}")
print(f"  Health:     {deploy_info['health']} (p99={deploy_info['p99_latency_ms']}ms)\n")


# ── Phase 5: Serving — Routing + Fallback + Cache ────────────────

print("─" * 70)
print("  Phase 5: Model Serving")
print("─" * 70)

# 5a: Routing — clinical query routed to specialized model
print("\n  [5a] Routing: clinical summarization request")
with model_ops.trace_route(
    selected_model=MODEL_ID,
    reason="capability",
    candidates=[MODEL_ID, "gpt-4o", "claude-sonnet-4-5-20250929"],
) as span:
    span.add_event("route.selected", attributes={
        "selection_criteria": "HIPAA-compliant clinical summarization",
        "routing_rule": "clinical-notes → clinical-summarizer",
    })

    # Actual inference
    with llm.trace_inference(
        model=MODEL_ID,
        system="custom",
        operation="chat",
        temperature=0.0,
        max_tokens=512,
    ) as llm_span:
        llm_span.set_prompt(
            "Summarize this discharge note:\n"
            "Patient: 72M, admitted 2026-02-20 for acute MI.\n"
            "Procedures: PCI with DES to LAD.  Echo: EF 45%.\n"
            "Meds: aspirin 81mg, clopidogrel 75mg, atorvastatin 80mg, "
            "metoprolol 25mg, lisinopril 10mg.\n"
            "Follow-up: cardiology in 2 weeks, cardiac rehab referral."
        )
        llm_span.set_completion(
            "72-year-old male admitted for acute MI, treated with PCI/DES to LAD. "
            "Echo showed EF 45%.  Discharged on dual antiplatelet therapy, statin, "
            "beta-blocker, and ACE inhibitor.  Follow-up: cardiology 2 weeks, "
            "cardiac rehabilitation."
        )
        llm_span.set_usage(input_tokens=180, output_tokens=65)

print(f"  Routed to {MODEL_ID} (HIPAA-compliant clinical model)")

# 5b: Fallback — model timeout triggers fallback to GPT-4o
print("\n  [5b] Fallback: model timeout → GPT-4o")
with model_ops.trace_fallback(
    original_model=MODEL_ID,
    final_model="gpt-4o",
    trigger="timeout",
    chain=[MODEL_ID, "gpt-4o"],
    depth=1,
) as span:
    span.add_event("fallback.triggered", attributes={
        "original_error": f"{MODEL_ID} inference timed out after 30s (GPU memory pressure)",
        "fallback_note": "GPT-4o used as emergency fallback; PII redacted before sending",
    })

    with llm.trace_inference(
        model="gpt-4o",
        system="openai",
        operation="chat",
        temperature=0.0,
        max_tokens=512,
    ) as llm_span:
        llm_span.set_prompt("[PII-REDACTED] Summarize discharge note: 72M, acute MI, PCI/DES …")
        llm_span.set_completion("72-year-old male, acute MI treated with PCI.  Discharged stable …")
        llm_span.set_usage(input_tokens=120, output_tokens=55)

print(f"  Fallback: {MODEL_ID} → gpt-4o (timeout, PII redacted)")

# 5c: Semantic cache hit
print("\n  [5c] Semantic cache: similar discharge note")
with model_ops.trace_cache_lookup(cache_type="semantic") as lookup:
    lookup.set_hit(hit=True, similarity_score=0.96, cost_saved_usd=0.008)

print(f"  Cache HIT (similarity: 0.96, saved: $0.008)")

# 5d: Semantic cache miss
with model_ops.trace_cache_lookup(cache_type="semantic") as lookup:
    lookup.set_hit(hit=False, similarity_score=0.42)

print(f"  Cache MISS (similarity: 0.42 — different clinical domain)\n")


# ── Phase 6: Monitoring ──────────────────────────────────────────

print("─" * 70)
print("  Phase 6: Production Monitoring")
print("─" * 70)

# 6a: Performance check
print("\n  [6a] Performance check")
with model_ops.trace_monitoring_check(
    model_id=MODEL_ID,
    check_type="performance",
    metric_name="p95_latency_ms",
) as check:
    check.set_result(
        result="pass",
        metric_value=135.0,
        baseline_value=200.0,
    )

print(f"  P95 latency: 135ms (threshold: 200ms) → PASS")

# 6b: Drift detection — input distribution shift
print("\n  [6b] Drift detection (input distribution)")
with model_ops.trace_monitoring_check(
    model_id=MODEL_ID,
    check_type="drift",
    metric_name="input_distribution",
) as check:
    check.set_result(
        result="warning",
        drift_score=0.38,
        drift_type="feature",
        baseline_value=0.10,
        metric_value=0.38,
        action_triggered="alert",
    )

print(f"  Input drift: 0.38 (baseline: 0.10) → WARNING")
print(f"  Possible cause: new oncology department sending clinical notes")
print(f"  Action: alert sent to ml-platform-team")

# 6c: Output quality monitoring
print("\n  [6c] Output quality check (hallucination rate)")
with model_ops.trace_monitoring_check(
    model_id=MODEL_ID,
    check_type="performance",
    metric_name="hallucination_rate",
) as check:
    check.set_result(
        result="pass",
        metric_value=0.028,
        baseline_value=0.050,
    )

print(f"  Hallucination rate: 2.8% (threshold: 5%) → PASS")

# 6d: SLA compliance
print("\n  [6d] SLA compliance check")
with model_ops.trace_monitoring_check(
    model_id=MODEL_ID,
    check_type="sla",
    metric_name="availability_pct",
) as check:
    check.set_result(
        result="pass",
        metric_value=99.97,
        baseline_value=99.9,
    )

print(f"  Availability: 99.97% (SLA target: 99.9%) → PASS\n")


# ── Phase 7: Prompt Lifecycle ─────────────────────────────────────

print("─" * 70)
print("  Phase 7: Prompt Lifecycle Management")
print("─" * 70)

# 7a: Register new prompt version
print("\n  [7a] Register new prompt version")
with model_ops.trace_prompt(
    name="discharge-summary-system",
    operation="register",
    version="3.0.0",
    label="staging",
    model_target=MODEL_ID,
) as prompt_op:
    prompt_op.set_content_hash("sha256:a1b2c3d4e5f6789012345678abcdef01")

print(f"  Registered 'discharge-summary-system' v3.0.0 → staging")

# 7b: Evaluate prompt quality
print("\n  [7b] Evaluate prompt quality")
with model_ops.trace_prompt(
    name="discharge-summary-system",
    operation="evaluate",
    version="3.0.0",
    model_target=MODEL_ID,
) as prompt_op:
    prompt_op.set_evaluation(score=0.94, passed=True)

print(f"  Prompt evaluation: score=0.94 → PASSED")

# 7c: A/B test — compare prompt v2.1 vs v3.0
print("\n  [7c] A/B test: prompt v2.1 vs v3.0")
with model_ops.trace_prompt(
    name="discharge-summary-system",
    operation="ab_test",
    version="3.0.0",
    model_target=MODEL_ID,
) as prompt_op:
    prompt_op.set_ab_test(
        test_id="ab-prompt-clinical-003",
        variant="B",
        traffic_pct=25.0,
    )

print(f"  A/B test: variant B (v3.0) at 25% traffic")
print(f"  Control: variant A (v2.1) at 75% traffic\n")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  Summary — Full Model Lifecycle")
print("=" * 70)
print(f"""
  Model:              {MODEL_ID}
  Base model:         {BASE_MODEL}

  Phase 1 — Training:    5 epochs, 8×A100, 36.2 GPU-hours
  Phase 2 — Evaluation:  3 eval runs (benchmark + LLM judge + bias audit)
  Phase 3 — Registry:    registered → staging → production (CMIO approved)
  Phase 4 — Deployment:  canary 10%, 4×A100, p99=142ms
  Phase 5 — Serving:     routing + fallback + cache (1 hit, 1 miss)
  Phase 6 — Monitoring:  4 checks (3 pass + 1 drift warning)
  Phase 7 — Prompts:     register + evaluate + A/B test

  OCSF events:         {ocsf_exporter.event_count}
  Events at:           /tmp/aitf_model_ops_events.jsonl
  Compliance:          NIST AI RMF + EU AI Act (high-risk medical device)

  Every lifecycle phase is traced for regulatory audit:
  training provenance, evaluation results, deployment approvals,
  serving decisions, drift alerts, and prompt versioning.
""")

provider.shutdown()
