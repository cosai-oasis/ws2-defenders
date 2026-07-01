import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

// ── AITF OCSF Class-Reuse constants ──
// Each AI event reuses an existing OCSF class (classUid) and carries an
// `aiOperation` profile string holding the AI-specific semantic.
const OCSF_CLASSES = {
  API_ACTIVITY: 6003,         // inference, tool_execution, mcp_operation
  DATASTORE_ACTIVITY: 6005,   // data_retrieval
  APP_LIFECYCLE: 6002,        // model_ops
  INVENTORY_INFO: 5001,       // asset_inventory
  AUTHENTICATION: 3002,       // identity
  DETECTION_FINDING: 2004,    // prompt_injection, data_exfiltration, etc.
  COMPLIANCE_FINDING: 2003,   // compliance_violation
  VULNERABILITY_FINDING: 2002,// supply_chain
  AGENT_ACTIVITY: 9001,       // agent_action
  DELEGATION_ACTIVITY: 9002,  // delegation
};

// type_uid is derived per OCSF as classUid * 100 + activity_id.
function typeUidFor(classUid: number, activityId: number): number {
  return classUid * 100 + activityId;
}

const MODELS = [
  { id: 'gpt-4o', provider: 'openai', type: 'llm' },
  { id: 'gpt-4o-mini', provider: 'openai', type: 'llm' },
  { id: 'claude-sonnet-4-5-20250929', provider: 'anthropic', type: 'llm' },
  { id: 'claude-haiku-4-5-20251001', provider: 'anthropic', type: 'llm' },
  { id: 'gemini-2.0-flash', provider: 'google', type: 'llm' },
  { id: 'mistral-large-latest', provider: 'mistral', type: 'llm' },
  { id: 'o3-mini', provider: 'openai', type: 'llm' },
  { id: 'text-embedding-3-small', provider: 'openai', type: 'embedding' },
  { id: 'llama-3.1-70b', provider: 'meta', type: 'llm' },
];

const AGENTS = [
  { name: 'research-agent', type: 'autonomous', framework: 'langchain' },
  { name: 'code-reviewer', type: 'autonomous', framework: 'crewai' },
  { name: 'data-analyst', type: 'autonomous', framework: 'autogen' },
  { name: 'customer-support', type: 'conversational', framework: 'langchain' },
  { name: 'security-scanner', type: 'autonomous', framework: 'custom' },
  { name: 'content-writer', type: 'autonomous', framework: 'langchain' },
  { name: 'orchestrator', type: 'orchestrator', framework: 'crewai' },
  { name: 'qa-tester', type: 'autonomous', framework: 'autogen' },
];

const MCP_SERVERS = ['filesystem-server', 'github-server', 'postgres-server', 'slack-server', 'jira-server', 'web-search-server'];
const TOOLS = ['read_file', 'write_file', 'search_repos', 'create_issue', 'execute_query', 'send_message', 'web_search', 'data-analysis', 'code-generation'];

const USERS = [
  { uid: 'user-001', name: 'Alice Chen', role: 'ml-engineer' },
  { uid: 'user-002', name: 'Bob Martinez', role: 'data-scientist' },
  { uid: 'user-003', name: 'Carol Johnson', role: 'sre' },
  { uid: 'user-004', name: 'David Kim', role: 'security-analyst' },
];

const RISK_LEVELS = ['low', 'low', 'low', 'medium', 'medium', 'high', 'critical'];

function pick<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function uuid() { return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16); }); }

function makeTimestamp(hoursAgo: number) {
  return new Date(Date.now() - hoursAgo * 3600000 + randInt(0, 3600000));
}

function makeActor() {
  const u = pick(USERS);
  return JSON.stringify({ user: { uid: u.uid, name: u.name, type: u.role }, session: { uid: uuid() } });
}

function makeCompliance() {
  const c: any = {};
  if (Math.random() > 0.3) c.nist_ai_rmf = { controls: ['MAP 1.1', 'MEASURE 2.3'], function: 'Measure' };
  if (Math.random() > 0.5) c.eu_ai_act = { articles: ['Art. 9', 'Art. 13'], risk_level: pick(['high_risk', 'limited_risk', 'minimal_risk']) };
  if (Math.random() > 0.6) c.mitre_atlas = { techniques: ['AML.T0043', 'AML.T0040'], tactic: 'ML Attack Staging' };
  if (Math.random() > 0.7) c.csa_aicm = { controls: ['AIS-01', 'AIS-04'], domain: 'AI Security' };
  return JSON.stringify(c);
}

function traceId() { return Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''); }
function spanId() { return Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join(''); }

// ── Event generators per OCSF class ──

function gen7001(hoursAgo: number) {
  const m = pick(MODELS.filter(x => x.type === 'llm'));
  const inputTokens = randInt(50, 4000);
  const outputTokens = randInt(20, 2000);
  const totalMs = randInt(200, 5000);
  const activityId = pick([1, 2, 3]);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_model_inference',
    classUid: 6003,
    aiOperation: 'inference',
    typeUid: typeUidFor(6003, activityId),
    activityId,
    severityId: pick([1, 1, 1, 2, 3]),
    statusId: pick([1, 1, 1, 2]),
    riskLevel: pick(['low', 'low', 'medium']),
    provider: m.provider,
    model: m.id,
    agentDetected: Math.random() > 0.4 ? pick(AGENTS).name : null,
    agentName: Math.random() > 0.5 ? pick(AGENTS).name : null,
    source: 'aitf_llm_instrumentor',
    message: `${m.provider}/${m.id} inference (${inputTokens}→${outputTokens} tokens, ${totalMs}ms)`,
    details: JSON.stringify({ operation: pick(['chat', 'text_completion']), temperature: +(Math.random() * 1.5).toFixed(2), max_tokens: randInt(256, 4096), finish_reason: pick(['stop', 'stop', 'length', 'tool_calls']), streaming: Math.random() > 0.5 }),
    tokenUsage: JSON.stringify({ input_tokens: inputTokens, output_tokens: outputTokens, total_tokens: inputTokens + outputTokens, estimated_cost_usd: +((inputTokens * 0.0025 + outputTokens * 0.01) / 1000).toFixed(6) }),
    costInfo: JSON.stringify({ input_cost_usd: +(inputTokens * 0.0025 / 1000).toFixed(6), output_cost_usd: +(outputTokens * 0.01 / 1000).toFixed(6), total_cost_usd: +((inputTokens * 0.0025 + outputTokens * 0.01) / 1000).toFixed(6) }),
    actor: makeActor(),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7002(hoursAgo: number) {
  const a = pick(AGENTS);
  const agentActivityId = pick([1, 2, 3, 4, 5]);
  const stepType = pick(['planning', 'reasoning', 'tool_use', 'delegation', 'response', 'memory_access', 'reflection']);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_agent_activity',
    classUid: 9001,
    aiOperation: 'agent_action',
    typeUid: typeUidFor(9001, agentActivityId),
    activityId: agentActivityId,
    severityId: pick([1, 1, 2, 2, 3]),
    statusId: 1,
    riskLevel: pick(['low', 'low', 'medium', 'high']),
    provider: null,
    model: Math.random() > 0.5 ? pick(MODELS).id : null,
    agentDetected: a.name,
    agentName: a.name,
    agentFramework: a.framework,
    source: 'aitf_agent_instrumentor',
    message: `Agent ${a.name} (${a.framework}) — ${stepType} step`,
    details: JSON.stringify({ agent_type: a.type, step_type: stepType, step_index: randInt(0, 10), thought: stepType === 'planning' ? 'Analyzing task requirements and planning execution strategy' : undefined, action: stepType === 'tool_use' ? pick(TOOLS) : undefined, session_id: uuid(), turn_count: randInt(1, 15) }),
    actor: makeActor(),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7003(hoursAgo: number) {
  const tool = pick(TOOLS);
  const server = pick(MCP_SERVERS);
  const isError = Math.random() > 0.9;
  const activityId = pick([1, 2]);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_tool_execution',
    classUid: 6003,
    aiOperation: 'tool_execution',
    typeUid: typeUidFor(6003, activityId),
    activityId,
    severityId: isError ? 4 : pick([1, 1, 2]),
    statusId: isError ? 2 : 1,
    riskLevel: isError ? 'high' : pick(['low', 'low', 'medium']),
    provider: null,
    model: null,
    agentDetected: pick(AGENTS).name,
    toolName: tool,
    mcpServer: server,
    source: 'aitf_mcp_instrumentor',
    message: `Tool ${tool} via MCP server ${server}${isError ? ' — FAILED' : ''}`,
    details: JSON.stringify({ tool_type: pick(['mcp_tool', 'function', 'skill']), is_error: isError, duration_ms: randInt(10, 3000), approval_required: Math.random() > 0.7, approved: true }),
    actor: makeActor(),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7004(hoursAgo: number) {
  const db = pick(['product-docs', 'knowledge-base', 'code-index', 'support-tickets', 'legal-corpus']);
  const dbType = pick(['pinecone', 'weaviate', 'qdrant', 'chromadb', 'pgvector']);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_data_retrieval',
    classUid: 6005,
    aiOperation: 'data_retrieval',
    typeUid: typeUidFor(6005, 1),
    activityId: 1,
    severityId: pick([1, 1, 2]),
    statusId: 1,
    riskLevel: pick(['low', 'low', 'medium']),
    provider: null,
    model: 'text-embedding-3-small',
    source: 'aitf_rag_instrumentor',
    message: `RAG retrieval from ${db} (${dbType}) — ${randInt(3, 20)} results`,
    details: JSON.stringify({ database_name: db, database_type: dbType, top_k: randInt(5, 20), results_count: randInt(3, 20), min_score: +(Math.random() * 0.3 + 0.5).toFixed(3), max_score: +(Math.random() * 0.2 + 0.8).toFixed(3), pipeline_stage: pick(['retrieve', 'rerank', 'generate']), embedding_model: 'text-embedding-3-small' }),
    actor: makeActor(),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7005(hoursAgo: number) {
  const threats = [
    { type: 'prompt_injection', owasp: 'LLM01', risk: 'critical', score: randInt(80, 99), msg: 'Prompt injection attempt detected in user input' },
    { type: 'jailbreak', owasp: 'LLM01', risk: 'high', score: randInt(65, 90), msg: 'Jailbreak attempt: DAN-style role bypass detected' },
    { type: 'data_exfiltration', owasp: 'LLM02', risk: 'critical', score: randInt(75, 95), msg: 'Potential data exfiltration via tool chain' },
    { type: 'sensitive_data_exposure', owasp: 'LLM02', risk: 'high', score: randInt(60, 85), msg: 'PII detected in model output (email, SSN)' },
    { type: 'excessive_agency', owasp: 'LLM06', risk: 'medium', score: randInt(40, 70), msg: 'Agent exceeded tool call threshold (>50 calls/min)' },
    { type: 'unbounded_consumption', owasp: 'LLM10', risk: 'high', score: randInt(55, 80), msg: 'Unusual token consumption spike: 5x rolling avg' },
    { type: 'system_prompt_leak', owasp: 'LLM07', risk: 'high', score: randInt(60, 85), msg: 'System prompt extraction pattern detected in output' },
    { type: 'supply_chain', owasp: 'LLM03', risk: 'critical', score: randInt(70, 95), msg: 'MCP server impersonation attempt detected' },
  ];
  const t = pick(threats);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_security_finding',
    classUid: 2004,
    aiOperation: 'prompt_injection',
    typeUid: typeUidFor(2004, 1),
    activityId: 1,
    severityId: t.risk === 'critical' ? 5 : t.risk === 'high' ? 4 : 3,
    statusId: 1,
    riskLevel: t.risk,
    agentDetected: pick(AGENTS).name,
    source: 'aitf_security_processor',
    message: t.msg,
    securityFinding: JSON.stringify({ finding_type: t.type, owasp_category: t.owasp, risk_level: t.risk, risk_score: t.score, confidence: +(Math.random() * 0.3 + 0.7).toFixed(2), detection_method: pick(['pattern_match', 'statistical', 'ml_classifier']), blocked: Math.random() > 0.3 }),
    details: JSON.stringify({ threat_type: t.type, owasp: t.owasp }),
    actor: makeActor(),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7006(hoursAgo: number) {
  const m = pick(MODELS);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_supply_chain',
    classUid: 2002,
    aiOperation: 'supply_chain',
    typeUid: typeUidFor(2002, 1),
    activityId: 1,
    severityId: pick([1, 2, 3]),
    statusId: 1,
    riskLevel: pick(['low', 'medium', 'high']),
    provider: m.provider,
    model: m.id,
    source: 'aitf_supply_chain',
    message: `Model provenance check: ${m.provider}/${m.id}`,
    details: JSON.stringify({ model_source: `https://huggingface.co/${m.id}`, model_signed: Math.random() > 0.3, verification_result: pick(['pass', 'pass', 'fail']), ai_bom_id: uuid() }),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7007(hoursAgo: number) {
  const frameworks = ['nist_ai_rmf', 'eu_ai_act', 'iso_42001', 'soc2', 'gdpr', 'csa_aicm'];
  const violation = Math.random() > 0.7;
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_governance',
    classUid: 2003,
    aiOperation: 'compliance_violation',
    typeUid: typeUidFor(2003, 1),
    activityId: 1,
    severityId: violation ? 4 : 1,
    statusId: 1,
    riskLevel: violation ? 'high' : 'low',
    source: 'aitf_compliance_mapper',
    message: violation ? `Compliance violation detected (${pick(frameworks)})` : `Compliance audit passed — ${pick(frameworks)}`,
    details: JSON.stringify({ frameworks: [pick(frameworks), pick(frameworks)], violation_detected: violation, audit_id: uuid() }),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7008(hoursAgo: number) {
  const a = pick(AGENTS);
  const authResult = pick(['success', 'success', 'success', 'failure', 'denied']);
  const activityId = pick([1, 2, 3]);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_identity',
    classUid: 3002,
    aiOperation: 'identity',
    typeUid: typeUidFor(3002, activityId),
    activityId,
    severityId: authResult === 'success' ? 1 : 4,
    statusId: authResult === 'success' ? 1 : 2,
    riskLevel: authResult === 'success' ? 'low' : 'high',
    agentDetected: a.name,
    agentName: a.name,
    source: 'aitf_identity_instrumentor',
    message: `Agent ${a.name} auth ${authResult} — ${pick(['oauth2', 'api_key', 'mtls', 'spiffe_svid'])}`,
    details: JSON.stringify({ identity_type: pick(['persistent', 'ephemeral', 'delegated']), auth_method: pick(['oauth2', 'api_key', 'mtls', 'spiffe_svid']), auth_result: authResult, scope_requested: ['read', 'write', 'execute'].slice(0, randInt(1, 3)), scope_granted: authResult === 'success' ? ['read', 'write'] : [] }),
    actor: makeActor(),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7009(hoursAgo: number) {
  const m = pick(MODELS);
  const opType = pick(['training', 'evaluation', 'deployment', 'monitoring', 'serving']);
  const activityId = pick([1, 2, 3]);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_model_ops',
    classUid: 6002,
    aiOperation: 'model_ops',
    typeUid: typeUidFor(6002, activityId),
    activityId,
    severityId: pick([1, 1, 2]),
    statusId: 1,
    riskLevel: pick(['low', 'low', 'medium']),
    provider: m.provider,
    model: m.id,
    source: 'aitf_model_ops_instrumentor',
    message: `Model ${opType}: ${m.provider}/${m.id}`,
    details: JSON.stringify({ operation_type: opType, model_version: `v${randInt(1, 5)}.${randInt(0, 9)}`, status: pick(['completed', 'in_progress', 'completed']), environment: pick(['production', 'staging', 'development']) }),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

function gen7010(hoursAgo: number) {
  const assetType = pick(['model', 'dataset', 'prompt_template', 'vector_db', 'mcp_server', 'agent', 'pipeline']);
  const activityId = pick([1, 2]);
  return {
    timestamp: makeTimestamp(hoursAgo),
    eventType: 'ai_asset_inventory',
    classUid: 5001,
    aiOperation: 'asset_inventory',
    typeUid: typeUidFor(5001, activityId),
    activityId,
    severityId: pick([1, 1, 2]),
    statusId: 1,
    riskLevel: pick(['low', 'low', 'medium']),
    source: 'aitf_asset_inventory',
    message: `Asset ${pick(['registered', 'discovered', 'audited'])}: ${assetType}`,
    details: JSON.stringify({ asset_type: assetType, asset_id: uuid(), risk_classification: pick(['high_risk', 'limited_risk', 'minimal_risk']), deployment_environment: pick(['production', 'staging', 'development']), audit_result: pick(['pass', 'pass', 'warning', 'fail']) }),
    compliance: makeCompliance(),
    traceId: traceId(),
    spanId: spanId(),
  };
}

async function main() {
  // Seed admin user
  const hashedPassword = await bcrypt.hash('johndoe123', 10);
  await prisma.user.upsert({
    where: { email: 'john@doe.com' },
    update: {},
    create: { email: 'john@doe.com', name: 'Admin User', password: hashedPassword, role: 'admin' },
  });

  // ── Always seed policies and storage (idempotent upserts) ──
  const POLICY_DEFS_EARLY = [
    { ruleId: 'AITF-DET-015', name: 'Malicious Skill/Plugin Loaded', severity: 'critical', threshold: { scan_skill_dirs: true, max_skill_files_per_window: 5, window_seconds: 300 } },
    { ruleId: 'AITF-DET-016', name: 'Unauthorized Messaging Channel', severity: 'high', threshold: { blocked_platforms: ['whatsapp', 'telegram'], allow_slack: true } },
    { ruleId: 'AITF-DET-017', name: 'Shell Command Execution', severity: 'high', threshold: { max_shell_commands: 5, window_seconds: 60 } },
    { ruleId: 'AITF-DET-018', name: 'Credential / Secret Access', severity: 'critical', threshold: { monitor_env_files: true, monitor_ssh_keys: true, monitor_cloud_creds: true } },
    { ruleId: 'AITF-DET-019', name: 'Cross-Platform Data Relay', severity: 'critical', threshold: { window_seconds: 300, require_both_ai_and_messaging: true } },
    { ruleId: 'AITF-DET-020', name: 'Unvetted Skill Installation', severity: 'high', threshold: { require_checksum_verification: true, allowed_skill_sources: [] } },
  ];
  for (const pol of POLICY_DEFS_EARLY) {
    await prisma.policy.upsert({
      where: { ruleId_orgId: { ruleId: pol.ruleId, orgId: '' } },
      update: { name: pol.name, severity: pol.severity, threshold: JSON.stringify(pol.threshold) },
      create: {
        name: pol.name,
        ruleId: pol.ruleId,
        enabled: true,
        severity: pol.severity,
        threshold: JSON.stringify(pol.threshold),
        action: pol.severity === 'critical' ? 'block' : 'alert',
        orgId: null,
      },
    }).catch(() => {
      return prisma.policy.create({
        data: {
          name: pol.name,
          ruleId: pol.ruleId,
          enabled: true,
          severity: pol.severity,
          threshold: JSON.stringify(pol.threshold),
          action: pol.severity === 'critical' ? 'block' : 'alert',
          orgId: null,
        },
      }).catch(() => { /* already exists */ });
    });
  }
  console.log('Ensured 6 new agent-specific detection policies exist.');

  // Check if CoSAI events exist already
  const existingCount = await prisma.event.count({ where: { classUid: { not: null } } });
  if (existingCount > 50) {
    console.log(`Already have ${existingCount} CoSAI events, skipping event seed.`);
    return;
  }

  // Generate CoSAI OCSF events — distribution mirrors real deployments
  const generators: Array<{ gen: (h: number) => any; count: number }> = [
    { gen: gen7001, count: 120 },  // Model Inference (30%)
    { gen: gen7002, count: 80 },   // Agent Activity (20%)
    { gen: gen7003, count: 60 },   // Tool Execution (15%)
    { gen: gen7004, count: 40 },   // Data Retrieval (10%)
    { gen: gen7005, count: 35 },   // Security Finding (8.75%)
    { gen: gen7006, count: 12 },   // Supply Chain (3%)
    { gen: gen7007, count: 25 },   // Governance (6.25%)
    { gen: gen7008, count: 28 },   // Identity (7%)
    { gen: gen7009, count: 25 },   // Model Operations
    { gen: gen7010, count: 15 },   // Asset Inventory
  ];

  let total = 0;
  for (const { gen, count } of generators) {
    for (let i = 0; i < count; i++) {
      const hoursAgo = Math.random() * 168; // last 7 days
      const data = gen(hoursAgo);
      await prisma.event.create({ data });
      total++;
    }
  }
  console.log(`Seeded ${total} AITF OCSF class-reuse events.`);

  // Generate CoSAI detection rule alerts. Detections are OCSF findings:
  // Detection Finding (2004) for all, except Supply Chain Compromise (2002).
  const DETECTION_RULES = [
    { ruleId: 'AITF-DET-001', name: 'Unusual Token Usage', owasp: 'LLM10', sev: 'medium', classUid: 2004, aiOperation: 'cost_anomaly' },
    { ruleId: 'AITF-DET-002', name: 'Model Switching Attack', owasp: null, sev: 'high', classUid: 2004, aiOperation: 'guardrail' },
    { ruleId: 'AITF-DET-003', name: 'Prompt Injection Attempt', owasp: 'LLM01', sev: 'critical', classUid: 2004, aiOperation: 'prompt_injection' },
    { ruleId: 'AITF-DET-005', name: 'Agent Loop Detection', owasp: null, sev: 'medium', classUid: 2004, aiOperation: 'guardrail' },
    { ruleId: 'AITF-DET-006', name: 'Unauthorized Agent Delegation', owasp: null, sev: 'high', classUid: 2004, aiOperation: 'permission_escalation' },
    { ruleId: 'AITF-DET-007', name: 'Agent Session Hijack', owasp: null, sev: 'critical', classUid: 2004, aiOperation: 'permission_escalation' },
    { ruleId: 'AITF-DET-009', name: 'MCP Server Impersonation', owasp: null, sev: 'critical', classUid: 2004, aiOperation: 'prompt_injection' },
    { ruleId: 'AITF-DET-010', name: 'Tool Permission Bypass', owasp: null, sev: 'high', classUid: 2004, aiOperation: 'permission_escalation' },
    { ruleId: 'AITF-DET-011', name: 'Data Exfiltration via Tools', owasp: 'LLM02', sev: 'critical', classUid: 2004, aiOperation: 'data_exfiltration' },
    { ruleId: 'AITF-DET-012', name: 'PII Exfiltration Chain', owasp: 'LLM02', sev: 'critical', classUid: 2004, aiOperation: 'data_exfiltration' },
    { ruleId: 'AITF-DET-013', name: 'Jailbreak Escalation', owasp: 'LLM01', sev: 'high', classUid: 2004, aiOperation: 'prompt_injection' },
    { ruleId: 'AITF-DET-014', name: 'Supply Chain Compromise', owasp: 'LLM03', sev: 'critical', classUid: 2002, aiOperation: 'supply_chain' },
  ];

  for (let i = 0; i < 30; i++) {
    const rule = pick(DETECTION_RULES);
    const hoursAgo = Math.random() * 168;
    await prisma.alert.create({
      data: {
        timestamp: makeTimestamp(hoursAgo),
        alertType: rule.name,
        severity: rule.sev,
        description: `${rule.ruleId}: ${rule.name} detected by CoSAI detection engine`,
        details: JSON.stringify({ rule_id: rule.ruleId, detection_method: pick(['pattern_match', 'statistical', 'behavioral']), affected_agent: pick(AGENTS).name }),
        resolved: Math.random() > 0.6,
        ruleId: rule.ruleId,
        owaspCategory: rule.owasp,
        classUid: rule.classUid,
        complianceRef: JSON.stringify({ nist_ai_rmf: ['MAP 1.1'], mitre_atlas: ['AML.T0043'] }),
      },
    });
  }
  console.log('Seeded 30 CoSAI detection rule alerts.');

  // ── Seed default policies (global, orgId=null) ──
  const POLICY_DEFS = [
    { ruleId: 'AITF-DET-001', name: 'Unusual Token Usage', severity: 'medium', threshold: { max_tokens_per_call: 50000, window_minutes: 10 } },
    { ruleId: 'AITF-DET-002', name: 'Model Switching Attack', severity: 'high', threshold: { max_model_switches: 5, window_minutes: 5 } },
    { ruleId: 'AITF-DET-003', name: 'Prompt Injection Attempt', severity: 'critical', threshold: { confidence_threshold: 0.85 } },
    { ruleId: 'AITF-DET-004', name: 'Excessive Cost Spike', severity: 'high', threshold: { cost_multiplier: 3.0, baseline_window_hours: 24 } },
    { ruleId: 'AITF-DET-005', name: 'Agent Loop Detection', severity: 'medium', threshold: { max_iterations: 20, window_minutes: 5 } },
    { ruleId: 'AITF-DET-006', name: 'Unauthorized Agent Delegation', severity: 'high', threshold: { allowed_delegation_depth: 2 } },
    { ruleId: 'AITF-DET-007', name: 'Agent Session Hijack', severity: 'critical', threshold: { max_session_switches: 3, window_minutes: 10 } },
    { ruleId: 'AITF-DET-008', name: 'Excessive Tool Calls', severity: 'medium', threshold: { max_calls: 100, window_minutes: 5 } },
    { ruleId: 'AITF-DET-009', name: 'MCP Server Impersonation', severity: 'critical', threshold: { fingerprint_mismatch: true } },
    { ruleId: 'AITF-DET-010', name: 'Tool Permission Bypass', severity: 'high', threshold: { monitor_sudo: true, monitor_fs_root: true } },
    { ruleId: 'AITF-DET-011', name: 'Data Exfiltration via Tools', severity: 'critical', threshold: { max_output_bytes: 1048576, sensitive_patterns: ['SSN', 'credit_card', 'api_key'] } },
    { ruleId: 'AITF-DET-012', name: 'PII Exfiltration Chain', severity: 'critical', threshold: { pii_types: ['email', 'phone', 'ssn', 'address'], max_pii_per_session: 5 } },
    { ruleId: 'AITF-DET-013', name: 'Jailbreak Escalation', severity: 'high', threshold: { confidence_threshold: 0.75, escalation_window_minutes: 30 } },
    { ruleId: 'AITF-DET-014', name: 'Supply Chain Compromise', severity: 'critical', threshold: { verify_checksums: true, allowed_registries: ['npm', 'pypi'] } },
    { ruleId: 'AITF-DET-015', name: 'Malicious Skill/Plugin Loaded', severity: 'critical', threshold: { scan_skill_dirs: true, max_skill_files_per_window: 5, window_seconds: 300 } },
    { ruleId: 'AITF-DET-016', name: 'Unauthorized Messaging Channel', severity: 'high', threshold: { blocked_platforms: ['whatsapp', 'telegram'], allow_slack: true } },
    { ruleId: 'AITF-DET-017', name: 'Shell Command Execution', severity: 'high', threshold: { max_shell_commands: 5, window_seconds: 60 } },
    { ruleId: 'AITF-DET-018', name: 'Credential / Secret Access', severity: 'critical', threshold: { monitor_env_files: true, monitor_ssh_keys: true, monitor_cloud_creds: true } },
    { ruleId: 'AITF-DET-019', name: 'Cross-Platform Data Relay', severity: 'critical', threshold: { window_seconds: 300, require_both_ai_and_messaging: true } },
    { ruleId: 'AITF-DET-020', name: 'Unvetted Skill Installation', severity: 'high', threshold: { require_checksum_verification: true, allowed_skill_sources: [] } },
  ];

  for (const pol of POLICY_DEFS) {
    await prisma.policy.upsert({
      where: { ruleId_orgId: { ruleId: pol.ruleId, orgId: '' } },
      update: { name: pol.name, severity: pol.severity, threshold: JSON.stringify(pol.threshold) },
      create: {
        name: pol.name,
        ruleId: pol.ruleId,
        enabled: true,
        severity: pol.severity,
        threshold: JSON.stringify(pol.threshold),
        action: pol.severity === 'critical' ? 'block' : 'alert',
        orgId: null,
      },
    }).catch(() => {
      // orgId=null unique constraint — try create only
      return prisma.policy.create({
        data: {
          name: pol.name,
          ruleId: pol.ruleId,
          enabled: true,
          severity: pol.severity,
          threshold: JSON.stringify(pol.threshold),
          action: pol.severity === 'critical' ? 'block' : 'alert',
          orgId: null,
        },
      }).catch(() => { /* already exists */ });
    });
  }
  console.log('Seeded 20 default CoSAI detection policies.');

  // ── Seed default storage config (global, orgId=null) ──
  const existingStorage = await prisma.storageConfig.findFirst({ where: { orgId: null } });
  if (!existingStorage) {
    await prisma.storageConfig.create({
      data: {
        retentionDays: 90,
        maxStorageMb: 5000,
        archiveEnabled: false,
        archiveAfterDays: 30,
        exportFormat: 'jsonl',
        autoCleanup: true,
        orgId: null,
      },
    });
    console.log('Seeded default storage configuration.');
  }
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
