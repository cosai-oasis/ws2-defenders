//! CoSAI ADR Agent — AI Detection & Response endpoint monitor.
//!
//! Rust implementation of the CoSAI ADR agent. Monitors processes, files, and
//! network connections for AI agent activity, ingests OpenTelemetry signals
//! from local AI runtimes (Claude Code, Codex CLI, Cursor, Aider), inventories
//! and wraps MCP servers, and emits AITF OCSF Class-Reuse events.

mod agents;
mod config;
mod detectors;
mod discovery;
mod engine;
mod exporters;
mod hooks;
mod ingest;
mod integrity;
mod mcp;
mod models;
mod monitors;
mod policy;
mod proxy;
mod shell;
mod storage;
mod watchdog;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "adr-agent", version, about = "CoSAI ADR Agent — AI Detection & Response")]
struct Cli {
    /// Root directory for agent data (config, logs, runtime).
    #[arg(short, long, default_value = ".", global = true)]
    root: PathBuf,

    /// Path to config file (TOML). Defaults to <root>/config.toml.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the agent (default).
    Start {
        /// Disable stdout streaming of events.
        #[arg(long, default_value_t = false)]
        quiet: bool,

        /// Watch directories (can be repeated). Overrides config file.
        #[arg(short, long)]
        watch: Vec<String>,
    },

    /// Verify SHA-256 integrity of the community rule pack.
    Verify,

    /// Download the latest community rule pack and verify it.
    Update,

    /// Manage runtime hooks for local AI agents (Tier 1).
    #[command(subcommand)]
    Hooks(HooksCmd),

    /// Inspect or wrap Model Context Protocol (MCP) servers (Tier 1).
    #[command(subcommand)]
    Mcp(McpCmd),

    /// Run a standalone OTLP ingest server (Tier 1).
    Otlp {
        /// Bind address (default 127.0.0.1:4318).
        #[arg(long, default_value = "127.0.0.1:4318")]
        bind: String,
    },

    /// Inspect or test the policy pack (Tier 5).
    #[command(subcommand)]
    Policy(PolicyCmd),

    /// Record an interactive command session (Tier 6).
    ///
    /// Use as: adr-agent shell wrap --name claude-bash -- bash -c "<cmd>"
    Shell {
        #[command(subcommand)]
        action: ShellCmd,
    },

    /// Multi-tool agent inventory (Tier 7).
    Agents {
        #[command(subcommand)]
        action: AgentsCmd,
    },

    /// Auto-discover AI agents on the host (Tier 8).
    Discovery {
        #[command(subcommand)]
        action: DiscoveryCmd,
    },

    /// Run the inline blocking HTTP CONNECT proxy in standalone mode (Tier 5).
    Proxy {
        /// Bind address (default 127.0.0.1:8080).
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        /// Allow-list (substring match, repeatable).
        #[arg(long)]
        allow: Vec<String>,
    },

    /// Run the LLM Guard reverse proxy in standalone mode (Tier 9).
    ///
    /// Fronts local model backends (Ollama, LM Studio, llama.cpp) using the
    /// `[llm_guard]` config block. Authenticates + rate-limits callers, scans
    /// request bodies for prompt-injection / PII, tracks token usage, probes
    /// upstream health (`GET /healthz`), and emits OCSF/AITF events as JSONL.
    LlmGuard {
        /// Listen address override (defaults to `[llm_guard].listen_address`).
        #[arg(long)]
        listen: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// List loaded policies as JSON.
    List,
    /// Evaluate the policy pack against an event read from --file or stdin.
    Test {
        /// Path to a JSON file containing one EventRecord. If omitted, stdin is used.
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum AgentsCmd {
    /// Show every supported AI agent on this host: binary on $PATH,
    /// hook-install state, configured MCP servers, currently running PIDs.
    List {
        /// Emit JSON instead of the human-readable table.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DiscoveryCmd {
    /// Run a one-shot scan. Reports only by default; pass --apply to
    /// honour the configured [discovery].mode (policy / automatic /
    /// interactive / off).
    Scan {
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Also apply per the [discovery].mode (install hooks, record
        /// decisions). Safe to run repeatedly; idempotent.
        #[arg(long, default_value_t = false)]
        apply: bool,
        /// OTLP endpoint hooks should point at when installing
        /// (default http://127.0.0.1:4318).
        #[arg(long, default_value = "http://127.0.0.1:4318")]
        endpoint: String,
    },
    /// Interactive prompt loop: ask the local user about every
    /// newly-discovered agent that doesn't already have a recorded
    /// decision. Refuses to run without a TTY.
    Prompt {
        #[arg(long, default_value = "http://127.0.0.1:4318")]
        endpoint: String,
    },
    /// Print recorded decisions from the state file.
    Status {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ShellCmd {
    /// Wrap a command, logging stdin/stdout/stderr as ai_operation=tool_execution (API Activity 6003) events.
    Wrap {
        /// Logical session name to record in events.
        #[arg(long)]
        name: String,
        /// Command to execute (mandatory). Provide after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum HooksCmd {
    /// Install hooks for one or all supported AI runtimes.
    Install {
        /// Target: claude-code | cursor | codex | aider | opencode | all
        target: String,
        /// OTLP endpoint hooks should send to. Default http://127.0.0.1:4318
        #[arg(long, default_value = "http://127.0.0.1:4318")]
        endpoint: String,
    },
    /// Remove hooks previously installed by AgentDR.
    Uninstall {
        /// Target: claude-code | cursor | codex | aider | opencode | all
        target: String,
    },
    /// Print install status for all supported runtimes.
    Status,
}

#[derive(Subcommand, Debug)]
enum McpCmd {
    /// Discover and emit MCP server configuration across the host.
    Inventory {
        /// Emit one JSONL event line per discovered server to stdout.
        #[arg(long, default_value_t = false)]
        jsonl: bool,
    },
    /// stdio-proxy an MCP server: log every JSON-RPC message to AgentDR.
    ///
    /// Use as: adr-agent mcp wrap --name my-server -- <server-binary> [args...]
    Wrap {
        /// Logical server name to record in events.
        #[arg(long)]
        name: String,
        /// Command to execute (mandatory). Provide after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("adr_agent=info,axum=info,tower_http=info")),
        )
        .with_target(false)
        .init();

    let config_path = cli.config.clone().unwrap_or_else(|| cli.root.join("config.toml"));

    match cli.command.unwrap_or(Command::Start { quiet: false, watch: Vec::new() }) {
        Command::Verify => {
            let ri = integrity::RuleIntegrity::discover();
            let status = ri.status();
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            if status.integrity != "ok" {
                std::process::exit(1);
            }
        }

        Command::Update => {
            let ri = integrity::RuleIntegrity::discover();
            let result = ri.update(true);
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            if result.status == "integrity_failed" || result.status == "error" {
                std::process::exit(1);
            }
        }

        Command::Hooks(HooksCmd::Install { target, endpoint }) => {
            if let Err(e) = hooks::install(&target, &endpoint) {
                eprintln!("install failed: {e}");
                std::process::exit(1);
            }
        }
        Command::Hooks(HooksCmd::Uninstall { target }) => {
            if let Err(e) = hooks::uninstall(&target) {
                eprintln!("uninstall failed: {e}");
                std::process::exit(1);
            }
        }
        Command::Hooks(HooksCmd::Status) => {
            let s = hooks::status();
            println!("{}", serde_json::to_string_pretty(&s).unwrap());
        }

        Command::Mcp(McpCmd::Inventory { jsonl }) => {
            let inv = mcp::inventory::scan();
            if jsonl {
                for ev in &inv.events {
                    println!("{}", serde_json::to_string(ev).unwrap());
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&inv).unwrap());
            }
        }
        Command::Mcp(McpCmd::Wrap { name, cmd }) => {
            // Resolve event-log target inside <root>/<config.storage.events_path>.
            let cfg = config::Config::load(&config_path);
            let log_path = cli.root.join(&cfg.storage.events_path);
            match mcp::intercept::run(&name, &cmd, &log_path).await {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("mcp wrap failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Otlp { bind } => {
            let cfg = config::Config::load(&config_path);
            let log_path = cli.root.join(&cfg.storage.events_path);
            ingest::otlp::serve_standalone(&bind, &log_path).await;
        }

        Command::Policy(PolicyCmd::List) => {
            let engine = policy::PolicyEngine::load_default();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "source":   engine.source().display().to_string(),
                    "count":    engine.len(),
                    "policies": engine.len(),
                })).unwrap()
            );
        }
        Command::Policy(PolicyCmd::Test { file }) => {
            let raw = match file {
                Some(p) => std::fs::read_to_string(&p).unwrap_or_default(),
                None => {
                    use std::io::Read;
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s).ok();
                    s
                }
            };
            let ev: models::EventRecord = match serde_json::from_str(&raw) {
                Ok(e) => e,
                Err(e) => { eprintln!("policy test: invalid EventRecord JSON: {e}"); std::process::exit(2); }
            };
            let engine = policy::PolicyEngine::load_default();
            let decision = engine.evaluate(&ev);
            println!("{}", serde_json::to_string_pretty(&decision).unwrap());
            if matches!(decision.action, policy::Action::Block) {
                std::process::exit(1);
            }
        }

        Command::Agents { action: AgentsCmd::List { json } } => {
            let inv = agents::list();
            if json {
                println!("{}", serde_json::to_string_pretty(&inv).unwrap());
            } else {
                print!("{}", agents::render_table(&inv));
            }
        }

        Command::Discovery { action: DiscoveryCmd::Scan { json, apply, endpoint } } => {
            let cfg = config::Config::load(&config_path);
            if apply {
                let rep = discovery::scan_and_apply(&cfg.discovery, &cli.root, &endpoint);
                if json {
                    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                } else {
                    print!("{}", discovery::scan::render_table(&rep.scanned));
                    println!();
                    println!("Mode: {}", rep.mode);
                    for row in &rep.actions {
                        println!("  {:<13} → {:?}  ({})  result={:?}",
                                 row.agent_id, row.action, row.from, row.result);
                    }
                }
            } else {
                let rep = discovery::scan_only();
                if json {
                    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
                } else {
                    print!("{}", discovery::scan::render_table(&rep));
                }
            }
        }

        Command::Discovery { action: DiscoveryCmd::Prompt { endpoint } } => {
            let cfg = config::Config::load(&config_path);
            let rep = discovery::scan_only();
            let state_path = cli.root.join(&cfg.discovery.state_file);
            match discovery::prompt::run(&rep, &endpoint, &state_path) {
                Ok(n) => println!("\ndiscovery: installed {} hook(s); state saved to {}", n, state_path.display()),
                Err(e) => { eprintln!("discovery prompt failed: {e}"); std::process::exit(1); }
            }
        }

        Command::Discovery { action: DiscoveryCmd::Status { json } } => {
            let cfg = config::Config::load(&config_path);
            let state_path = cli.root.join(&cfg.discovery.state_file);
            let st = discovery::state::DiscoveryState::load(&state_path).unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&st).unwrap());
            } else if st.decisions.is_empty() {
                println!("(no decisions recorded — run `adr-agent discovery scan --apply` or `discovery prompt`)");
            } else {
                println!("AGENT          DECISION  SOURCE        DECIDED AT");
                println!("─────────────  ────────  ────────────  ───────────────────────");
                for (id, d) in &st.decisions {
                    println!("{:<13}  {:<8}  {:<12}  {}", id, d.decision, d.source, d.decided_at);
                }
            }
        }

        Command::Shell { action: ShellCmd::Wrap { name, cmd } } => {
            let cfg = config::Config::load(&config_path);
            let log_path = cli.root.join(&cfg.storage.events_path);
            match shell::run(&name, &cmd, &log_path).await {
                Ok(code) => std::process::exit(code),
                Err(e) => { eprintln!("shell wrap failed: {e}"); std::process::exit(1); }
            }
        }

        Command::Proxy { bind, allow } => {
            let engine = std::sync::Arc::new(policy::PolicyEngine::load_default());
            let cfg = config::Config::load(&config_path);
            let log_path = cli.root.join(&cfg.storage.events_path);
            // Standalone proxy: writes JSONL directly, no engine bus.
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<models::EventRecord>();
            let log_path_w = log_path.clone();
            tokio::spawn(async move {
                if let Some(parent) = log_path_w.parent() { let _ = std::fs::create_dir_all(parent); }
                while let Some(ev) = rx.recv().await {
                    if let Ok(line) = serde_json::to_string(&ev) {
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path_w) {
                            use std::io::Write;
                            let _ = writeln!(f, "{}", line);
                        }
                    }
                }
            });
            let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
            // Start from the config's [proxy] settings (auth / rate limits /
            // provenance) and override bind + allowlist with the CLI args.
            let mut proxy_cfg = cfg.proxy.clone();
            proxy_cfg.bind = bind;
            proxy_cfg.allowlist = allow;
            let prx = proxy::InlineProxy::from_config(&proxy_cfg, engine, tx);
            prx.run(sd_rx).await;
        }

        Command::LlmGuard { listen } => {
            let cfg = config::Config::load(&config_path);
            let log_path = cli.root.join(&cfg.storage.events_path);
            // Standalone reverse proxy: writes JSONL directly, no engine bus.
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<models::EventRecord>();
            let log_path_w = log_path.clone();
            tokio::spawn(async move {
                if let Some(parent) = log_path_w.parent() { let _ = std::fs::create_dir_all(parent); }
                while let Some(ev) = rx.recv().await {
                    if let Ok(line) = serde_json::to_string(&ev) {
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path_w) {
                            use std::io::Write;
                            let _ = writeln!(f, "{}", line);
                        }
                    }
                }
            });
            // Start from the config's [llm_guard] settings (backends / auth /
            // rate limits / monitoring). Force-enable for the standalone run and
            // honour an optional --listen override.
            let mut lg_cfg = cfg.llm_guard.clone();
            lg_cfg.enabled = true;
            if let Some(addr) = listen {
                lg_cfg.listen_address = addr;
            }
            if lg_cfg.backends.is_empty() {
                eprintln!("llm-guard: no backends configured under [llm_guard]; nothing to protect");
                std::process::exit(2);
            }
            let (_sd_tx, sd_rx) = tokio::sync::watch::channel(false);
            proxy::reverse::serve(&lg_cfg, tx, sd_rx).await;
        }

        Command::Start { quiet, watch } => {
            // Startup integrity check
            let ri = integrity::RuleIntegrity::discover();
            match ri.verify() {
                Ok(status) => tracing::info!(version = %status.version, "Community rules integrity check passed"),
                Err(msg) => {
                    tracing::warn!("Community rules integrity issue: {}", msg);
                    tracing::info!("Attempting automatic rule update...");
                    let result = ri.update(false);
                    tracing::info!(status = %result.status, "Auto-update result");
                }
            }

            // Load config
            let mut cfg = config::Config::load(&config_path);

            // CLI overrides
            if !watch.is_empty() {
                cfg.watch_directories = watch;
            }

            tracing::info!(
                root = %cli.root.display(),
                watch_dirs = ?cfg.watch_directories,
                detection_rules = 20,
                otlp_enabled = cfg.otlp.enabled,
                openshell_ingest = cfg.openshell.enabled,
                mcp_inventory_on_start = cfg.mcp.inventory_on_start,
                "CoSAI ADR Agent v{} (Rust) — AITF OCSF Class-Reuse",
                env!("CARGO_PKG_VERSION"),
            );

            let engine = engine::AgentEngine::new(cli.root, cfg, !quiet);
            engine.run().await;
        }
    }
}
