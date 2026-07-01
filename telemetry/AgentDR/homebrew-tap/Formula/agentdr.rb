# Homebrew formula for AgentDR.
#
# Distribute via a tap:
#   brew tap girdav01/agentdr https://github.com/girdav01/agentdr
#   brew install girdav01/agentdr/agentdr
#
# The SHA-256 values below are placeholders; the GitHub release workflow
# (.github/workflows/release.yml) rewrites them on every release.
class Agentdr < Formula
  desc "AI Agent Detection & Response endpoint telemetry agent (CoSAI / AITF)"
  homepage "https://github.com/girdav01/agentdr"
  version "0.2.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/girdav01/agentdr/releases/download/v#{version}/adr-agent-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/girdav01/agentdr/releases/download/v#{version}/adr-agent-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/girdav01/agentdr/releases/download/v#{version}/adr-agent-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/girdav01/agentdr/releases/download/v#{version}/adr-agent-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "adr-agent"
    (etc/"agentdr").mkpath
    (var/"lib/agentdr").mkpath
    (var/"log/agentdr").mkpath
    (etc/"agentdr/config.toml").write <<~EOS
      watch_directories = ["#{Dir.home}"]

      [otlp]
      enabled = true
      bind = "127.0.0.1:4318"
      redact_content = true

      [mcp]
      inventory_on_start = true
      rescan_seconds = 600
    EOS
  end

  service do
    run [opt_bin/"adr-agent", "start", "--root", var/"lib/agentdr",
         "--config", etc/"agentdr/config.toml", "--quiet"]
    keep_alive true
    log_path var/"log/agentdr/stdout.log"
    error_log_path var/"log/agentdr/stderr.log"
    environment_variables RUST_LOG: "adr_agent=info"
  end

  test do
    system "#{bin}/adr-agent", "--version"
    system "#{bin}/adr-agent", "verify"
  end
end
