Name:           agentdr
Version:        %{?_version}%{!?_version:0.2.0}
Release:        1%{?dist}
Summary:        AgentDR — AI Agent Detection & Response endpoint agent
License:        ASL 2.0
URL:            https://github.com/girdav01/agentdr
BuildArch:      %{?_arch}%{!?_arch:x86_64}
Requires:       glibc
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

# Pre-built binaries come in from the CI workflow; we don't rebuild from source
# inside the rpm.
%description
AgentDR monitors local AI runtimes (Claude Code, Cursor, Codex CLI, Aider,
OpenClaw, etc.) on the endpoint, accepts OpenTelemetry signals on the loopback
OTLP endpoint, inventories and intercepts Model Context Protocol (MCP)
servers, and ships normalised CoSAI AI Telemetry Framework events
(OCSF Category 7) to any SIEM.

%prep
# nothing — files installed directly from %{_sourcedir} in %install

%install
install -d %{buildroot}/usr/bin
install -d %{buildroot}/usr/lib/systemd/system
install -d %{buildroot}/etc/agentdr
install -m 0755 %{_sourcedir}/adr-agent             %{buildroot}/usr/bin/adr-agent
install -m 0644 %{_sourcedir}/agentdr.service       %{buildroot}/usr/lib/systemd/system/agentdr.service
install -m 0644 %{_sourcedir}/config.toml           %{buildroot}/etc/agentdr/config.toml

%pre
getent group agentdr  >/dev/null || groupadd --system agentdr
getent passwd agentdr >/dev/null || useradd --system --gid agentdr --home-dir /var/lib/agentdr --shell /sbin/nologin agentdr
exit 0

%post
install -d -m 0755 -o agentdr -g agentdr /var/lib/agentdr /var/log/agentdr
%systemd_post agentdr.service
systemctl enable agentdr.service  >/dev/null 2>&1 || true
systemctl restart agentdr.service >/dev/null 2>&1 || true

%preun
%systemd_preun agentdr.service

%postun
%systemd_postun_with_restart agentdr.service

%files
%attr(0755,root,root) /usr/bin/adr-agent
%attr(0644,root,root) /usr/lib/systemd/system/agentdr.service
%config(noreplace) %attr(0644,root,root) /etc/agentdr/config.toml

%changelog
* Fri May 16 2026 CoSAI Community <agentdr@cosai.dev> - 0.2.0-1
- Add OTLP/HTTP ingest, runtime hooks (Claude Code/Cursor/Codex/Aider),
  MCP server inventory and stdio-proxy.
