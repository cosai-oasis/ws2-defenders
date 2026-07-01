#!/usr/bin/env bash
# Build an RPM. Inputs:
#   VERSION  — 0.2.0
#   ARCH     — x86_64 (default) | aarch64
#   BIN      — path to compiled adr-agent
#
# Output: dist/agentdr-${VERSION}-1.${dist}.${ARCH}.rpm
set -euo pipefail

VERSION="${VERSION:?VERSION required}"
ARCH="${ARCH:-x86_64}"
BIN="${BIN:?BIN required}"

TOPDIR="$(mktemp -d)"
mkdir -p "${TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p dist

# Stage payload as flat sources
cp "${BIN}"                                  "${TOPDIR}/SOURCES/adr-agent"
cp packaging/linux/systemd/agentdr.service   "${TOPDIR}/SOURCES/agentdr.service"

cat > "${TOPDIR}/SOURCES/config.toml" <<'EOF'
watch_directories = ["/home"]

[otlp]
enabled = true
bind = "127.0.0.1:4318"
redact_content = true

[mcp]
inventory_on_start = true
rescan_seconds = 600
EOF

cp packaging/linux/rpm/agentdr.spec "${TOPDIR}/SPECS/agentdr.spec"

rpmbuild \
  --define "_topdir ${TOPDIR}" \
  --define "_version ${VERSION}" \
  --define "_arch ${ARCH}" \
  --target "${ARCH}" \
  -bb "${TOPDIR}/SPECS/agentdr.spec"

find "${TOPDIR}/RPMS" -name '*.rpm' -exec cp -v {} dist/ \;
echo "RPMs in ./dist/"
