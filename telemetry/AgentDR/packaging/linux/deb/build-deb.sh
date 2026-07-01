#!/usr/bin/env bash
# Build a .deb for AgentDR. Inputs:
#   VERSION       — e.g. 0.2.0
#   ARCH          — amd64 (default) | arm64
#   BIN           — path to compiled adr-agent
#
# Output: dist/agentdr_${VERSION}_${ARCH}.deb
set -euo pipefail

VERSION="${VERSION:?VERSION required}"
ARCH="${ARCH:-amd64}"
BIN="${BIN:?BIN required}"

ROOT="$(mktemp -d)"
mkdir -p dist

# Standard layout
install -d "${ROOT}/usr/bin"
install -d "${ROOT}/lib/systemd/system"
install -d "${ROOT}/DEBIAN"

install -m 0755 "${BIN}" "${ROOT}/usr/bin/adr-agent"
install -m 0644 packaging/linux/systemd/agentdr.service "${ROOT}/lib/systemd/system/agentdr.service"

# Control + maintainer scripts; substitute architecture and version.
sed -e "s/^Version: .*/Version: ${VERSION}/" \
    -e "s/^Architecture: .*/Architecture: ${ARCH}/" \
    packaging/linux/deb/DEBIAN/control > "${ROOT}/DEBIAN/control"
install -m 0755 packaging/linux/deb/DEBIAN/postinst "${ROOT}/DEBIAN/postinst"
install -m 0755 packaging/linux/deb/DEBIAN/prerm    "${ROOT}/DEBIAN/prerm"

dpkg-deb --root-owner-group --build "${ROOT}" "dist/agentdr_${VERSION}_${ARCH}.deb"
echo "Wrote dist/agentdr_${VERSION}_${ARCH}.deb"
