#!/usr/bin/env bash
# Build a signed, notarized AgentDR .pkg for macOS (universal binary).
#
# Inputs (env):
#   VERSION             — agent version, e.g. 0.2.0
#   BIN_X86_64          — path to release adr-agent (x86_64)
#   BIN_ARM64           — path to release adr-agent (aarch64)
#   DEVELOPER_ID_INST   — Developer ID Installer cert common name (signing)
#   NOTARY_PROFILE      — keychain profile name for `notarytool` (notarization)
#
# Outputs:
#   ./dist/agentdr-${VERSION}.pkg  (signed; notarized if NOTARY_PROFILE is set)
#
# Run from the repo root.
set -euo pipefail

VERSION="${VERSION:?VERSION is required (e.g. 0.2.0)}"
BIN_X86_64="${BIN_X86_64:-target/x86_64-apple-darwin/release/adr-agent}"
BIN_ARM64="${BIN_ARM64:-target/aarch64-apple-darwin/release/adr-agent}"
PKG_ROOT="$(mktemp -d)"
BUILD_DIR="$(mktemp -d)"
OUT="dist/agentdr-${VERSION}.pkg"

mkdir -p dist

# Layout: payload installed verbatim from $PKG_ROOT
install -d "${PKG_ROOT}/usr/local/bin"
install -d "${PKG_ROOT}/Library/LaunchDaemons"
install -d "${PKG_ROOT}/etc/agentdr"

if [[ -f "${BIN_X86_64}" && -f "${BIN_ARM64}" ]]; then
  lipo -create -output "${PKG_ROOT}/usr/local/bin/adr-agent" "${BIN_X86_64}" "${BIN_ARM64}"
else
  # Fallback: ship whichever single arch we have.
  cp "${BIN_X86_64:-${BIN_ARM64}}" "${PKG_ROOT}/usr/local/bin/adr-agent"
fi
chmod 0755 "${PKG_ROOT}/usr/local/bin/adr-agent"
cp packaging/macos/LaunchDaemons/com.cosai.agentdr.plist "${PKG_ROOT}/Library/LaunchDaemons/"
chmod 0644 "${PKG_ROOT}/Library/LaunchDaemons/com.cosai.agentdr.plist"

# Scripts
install -d "${BUILD_DIR}/scripts"
cp packaging/macos/scripts/preinstall  "${BUILD_DIR}/scripts/preinstall"
cp packaging/macos/scripts/postinstall "${BUILD_DIR}/scripts/postinstall"
chmod 0755 "${BUILD_DIR}/scripts/preinstall" "${BUILD_DIR}/scripts/postinstall"

# Component package
pkgbuild \
  --root "${PKG_ROOT}" \
  --identifier ai.cosai.agentdr.pkg \
  --version "${VERSION}" \
  --scripts "${BUILD_DIR}/scripts" \
  --install-location / \
  "${BUILD_DIR}/agentdr-component.pkg"

# Distribution product
productbuild \
  --distribution packaging/macos/Distribution.xml \
  --package-path "${BUILD_DIR}" \
  --version "${VERSION}" \
  "${BUILD_DIR}/agentdr-unsigned.pkg"

# Signing
if [[ -n "${DEVELOPER_ID_INST:-}" ]]; then
  productsign --sign "${DEVELOPER_ID_INST}" "${BUILD_DIR}/agentdr-unsigned.pkg" "${OUT}"
else
  echo "WARN: DEVELOPER_ID_INST not set — shipping unsigned package."
  cp "${BUILD_DIR}/agentdr-unsigned.pkg" "${OUT}"
fi

# Notarization (optional)
if [[ -n "${NOTARY_PROFILE:-}" && -n "${DEVELOPER_ID_INST:-}" ]]; then
  xcrun notarytool submit "${OUT}" --keychain-profile "${NOTARY_PROFILE}" --wait
  xcrun stapler staple "${OUT}"
fi

echo "Wrote ${OUT}"
