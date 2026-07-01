#!/usr/bin/env bash
# Regenerate checksums.sha256 manifest for CoSAI Community rule files.
# Run from the cosai-community/ directory.
set -euo pipefail
cd "$(dirname "$0")/.."

FILES=(
  rules/agent-signatures.json
  rules/ai-endpoints.json
  rules/messaging-endpoints.json
  policies/detection-rules.json
)

> checksums.sha256
for f in "${FILES[@]}"; do
  sha256sum "$f" >> checksums.sha256
done

echo "✓ Generated checksums.sha256 with ${#FILES[@]} entries"
cat checksums.sha256
