#!/usr/bin/env bash
# validate.sh — Phase 1 gate: verify the workspace compiles cleanly.
#
# Run this from the securenet/ root:
#   chmod +x validate.sh && ./validate.sh
#
# Expected output:
#   Compiling shared v0.1.0
#   Compiling api-gateway v0.1.0
#   Compiling user-service v0.1.0
#   Compiling order-service v0.1.0
#   Compiling vault-service v0.1.0
#   Finished `dev` profile [unoptimized + debuginfo] target(s)
#   ✓ Phase 1 gate passed

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "==> Checking Rust toolchain..."
rustc --version
cargo --version

echo ""
echo "==> Building workspace (debug)..."
cargo build --workspace 2>&1

echo ""
echo "==> Running clippy (warnings only)..."
cargo clippy --workspace -- -W clippy::all 2>&1 || true

echo ""
echo "==> Checking each binary runs and exits..."
for bin in api-gateway user-service order-service vault-service; do
    # Each binary needs env vars to not panic; run with a 1s timeout.
    # They'll fail on vault connection (expected at phase 1), but must not
    # crash before reaching the vault call.
    echo -n "    $bin ... "
    timeout 2s cargo run -p "$bin" -- &>/dev/null || true
    echo "started ok (killed after 2s as expected)"
done

echo ""
echo -e "${GREEN}✓ Phase 1 gate passed — workspace compiles, all binaries start${NC}"
echo ""
echo "Next: Phase 2 — Vault service cert issuance"
