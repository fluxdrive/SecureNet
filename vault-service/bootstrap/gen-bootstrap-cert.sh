#!/usr/bin/env bash
# gen-bootstrap-cert.sh
#
# Generates the SecureNet root CA used by the vault service.
# Run this ONCE before building the vault Docker image.
#
# Output files (written to this directory):
#   ca.pem       — Root CA certificate (public, safe to distribute)
#   ca-key.pem   — Root CA private key  (SECRET — never commit this)
#
# Usage:
#   cd vault-service/bootstrap
#   chmod +x gen-bootstrap-cert.sh
#   ./gen-bootstrap-cert.sh
#
# The generated ca.pem is baked into the vault Docker image.
# The ca-key.pem is mounted as a Kubernetes Secret at runtime.
# Neither file is committed to source control (.gitignore covers them).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}==> Generating SecureNet Root CA${NC}"

# ── Check dependencies ────────────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
    echo -e "${RED}Error: openssl not found. Install with: sudo pacman -S openssl${NC}"
    exit 1
fi

# ── Refuse to overwrite existing keys ─────────────────────────────────────────
if [[ -f "$OUT_DIR/ca-key.pem" ]]; then
    echo -e "${YELLOW}Warning: ca-key.pem already exists.${NC}"
    read -rp "Overwrite? This will invalidate all previously issued certs. [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# ── Generate CA private key (EC P-384) ────────────────────────────────────────
echo "  Generating CA private key (EC P-384)..."
openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-384 \
    -out "$OUT_DIR/ca-key.pem"

chmod 600 "$OUT_DIR/ca-key.pem"

# ── Generate self-signed CA certificate (10-year validity) ────────────────────
echo "  Generating self-signed CA certificate..."
openssl req \
    -new -x509 \
    -key    "$OUT_DIR/ca-key.pem" \
    -out    "$OUT_DIR/ca.pem" \
    -days   3650 \
    -subj   "/CN=SecureNet Root CA/O=SecureNet" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

# ── Verify ────────────────────────────────────────────────────────────────────
echo "  Verifying..."
openssl x509 -in "$OUT_DIR/ca.pem" -noout -text | grep -E "Subject:|Validity|Not (Before|After)"

echo ""
echo -e "${GREEN}✓ Bootstrap CA generated:${NC}"
echo "   ca.pem      — bake into vault Docker image (public)"
echo "   ca-key.pem  — mount as Kubernetes Secret (KEEP SECRET)"
echo ""
echo -e "${YELLOW}  IMPORTANT: ca-key.pem is in .gitignore — never commit it.${NC}"
echo "  Add it to your secrets manager or pass as K8s Secret:"
echo ""
echo "  kubectl create secret generic vault-ca-key \\"
echo "      --from-file=ca-key.pem=$OUT_DIR/ca-key.pem \\"
echo "      -n securenet"
