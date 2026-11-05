#!/usr/bin/env bash
set -e

BUILD_DIR="/tmp/carerail_contract_build"
SRC_DIR="/mnt/c/AI/project_carerail/contract"
OUT_DIR="/mnt/c/AI/project_carerail/contract/build"

echo "[1] Setting up build workspace in $BUILD_DIR..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/src"

cp "$SRC_DIR/package.json" "$BUILD_DIR/"
cp "$SRC_DIR/src/index.js" "$BUILD_DIR/src/"

cd "$BUILD_DIR"
echo "[2] Installing near-sdk-js on Linux..."
npm install near-sdk-js@2.0.0 --save-dev --silent

echo "[3] Compiling PolicyVault to WebAssembly (WASM)..."
npx near-sdk-js build src/index.js build/policy_vault.wasm

echo "[4] Copying compiled WASM artifact to Windows workspace..."
mkdir -p "$OUT_DIR"
cp build/policy_vault.wasm "$OUT_DIR/policy_vault.wasm"
cp build/policy_vault.js "$OUT_DIR/policy_vault.js" || true

echo "[+] Compilation successful! Size: $(wc -c < "$OUT_DIR/policy_vault.wasm") bytes"
