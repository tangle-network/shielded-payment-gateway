#!/usr/bin/env bash
# Setup script for shielded payments dependencies.
# Run this after cloning the repo.
#
# All Solidity dependencies are soldeer-managed (see foundry.toml [dependencies]):
#   - @openzeppelin-contracts 5.1.0      -> repo-wide (gateway contracts, tests)
#   - @openzeppelin-contracts-4 4.9.6    -> protocol-solidity only, via the context
#     remapping in remappings.txt (protocol-solidity was audited against OZ 4.x and
#     imports paths removed/moved in OZ 5.x)
#   - forge-std 1.9.4
# Nothing is written into the soldeer-managed directories, so re-running
# `forge soldeer install`/`update` at any time is safe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Setting up shielded payments dependencies..."

echo "  Running soldeer update..."
cd "$ROOT_DIR"
forge soldeer update

echo "  Initializing protocol-solidity submodule..."
git submodule update --init dependencies/protocol-solidity

echo "  Done! Run 'forge build' to verify compilation."
