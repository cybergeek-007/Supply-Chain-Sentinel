#!/bin/bash
# Sentinel sandbox entrypoint
# Runs npm install under strace to capture all syscalls.
# Strace output goes to /sandbox/trace/strace.log
# npm stdout/stderr go to normal stdout/stderr.

set -euo pipefail

PKG_PATH="${1:-/sandbox/pkg}"
TRACE_OUT="/sandbox/trace/strace.log"
INSTALL_DIR="/sandbox/install"

# Initialize a minimal package.json
cd "$INSTALL_DIR"
echo '{"name":"sentinel-sandbox","private":true}' > package.json

# Run npm install under strace
# -f  = follow forks (child processes)
# -e trace=network,file,process = only trace relevant syscall categories
# -o  = output to file (keeps npm output clean on stdout/stderr)
# -tt = timestamps with microseconds
# -s 256 = show 256 chars of string arguments
exec strace -f -tt -s 256 \
    -e trace=network,file,process \
    -o "$TRACE_OUT" \
    -- npm install --ignore-scripts=false \
                   --no-audit \
                   --no-fund \
                   --no-save \
                   "$PKG_PATH"
