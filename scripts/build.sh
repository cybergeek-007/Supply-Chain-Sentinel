#!/usr/bin/env bash
set -euo pipefail

echo "=== Building Supply Chain Sentinel ==="
echo "Target: Production Release"

if [[ "${OSTYPE:-}" != linux-gnu* ]]; then
  echo "Only Linux is supported by this build script."
  exit 1
fi

KERNEL_VERSION="$(uname -r | cut -d. -f1-2)"
if ! awk "BEGIN {exit !($KERNEL_VERSION >= 5.8)}"; then
  echo "Kernel 5.8+ required for eBPF support."
  exit 1
fi
echo "Kernel version: $(uname -r)"

for cmd in cmake clang python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing dependency: $cmd"
    exit 1
  fi
done
echo "System dependencies found."

rm -rf build
mkdir -p build
pushd build >/dev/null

echo "Building C++ entropy engine..."
cmake .. -DCMAKE_BUILD_TYPE=Release -DSCS_BUILD_CPP_CORE=ON
cmake --build . --config Release -j"$(nproc)"

popd >/dev/null

echo "Installing Python dependencies..."
python3 -m venv build/venv
source build/venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

echo "Verifying extension import..."
python -c "import sentinel_core; print('sentinel_core loaded')"

echo "=== Build Complete ==="
echo "Activate venv: source build/venv/bin/activate"

