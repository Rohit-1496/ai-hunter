#!/usr/bin/env bash
set -e

echo "Starting Beast Brain Bootstrap..."
echo "1. Inspecting environment..."
echo "OS: $(uname -s)"
echo "Arch: $(uname -m)"

echo "2. Checking Python & Virtual Environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q pyyaml

echo "3. Provisioning Security Tools..."
./scripts/provision_tools.sh

echo "4. Configuring OpenCode integration..."
python3 -c "
from runtime.provisioning import OpenCodeIntegration
oc = OpenCodeIntegration()
oc.configure()
print('OpenCode integration configured.')
"

echo "5. Generating tool status..."
./scripts/check_tools.sh || true

echo "Bootstrap complete."
