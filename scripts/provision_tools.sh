#!/usr/bin/env bash
set -e

source .venv/bin/activate

python3 -c "
from runtime.provisioning import ToolManifest, ToolState, ToolVerifier, ToolInstaller
manifest = ToolManifest()
state = ToolState()
verifier = ToolVerifier()
installer = ToolInstaller()

for t in manifest.get_all_tools():
    print(f'Checking {t["name"]}...')
    res = installer.install(t)
    state.update_tool(t["name"], res)
    print(f'  Status: {res["status"]}')

print('Provisioning finished.')
"
