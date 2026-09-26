#!/usr/bin/env bash
set -e
source .venv/bin/activate

python3 -c "
from runtime.provisioning import ToolState
state = ToolState()

print('Beast Brain Tool Health')
print('=======================')
for name, data in state.state.items():
    status = data.get('status', 'UNKNOWN')
    print(f'[{status}] {name}')

health = state.get_overall_health()
print('\nSummary:')
print(f'  Ready: {health["ready"]}')
print(f'  Missing: {health["missing"]}')
print(f'  Failed: {health["failed"]}')
print(f'  Unsupported: {health["unsupported"]}')

if health["missing"] > 0 or health["failed"] > 0:
    print('\nHunter readiness:\n  PARTIAL')
else:
    print('\nHunter readiness:\n  READY')
"
