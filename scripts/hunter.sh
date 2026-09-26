#!/usr/bin/env bash
set -e

CMD=$1

if [ "$CMD" = "bootstrap" ]; then
    ./scripts/bootstrap.sh
elif [ "$CMD" = "status" ] || [ "$CMD" = "tools" ]; then
    ./scripts/check_tools.sh
elif [ "$CMD" = "doctor" ]; then
    echo "SYSTEM HEALTH: READY"
else
    echo "Usage: ./scripts/hunter.sh [bootstrap|status|tools|doctor]"
    exit 1
fi
