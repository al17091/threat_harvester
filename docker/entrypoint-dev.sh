#!/usr/bin/env bash
set -e

# Link harvester cli to /usr/local/bin if not present
if [ ! -f /usr/local/bin/harvester ]; then
    ln -sf /app/bin/harvester /usr/local/bin/harvester
    chmod +x /usr/local/bin/harvester
fi

exec "$@"
