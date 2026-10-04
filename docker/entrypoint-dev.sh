#!/usr/bin/env bash
set -e

# Start Tor service in background if tor is installed and TOR_START_DAEMON is true or default
if command -v tor >/dev/null 2>&1 && [ "${ENABLE_LOCAL_TOR:-false}" = "true" ]; then
    echo "[*] Starting local Tor daemon..."
    tor --RunAsDaemon 1 || echo "[!] Tor daemon warning: could not launch background Tor"
fi

# Link harvester cli to /usr/local/bin if not present
if [ ! -f /usr/local/bin/harvester ]; then
    ln -sf /app/bin/harvester /usr/local/bin/harvester
    chmod +x /usr/local/bin/harvester
fi

exec "$@"
