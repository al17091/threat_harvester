#!/usr/bin/env python3
"""Main entrypoint for Kubernetes CronJob execution."""

import logging
import os
import sys

from src.pipeline import HarvesterPipeline

# Configure root logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("watchdog")


def main():
    logger.info("Threat Information Harvester starting batch execution...")
    check_interval = int(os.getenv("CHECK_INTERVAL_HOURS", "1"))
    direct_only = os.getenv("NOTIFY_DIRECT_ONLY", "false").lower() in ("true", "1", "yes")

    pipeline = HarvesterPipeline()
    summary = pipeline.run_all(lookback_hours=check_interval, notify_direct_only=direct_only)

    logger.info(f"Execution finished successfully: {summary}")


if __name__ == "__main__":
    main()
