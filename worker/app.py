#!/usr/bin/env python3
"""Main entrypoint for the Threat Information Harvester batch runner."""

import logging
import os
import sys

# Configure root logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("threat_harvester")


def run_batch():
    """Run batch harvesting pipeline for scheduled jobs."""
    logger.info("Threat Information Harvester starting batch execution...")
    from worker.pipeline import HarvesterPipeline

    check_interval = int(os.getenv("CHECK_INTERVAL_HOURS", "1"))
    direct_only = os.getenv("NOTIFY_DIRECT_ONLY", "false").lower() in ("true", "1", "yes")

    pipeline = HarvesterPipeline()
    summary = pipeline.run_all(lookback_hours=check_interval, notify_direct_only=direct_only)
    logger.info(f"Batch execution finished successfully: {summary}")


def main():
    mode = os.getenv("MODE", "batch").lower()
    if mode != "batch" and "--batch" not in sys.argv:
        logger.error(
            f"MODE={mode} is not supported: the Python API was retired. Use the Go API (api/) instead."
        )
        sys.exit(2)
    run_batch()


if __name__ == "__main__":
    main()
