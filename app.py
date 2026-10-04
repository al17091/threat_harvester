#!/usr/bin/env python3
"""Main entrypoint for Information Harvester (Web Dashboard and Batch runner)."""

import logging
import os
import sys

import uvicorn

# Configure root logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger("information_harvester")


def run_batch():
    """Run batch harvesting pipeline for scheduled jobs."""
    logger.info("Threat Information Harvester starting batch execution...")
    from src.pipeline import HarvesterPipeline

    check_interval = int(os.getenv("CHECK_INTERVAL_HOURS", "1"))
    direct_only = os.getenv("NOTIFY_DIRECT_ONLY", "false").lower() in ("true", "1", "yes")

    pipeline = HarvesterPipeline()
    summary = pipeline.run_all(lookback_hours=check_interval, notify_direct_only=direct_only)
    logger.info(f"Batch execution finished successfully: {summary}")


def run_web():
    """Run FastAPI Web Dashboard server."""
    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info(f"Starting Threat Information Harvester Web Dashboard on http://{host}:{port}")
    uvicorn.run(
        "src.web.app:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
        access_log=True,
    )


def main():
    mode = os.getenv("MODE", "web").lower()
    if mode == "batch" or "--batch" in sys.argv:
        run_batch()
    else:
        run_web()


if __name__ == "__main__":
    main()
