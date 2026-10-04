#!/usr/bin/env python3
"""Main entrypoint for Threat Information Harvester (API and Batch runner)."""

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
    from backend.pipeline import HarvesterPipeline

    check_interval = int(os.getenv("CHECK_INTERVAL_HOURS", "1"))
    direct_only = os.getenv("NOTIFY_DIRECT_ONLY", "false").lower() in ("true", "1", "yes")

    pipeline = HarvesterPipeline()
    summary = pipeline.run_all(lookback_hours=check_interval, notify_direct_only=direct_only)
    logger.info(f"Batch execution finished successfully: {summary}")


def run_api():
    """Run FastAPI REST API server."""
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info(f"Starting Threat Information Harvester API on http://{host}:{port}")
    uvicorn.run(
        "backend.api:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
        access_log=True,
    )


def main():
    mode = os.getenv("MODE", "api").lower()
    if mode == "batch" or "--batch" in sys.argv:
        run_batch()
    else:
        run_api()


if __name__ == "__main__":
    main()
