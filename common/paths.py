"""Stable paths and CSV schemas shared by the project."""

from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT_DIR / "logs"
DATA_DIR = ROOT_DIR / "data"
ACTIVITY_LOG = LOG_DIR / "activity_log.csv"
AI_RESULTS_LOG = LOG_DIR / "ai_results.csv"

ACTIVITY_COLUMNS = [
    "timestamp",
    "pid",
    "process_name",
    "cpu_usage",
    "memory_usage",
    "status",
]
AI_RESULT_COLUMNS = ACTIVITY_COLUMNS + ["anomaly", "threat_score", "severity"]


def ensure_project_dirs() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
