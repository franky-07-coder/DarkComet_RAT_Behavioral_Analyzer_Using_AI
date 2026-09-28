"""Dependency-free robust outlier scoring for process activity CSV logs.

This is a small statistical detector, not a trained malware classifier. It uses
median absolute deviation, which works without NumPy, pandas, or scikit-learn.
"""

import csv
import math
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.paths import ACTIVITY_LOG, AI_RESULT_COLUMNS, AI_RESULTS_LOG, ensure_project_dirs
from detector.threat_score import calculate_threat_score

FEATURES = ("cpu_usage", "memory_usage")


def _robust_outliers(rows):
    """Return row anomaly flags using a robust 3.5 MAD threshold per feature."""
    if len(rows) < 5:
        return [False] * len(rows)
    outliers = [False] * len(rows)
    for feature in FEATURES:
        values = [row[feature] for row in rows]
        median = statistics.median(values)
        deviations = [abs(value - median) for value in values]
        mad = statistics.median(deviations)
        if mad == 0:
            # With a zero MAD, any non-median value is outside the dominant baseline.
            feature_outliers = [value != median for value in values]
        else:
            feature_outliers = [abs(value - median) / (1.4826 * mad) > 3.5 for value in values]
        outliers = [old or new for old, new in zip(outliers, feature_outliers)]
    return outliers


def analyze_activity(input_path=ACTIVITY_LOG, output_path=AI_RESULTS_LOG):
    """Score activity records and write results as a CSV with no third-party data stack."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    ensure_project_dirs()
    if not input_path.exists():
        raise FileNotFoundError(f"Activity log not found: {input_path}")

    with input_path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError("Activity log is empty or has no CSV header.")
        missing = [column for column in (*FEATURES, "status") if column not in reader.fieldnames]
        if missing:
            raise ValueError(f"Activity log is missing required columns: {missing}")
        rows = []
        for line_number, raw in enumerate(reader, start=2):
            try:
                row = {key: (value or "") for key, value in raw.items() if key is not None}
                for feature in FEATURES:
                    value = float(row[feature])
                    if not math.isfinite(value):
                        raise ValueError
                    row[feature] = value
                row.setdefault("timestamp", "")
                row.setdefault("pid", "-1")
                row.setdefault("process_name", "Unknown")
                row["status"] = row.get("status", "SAFE") or "SAFE"
                rows.append(row)
            except (ValueError, TypeError):
                continue

    flags = _robust_outliers(rows)
    for row, anomaly in zip(rows, flags):
        score = calculate_threat_score(row["cpu_usage"], row["memory_usage"], row["status"], anomaly)
        row["anomaly"] = str(anomaly).lower()
        row["threat_score"] = score
        row["severity"] = (
            "LOW" if score < 30 else "MEDIUM" if score < 60
            else "HIGH" if score < 85 else "CRITICAL"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=AI_RESULT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return rows


if __name__ == "__main__":
    try:
        results = analyze_activity()
        count = sum(row["anomaly"] == "true" for row in results)
        print(f"Analyzed {len(results)} process records; {count} statistical outlier(s).")
        print(f"Scored results saved to {AI_RESULTS_LOG}")
    except (FileNotFoundError, ValueError) as error:
        raise SystemExit(str(error))
