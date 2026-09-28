"""Log process snapshots using Windows tasklist and Python's standard library."""

import csv
import subprocess
import time
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.paths import ACTIVITY_COLUMNS, ACTIVITY_LOG, ensure_project_dirs

SUSPICIOUS_KEYWORDS = ("hack", "inject", "malware", "trojan", "rat", "keylogger")
INTERVAL_SECONDS = 5


def get_processes():
    """Return Windows process records from tasklist's CSV output."""
    result = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=True,
    )
    for item in csv.reader(result.stdout.splitlines()):
        if len(item) >= 5:
            name, pid, _session, _session_number, memory = item[:5]
            memory_mb = float(memory.replace(",", "").replace(" K", "")) / 1024
            yield {"pid": int(pid), "name": name, "memory_mb": memory_mb}


def log_activity(timestamp, pid, name, cpu, memory, status):
    ensure_project_dirs()
    write_header = not ACTIVITY_LOG.exists() or ACTIVITY_LOG.stat().st_size == 0
    with ACTIVITY_LOG.open("a", newline="", encoding="utf-8") as target:
        writer = csv.writer(target)
        if write_header:
            writer.writerow(ACTIVITY_COLUMNS)
        writer.writerow([timestamp, pid, name, f"{cpu:.2f}", f"{memory:.2f}", status])


def monitor_processes():
    if sys.platform != "win32":
        raise SystemExit("The built-in process monitor currently supports Windows only.")
    print("Standard-library process monitor started. Press Ctrl+C to stop.")
    previous = {}
    try:
        while True:
            now = time.monotonic()
            processes = list(get_processes())
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for process in processes:
                pid, name = process["pid"], process["name"]
                cpu = 0.0
                status = "SUSPICIOUS" if any(key in name.lower() for key in SUSPICIOUS_KEYWORDS) else "SAFE"
                log_activity(timestamp, pid, name, cpu, process["memory_mb"], status)
            print(f"Logged {len(processes)} processes at {timestamp} (CPU unavailable; memory is logged in MB).")
            time.sleep(INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nProcess monitor stopped.")


if __name__ == "__main__":
    monitor_processes()
