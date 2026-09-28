"""Generate bounded, harmless CPU activity for monitor demonstrations."""

import argparse
import time


def simulate(duration=10, interval=0.1):
    """Briefly use CPU in small intervals, yielding between each burst."""
    end_time = time.monotonic() + duration
    print(f"Generating harmless CPU activity for up to {duration:g} seconds; Ctrl+C stops it.")
    try:
        while time.monotonic() < end_time:
            burst_end = time.monotonic() + min(interval, max(0, end_time - time.monotonic()))
            value = 0
            while time.monotonic() < burst_end:
                value = (value + 1) * (value + 3) % 1_000_003
            time.sleep(0.15)
    except KeyboardInterrupt:
        print("Simulation stopped early.")
    else:
        print("Simulation complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=10, help="Maximum run time in seconds")
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    simulate(args.duration)
