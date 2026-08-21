"""
run_lanes.py
MACK Stack — 12-Lane Concurrent Driver
Fires all 12 lanes in parallel, logs each to the shared ledger,
then verifies the full chain.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from mack_sandbox import get_ledger

LANES = [
    "propulsion", "nav_lidar", "flight_controller", "ai_core",
    "power_mgmt", "comms", "sensor_fusion", "thermal",
    "structural", "payload", "telemetry", "failsafe",
]


def execute_lane(lane_id: str):
    ledger = get_ledger()
    record = ledger.append(
        event_type="lane_execute",
        lane=lane_id,
        payload={"status": "GREEN", "action": "lane_execute"},
    )
    return lane_id, record


def main():
    results = {}
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(execute_lane, lane): lane for lane in LANES}
        for future in as_completed(futures):
            lane_id, record = future.result()
            results[lane_id] = record
            print(f"[OK] {lane_id} -> event_id={record.get('event_id')}")

    print("\nAll 12 lanes complete. Verifying ledger...")
    ledger = get_ledger()
    verdict = ledger.verify()

    if verdict["valid"]:
        print(f"LEDGER VALID — {verdict['count']} events, last_hash={verdict['last_hash'][:16]}...")
    else:
        print(f"LEDGER BROKEN — {len(verdict['broken_segments'])} bad segment(s):")
        for seg in verdict["broken_segments"]:
            print(f"  {seg}")


if __name__ == "__main__":
    main()
