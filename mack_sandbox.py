"""
mack_sandbox.py
MACK Stack — Hardened Hash-Chained Audit Ledger
HMAC-SHA256 + fcntl file lock + fsync + crash recovery + thread lock
Author: Mack
"""

import hashlib
import hmac
import json
import os
import fcntl
import threading
import time


class HashChainedAuditLedger:
    def __init__(self, ledger_path: str, hmac_key: bytes):
        self.ledger_path = ledger_path
        self.hmac_key = hmac_key
        self._lock = threading.Lock()
        self._cached_hash = None

        if not os.path.exists(self.ledger_path):
            open(self.ledger_path, "a").close()

        self._cached_hash = self._recover_last_valid_hash()

    def _sign(self, data: str) -> str:
        return hmac.new(self.hmac_key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _recover_last_valid_hash(self) -> str:
        """
        Scan the ledger backward, find the last line with a valid HMAC
        signature, and truncate anything after it (an incomplete write
        left behind by a crash).
        """
        genesis_hash = "0" * 64

        if not os.path.getsize(self.ledger_path):
            return genesis_hash

        with open(self.ledger_path, "r") as f:
            lines = f.readlines()

        last_valid_index = -1
        last_valid_hash = genesis_hash

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                expected_sig = record.pop("sig")
                check_str = json.dumps(record, sort_keys=True)
                if hmac.compare_digest(self._sign(check_str), expected_sig):
                    last_valid_index = i
                    last_valid_hash = record["curr_hash"]
                else:
                    break
            except (json.JSONDecodeError, KeyError):
                break

        if last_valid_index != len(lines) - 1:
            with open(self.ledger_path, "w") as f:
                f.writelines(lines[: last_valid_index + 1])

        return last_valid_hash

    def append(self, event: dict) -> str:
        with self._lock:
            timestamp = time.time()
            prev_hash = self._cached_hash

            body = {
                "timestamp": timestamp,
                "event": event,
                "prev_hash": prev_hash,
            }
            curr_hash = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode("utf-8")
            ).hexdigest()
            body["curr_hash"] = curr_hash

            sig = self._sign(json.dumps(body, sort_keys=True))
            record = dict(body)
            record["sig"] = sig

            with open(self.ledger_path, "a") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(record) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

            self._cached_hash = curr_hash
            return curr_hash

    def verify_ledger(self) -> bool:
        genesis_hash = "0" * 64
        prev_hash = genesis_hash

        with open(self.ledger_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                sig = record.pop("sig")
                check_str = json.dumps(record, sort_keys=True)
                if not hmac.compare_digest(self._sign(check_str), sig):
                    return False
                if record["prev_hash"] != prev_hash:
                    return False
                prev_hash = record["curr_hash"]

        return True


def execute_sandbox_lane(lane_id: str, ledger: HashChainedAuditLedger):
    """
    Simulate one MACK Stack lane executing and logging its result
    into the shared audit ledger.
    """
    event = {
        "lane_id": lane_id,
        "status": "GREEN",
        "action": "lane_execute",
    }
    return ledger.append(event)
