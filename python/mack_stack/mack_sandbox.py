"""
MACK Stack - Hardened Hash-Chained Audit Ledger
Copyright (c) 2026 Allen Mack - All Rights Reserved - Patent Pending
MACK-STACK-01 - Morriston, FL 32668
By Mack
"""
import os
import json
import hashlib
import hmac
import time
import datetime
import fcntl
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List

LEDGER_FILE = Path(os.getenv("MACK_LEDGER_FILE", "mack_audit_ledger.jsonl"))
HMAC_KEY = os.getenv("MACK_LEDGER_HMAC_KEY", "").encode()
GENESIS_ID = "evt-1041"

_thread_lock = threading.RLock()

class MackLedger:
    """
    Hash-chained tamper-evident ledger:
    hash(n) = SHA256(prev_hash + payload_json)
    Optional HMAC-SHA256 if MACK_LEDGER_HMAC_KEY is set.
    Features: cached last hash, fcntl lock, flush+fsync durability, threading lock
    """
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else LEDGER_FILE
        self._last_hash: Optional[str] = None
        self._last_id: Optional[str] = None
        self._count: int = 0
        self._load_cache()

    def _load_cache(self):
        if not self.path.exists():
            self._last_hash = "0"*64
            self._last_id = None
            self._count = 0
            return
        try:
            last = None
            count = 0
            with open(self.path, 'r') as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)
                        count += 1
            if last:
                self._last_hash = last.get("hash")
                self._last_id = last.get("event_id")
                self._count = count
            else:
                self._last_hash = "0"*64
                self._count = 0
        except Exception:
            self._last_hash = "0"*64
            self._count = 0

    def _compute_hash(self, prev_hash: str, payload: Dict[str, Any]) -> str:
        data = prev_hash + json.dumps(payload, sort_keys=True, separators=(',',':'))
        base_hash = hashlib.sha256(data.encode()).hexdigest()
        if HMAC_KEY:
            return hmac.new(HMAC_KEY, base_hash.encode(), hashlib.sha256).hexdigest()
        return base_hash

    def _read_last_from_file_locked(self, f):
        """Read last hash from file while holding fcntl lock - for multi-process safety"""
        try:
            f.seek(0)
            last = None
            count = 0
            for line in f:
                if line.strip():
                    try:
                        last = json.loads(line)
                        count += 1
                    except:
                        pass
            if last:
                return last.get("hash"), last.get("event_id"), count
            else:
                return "0"*64, None, 0
        except:
            return "0"*64, None, 0

    def append(self, event_type: str, lane: str, payload: Dict[str, Any], event_id: Optional[str]=None) -> Dict[str, Any]:
        with _thread_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, 'a+') as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    true_last_hash, true_last_id, true_count = self._read_last_from_file_locked(f)
                    if true_count > 0:
                        prev_hash = true_last_hash
                        last_id = true_last_id
                        count = true_count
                    else:
                        prev_hash = self._last_hash or "0"*64
                        last_id = self._last_id
                        count = self._count

                    ts = datetime.datetime.utcnow().isoformat() + "Z"
                    if not event_id:
                        if count == 0:
                            event_id = GENESIS_ID
                        else:
                            try:
                                num = int(last_id.split("-")[1]) + 1 if last_id else 1042
                            except:
                                num = 1041 + count + 1
                            event_id = f"evt-{num}"

                    record_payload = {
                        "event_id": event_id,
                        "ts": ts,
                        "type": event_type,
                        "lane": lane,
                        "data": payload,
                        "prev_hash": prev_hash
                    }
                    cur_hash = self._compute_hash(prev_hash, record_payload)
                    record = {**record_payload, "hash": cur_hash}

                    f.write(json.dumps(record) + "\n")
                    f.flush()
                    os.fsync(f.fileno())

                    self._last_hash = cur_hash
                    self._last_id = event_id
                    self._count = count + 1
                    return record
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

    def verify(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"valid": True, "count": 0, "broken": 0, "broken_segments": []}
        broken = []
        prev_hash = "0"*64
        count = 0
        last_hash = prev_hash
        with open(self.path, 'r') as f:
            for i, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except:
                    broken.append({"line": i, "reason": "json_parse"})
                    continue
                payload = {k: rec[k] for k in ["event_id","ts","type","lane","data","prev_hash"]}
                expected_prev = rec.get("prev_hash")
                if expected_prev != prev_hash:
                    broken.append({"line": i, "event_id": rec.get("event_id"), "reason": f"prev_hash mismatch expected {prev_hash[:8]} got {expected_prev[:8] if expected_prev else None}"})
                calc = self._compute_hash(prev_hash, payload)
                if calc != rec.get("hash"):
                    broken.append({"line": i, "event_id": rec.get("event_id"), "reason": "hash mismatch"})
                prev_hash = rec.get("hash", prev_hash)
                last_hash = prev_hash
                count += 1
        return {"valid": len(broken)==0, "count": count, "broken": len(broken), "broken_segments": broken, "last_hash": last_hash}

_ledger = None
def get_ledger():
    global _ledger
    if _ledger is None:
        _ledger = MackLedger()
    return _ledger
