"""
blockchain.py
-------------
A deliberately simple, dependency-free blockchain used to record votes.

Each vote is stored as a Block. Every block contains a SHA-256 hash of its
own contents plus the hash of the previous block, so changing any past
vote changes that block's hash and breaks the chain -- this is what gives
the ledger its tamper-evidence property, and it's the same core idea real
platforms like Ethereum use (just without the networking / consensus /
mining layer, which is out of scope for a college project).

The chain is persisted to a JSON file (chain_data.json) so it survives
app restarts, the same way SQLite persists the voter table.
"""

import hashlib
import json
import os
import tempfile
import threading
import time


class Block:
    def __init__(self, index, timestamp, data, previous_hash, hash_=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = hash_ or self.compute_hash()

    def compute_hash(self):
        payload = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "data": self.data,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }


class Blockchain:
    def __init__(self, chain_file="chain_data.json"):
        self.chain_file = chain_file
        self.chain = []
        self._lock = threading.RLock()
        self._load_or_init()

    # -- persistence ---------------------------------------------------
    def _load_or_init(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.chain_file)), exist_ok=True)
        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, "r", encoding="utf-8") as f:
                    raw_blocks = json.load(f)
                self.chain = [
                    Block(b["index"], b["timestamp"], b["data"], b["previous_hash"], b["hash"])
                    for b in raw_blocks
                ]
                if self.chain:
                    return
            except (json.JSONDecodeError, KeyError, TypeError, OSError) as exc:
                raise RuntimeError(f"Cannot load blockchain ledger: {exc}") from exc
        genesis = Block(0, time.time(), {"info": "Genesis Block"}, "0")
        self.chain = [genesis]
        self._save()

    def _save(self):
        directory = os.path.dirname(os.path.abspath(self.chain_file))
        file_descriptor, temporary_path = tempfile.mkstemp(
            prefix="chain-", suffix=".tmp", dir=directory
        )
        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as file_handle:
                json.dump([b.to_dict() for b in self.chain], file_handle, indent=2)
                file_handle.flush()
                os.fsync(file_handle.fileno())
            os.replace(temporary_path, self.chain_file)
        except Exception:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
            raise

    # -- core operations --------------------------------------------------
    def last_block(self):
        return self.chain[-1]

    def add_block(self, data):
        with self._lock:
            prev = self.last_block()
            new_block = Block(prev.index + 1, time.time(), data, prev.hash)
            self.chain.append(new_block)
            try:
                self._save()
            except Exception:
                self.chain.pop()
                raise
            return new_block

    def rollback_last(self, expected_hash):
        """Remove only the block just added by a failed database transaction."""
        with self._lock:
            if len(self.chain) > 1 and self.chain[-1].hash == expected_hash:
                self.chain.pop()
                self._save()
                return True
            return False

    def is_valid(self):
        """Re-hashes every block and checks the links -- this is the
        'audit' an admin (or anyone with a copy of the file) can run to
        prove nobody tampered with recorded votes after the fact."""
        with self._lock:
            if not self.chain:
                return False, "Chain is empty"
            if self.chain[0].hash != self.chain[0].compute_hash():
                return False, "Genesis block has been altered"
            for i in range(1, len(self.chain)):
                current, prev = self.chain[i], self.chain[i - 1]
                if current.index != prev.index + 1:
                    return False, f"Block sequence is broken at block {current.index}"
                if current.previous_hash != prev.hash:
                    return False, f"Block {current.index} does not link to block {prev.index}"
                if current.hash != current.compute_hash():
                    return False, f"Block {current.index} has been altered"
            return True, "Chain is valid"

    def all_vote_blocks(self):
        with self._lock:
            return list(self.chain[1:])
