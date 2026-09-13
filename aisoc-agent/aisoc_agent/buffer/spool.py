import os
import json
import sqlite3
import threading
from typing import List, Tuple, Dict, Any, Optional

class EventSpool:
    """
    Thread-safe SQLite-backed persistent FIFO spool for telemetry events.
    Guarantees event persistence across agent crashes, power interruptions, and network outages.
    """
    def __init__(self, directory: str, max_events: int = 50000):
        self.directory = os.path.abspath(directory)
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        self.db_path = os.path.join(self.directory, "events_spool.db")
        self.max_events = max_events
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS spool (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            payload TEXT NOT NULL,
                            retry_count INTEGER DEFAULT 0
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_spool_id ON spool(id);")
            finally:
                conn.close()

    def push(self, event_dict: Dict[str, Any]) -> int:
        """Pushes a single event dictionary into the persistent spool."""
        return self.push_batch([event_dict])

    def push_batch(self, events: List[Dict[str, Any]]) -> int:
        """Pushes multiple event dictionaries within a single transactional commit."""
        if not events:
            return 0
        
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    # Enforce max backlog limit (evict oldest if over capacity)
                    cur = conn.execute("SELECT COUNT(id) FROM spool;")
                    current_count = cur.fetchone()[0]
                    if current_count + len(events) > self.max_events:
                        excess = (current_count + len(events)) - self.max_events
                        conn.execute(f"DELETE FROM spool WHERE id IN (SELECT id FROM spool ORDER BY id ASC LIMIT {excess});")

                    rows = [(json.dumps(ev),) for ev in events]
                    conn.executemany("INSERT INTO spool (payload) VALUES (?);", rows)
                return len(events)
            finally:
                conn.close()

    def peek_batch(self, limit: int = 50) -> List[Tuple[int, Dict[str, Any]]]:
        """
        Retrieves the oldest unacknowledged batch of events without deleting them.
        Returns list of (spool_id, event_dict).
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT id, payload, retry_count FROM spool ORDER BY id ASC LIMIT ?;",
                    (limit,)
                )
                results = []
                for row in cur.fetchall():
                    spool_id = row[0]
                    payload_json = row[1]
                    try:
                        ev = json.loads(payload_json)
                        results.append((spool_id, ev))
                    except Exception:
                        # Corrupted JSON payload -> mark for removal
                        pass
                return results
            finally:
                conn.close()

    def ack_batch(self, spool_ids: List[int]) -> int:
        """
        Deletes acknowledged events from the spool after successful server ingestion.
        """
        if not spool_ids:
            return 0
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    placeholders = ",".join("?" for _ in spool_ids)
                    cur = conn.execute(f"DELETE FROM spool WHERE id IN ({placeholders});", spool_ids)
                    return cur.rowcount
            finally:
                conn.close()

    def increment_retries(self, spool_ids: List[int]) -> None:
        """Increments the retry counter for failed transmission attempts."""
        if not spool_ids:
            return
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    placeholders = ",".join("?" for _ in spool_ids)
                    conn.execute(f"UPDATE spool SET retry_count = retry_count + 1 WHERE id IN ({placeholders});", spool_ids)
            finally:
                conn.close()

    def count(self) -> int:
        """Returns total unacknowledged events remaining in the spool."""
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT COUNT(id) FROM spool;")
                return cur.fetchone()[0]
            finally:
                conn.close()

    def clear(self) -> None:
        """Clears all events from the spool (for test resets)."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM spool;")
            finally:
                conn.close()
