import time
import threading
import logging
from typing import Optional
from ..config import AgentConfig
from ..buffer.spool import EventSpool
from .client import TransportClient

logger = logging.getLogger("aisoc-agent.shipper")

class BatchShipper:
    """
    Background worker that continuously drains the persistent EventSpool
    and ships batches of normalized telemetry to the Central SOC platform.
    Implements exponential backoff and persistent retries.
    """
    def __init__(self, config: AgentConfig, spool: EventSpool, transport: TransportClient):
        self.config = config
        self.spool = spool
        self.transport = transport
        
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._backoff_delay = 0.0
        self.total_shipped = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="aisoc-batch-shipper", daemon=True)
        self._thread.start()
        logger.info(f"BatchShipper started (batch_size: {self.config.batch_size}, interval: {self.config.batch_interval}s)")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=4.0)
        logger.info("BatchShipper stopped.")

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._backoff_delay > 0:
                logger.debug(f"Backing off for {self._backoff_delay:.1f}s due to previous transport failure...")
                if self._stop_event.wait(timeout=self._backoff_delay):
                    break
                self._backoff_delay = 0.0

            drained = self.ship_once()

            if not drained:
                # No events in spool or backoff triggered; wait batch_interval
                if self._stop_event.wait(timeout=self.config.batch_interval):
                    break

    def ship_once(self) -> bool:
        """
        Attempts to ship one batch of events.
        Returns True if a full batch was shipped (indicating more events may be waiting),
        False if spool was empty or shipment failed.
        """
        if not self.config.agent_token:
            # Cannot ship without bearer authentication token
            return False

        batch_items = self.spool.peek_batch(limit=self.config.batch_size)
        if not batch_items:
            return False

        spool_ids = [item[0] for item in batch_items]
        events_payload = [item[1] for item in batch_items]

        success, ingested_count, err_msg = self.transport.send_batch(events_payload)

        if success:
            self.spool.ack_batch(spool_ids)
            self.total_shipped += ingested_count
            self._backoff_delay = 0.0
            logger.info(f"Successfully shipped batch of {ingested_count} events (Total: {self.total_shipped}, Spool backlog: {self.spool.count()})")
            return len(batch_items) >= self.config.batch_size
        else:
            self.spool.increment_retries(spool_ids)
            logger.warning(f"Batch shipment failed: {err_msg}. Spool retained {len(spool_ids)} events.")
            # Calculate exponential backoff (1s, 2s, 4s, 8s, 16s, max 30s)
            self._backoff_delay = min(30.0, max(1.0, (self._backoff_delay * 2.0) if self._backoff_delay > 0 else 1.0))
            return False
