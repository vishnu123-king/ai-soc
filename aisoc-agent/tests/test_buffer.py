import os
import shutil
import tempfile
import pytest
from aisoc_agent.buffer.spool import EventSpool

@pytest.fixture
def temp_spool_dir():
    dir_path = tempfile.mkdtemp(prefix="aisoc_spool_test_")
    yield dir_path
    shutil.rmtree(dir_path, ignore_errors=True)

def test_spool_push_peek_ack(temp_spool_dir):
    spool = EventSpool(temp_spool_dir)
    assert spool.count() == 0

    # Push 3 events
    ev1 = {"id": 1, "raw": "event 1"}
    ev2 = {"id": 2, "raw": "event 2"}
    ev3 = {"id": 3, "raw": "event 3"}

    spool.push(ev1)
    spool.push_batch([ev2, ev3])

    assert spool.count() == 3

    # Peek batch of 2
    batch = spool.peek_batch(limit=2)
    assert len(batch) == 2
    spool_id1, payload1 = batch[0]
    spool_id2, payload2 = batch[1]

    assert payload1["raw"] == "event 1"
    assert payload2["raw"] == "event 2"

    # Ack the first 2 events
    acked = spool.ack_batch([spool_id1, spool_id2])
    assert acked == 2
    assert spool.count() == 1

    # Remaining event in queue
    rem = spool.peek_batch(limit=10)
    assert len(rem) == 1
    assert rem[0][1]["raw"] == "event 3"

def test_spool_persistence_across_restart(temp_spool_dir):
    # Initialize spool and add data
    spool1 = EventSpool(temp_spool_dir)
    spool1.push({"msg": "persisted event"})
    assert spool1.count() == 1

    # Simulate restart by opening new instance on same directory
    spool2 = EventSpool(temp_spool_dir)
    assert spool2.count() == 1
    batch = spool2.peek_batch(limit=5)
    assert len(batch) == 1
    assert batch[0][1]["msg"] == "persisted event"

def test_spool_max_backlog_capacity(temp_spool_dir):
    # Spool with max 5 items
    spool = EventSpool(temp_spool_dir, max_events=5)
    
    for i in range(10):
        spool.push({"seq": i})

    # Should cap at 5, retaining the most recent events (seq 5 through 9)
    assert spool.count() == 5
    items = spool.peek_batch(limit=10)
    seqs = [it[1]["seq"] for it in items]
    assert seqs == [5, 6, 7, 8, 9]
