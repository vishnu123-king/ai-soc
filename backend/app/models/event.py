from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Index
from backend.app.database.connection import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), index=True, nullable=True)
    hostname = Column(String(255), index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    event_type = Column(String(64), index=True, nullable=False)  # authentication, process, privilege, network
    action = Column(String(64), nullable=True)                   # ssh_login, sudo_exec, socket_connect
    status = Column(String(32), nullable=False)                  # failed, success, denied
    username = Column(String(128), nullable=True)
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    process = Column(String(255), nullable=True)
    parent_process = Column(String(255), nullable=True)
    command = Column(Text, nullable=True)
    raw_message = Column(Text, nullable=False)
    event_metadata = Column("metadata", JSON, default=dict)
    is_simulation = Column(Boolean, default=False, index=True)

# Additional composite indexes for query optimization
Index("idx_events_agent_timestamp", Event.agent_id, Event.timestamp)
Index("idx_events_ip_timestamp", Event.source_ip, Event.timestamp)
Index("idx_events_type_timestamp", Event.event_type, Event.timestamp)
