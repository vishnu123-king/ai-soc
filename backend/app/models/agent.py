from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text
from backend.app.database.connection import Base

class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), unique=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    operating_system = Column(String(255), default="Linux")
    ip_address = Column(String(64), nullable=False)
    agent_version = Column(String(32), default="1.0.0")
    status = Column(String(32), default="ONLINE")  # ONLINE, OFFLINE, DEGRADED
    auth_token_hash = Column(String(255), nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    registered_at = Column(DateTime, default=datetime.utcnow)
    agent_metadata = Column("metadata", JSON, default=dict)
