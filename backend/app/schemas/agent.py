from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=100, description="Unique agent identifier, e.g. linux-node-01")
    hostname: str = Field(..., min_length=1, max_length=255)
    operating_system: str = Field(default="Linux", max_length=255)
    ip_address: str = Field(..., min_length=7, max_length=64)
    agent_version: str = Field(default="1.0.0", max_length=32)
    enrollment_key: Optional[str] = Field(None, description="Pre-shared agent enrollment key")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class AgentRegisterResponse(BaseModel):
    agent_id: str
    hostname: str
    status: str
    token: str = Field(..., description="Secret bearer token for future aisoc-agent submissions")
    registered_at: datetime
    message: str

class AgentUpdate(BaseModel):
    status: Optional[str] = None
    ip_address: Optional[str] = None
    agent_version: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class AgentResponse(BaseModel):
    id: int
    agent_id: str
    hostname: str
    operating_system: str
    ip_address: str
    agent_version: str
    status: str
    last_seen: datetime
    registered_at: datetime
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, alias="agent_metadata")
    event_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
