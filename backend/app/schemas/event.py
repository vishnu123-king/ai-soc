from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict

class EventCreate(BaseModel):
    agent_id: Optional[str] = Field(None, description="Identifier of the reporting agent")
    hostname: str = Field(..., description="Target or reporting hostname")
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)
    event_type: str = Field(..., description="Category: authentication, process, privilege, network")
    action: Optional[str] = Field(None, description="Action: ssh_login, execve, sudo_command, outbound_socket")
    status: str = Field(..., description="Outcome: failed, success, denied, accepted")
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    command: Optional[str] = None
    raw_message: str = Field(..., description="Original raw log or audit line")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    simulation: Optional[bool] = Field(default=False, description="Flag indicating simulated/educational telemetry")

class EventBatchCreate(BaseModel):
    events: List[EventCreate] = Field(..., min_length=1, max_length=500)

class EventResponse(BaseModel):
    id: int
    agent_id: Optional[str] = None
    hostname: str
    timestamp: datetime
    event_type: str
    action: Optional[str] = None
    status: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    command: Optional[str] = None
    raw_message: str
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, alias="event_metadata")
    is_simulation: bool = False

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
