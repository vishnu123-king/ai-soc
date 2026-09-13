from abc import ABC, abstractmethod
from typing import Dict, Any
from backend.app.schemas.ai import AIAnalysisSchema

class AIProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    async def analyze_incident(self, incident_context: Dict[str, Any]) -> AIAnalysisSchema:
        """
        Takes structured incident telemetry data and produces structured AI incident analysis.
        Strictly an analyst assistant: NO command execution, NO autonomous remediation.
        """
        pass
