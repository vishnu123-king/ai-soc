from abc import ABC, abstractmethod
from typing import Dict, Any
from backend.schemas import AIAnalysisSchema

class AIProvider(ABC):
    """
    Abstract AI Provider interface for AI-SOC security incident analysis.
    Security Constraint: Purely read-only analytical model.
    Never permitted to execute shell commands, tools, or scripts directly.
    """
    provider_name: str

    @abstractmethod
    async def analyze_incident(self, incident_data: Dict[str, Any]) -> AIAnalysisSchema:
        """
        Takes structured incident data and returns validated structured AI analysis.
        """
        pass
