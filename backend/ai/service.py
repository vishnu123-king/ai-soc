from typing import Dict, Any, Optional
from backend.ai.provider import AIProvider
from backend.ai.gemini_provider import GeminiProvider
from backend.ai.local_llm_provider import LocalLLMProvider
from backend.schemas import AIAnalysisSchema

class AIAnalystService:
    def __init__(self):
        self.providers: Dict[str, AIProvider] = {
            "gemini": GeminiProvider(),
            "local_qwen": LocalLLMProvider(),
        }
        self.default_provider = "gemini"

    def get_provider(self, name: Optional[str] = None) -> AIProvider:
        provider_key = (name or self.default_provider).lower()
        if provider_key in self.providers:
            return self.providers[provider_key]
        return self.providers["gemini"]

    async def analyze(self, incident_data: Dict[str, Any], provider_name: Optional[str] = None) -> AIAnalysisSchema:
        provider = self.get_provider(provider_name)
        # Security verification: Ensure AI analysis is purely read-only
        analysis = await provider.analyze_incident(incident_data)
        return analysis

ai_analyst_service = AIAnalystService()
