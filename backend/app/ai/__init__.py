import logging
from typing import Dict, Any
from backend.app.config import settings
from backend.app.ai.base import AIProvider
from backend.app.ai.gemini import GeminiProvider
from backend.app.ai.local_llm import LocalLLMProvider
from backend.app.ai.mock import MockAIProvider
from backend.app.schemas.ai import AIAnalysisSchema

logger = logging.getLogger("aisoc.ai")

def get_ai_provider() -> AIProvider:
    provider_type = settings.AI_PROVIDER.lower()
    
    if provider_type == "gemini" and settings.GEMINI_API_KEY:
        return GeminiProvider()
    elif provider_type in ["local", "local_llm", "qwen"]:
        return LocalLLMProvider()
    elif settings.GEMINI_API_KEY:
        # Fallback to Gemini if API key is present
        return GeminiProvider()
    else:
        logger.info("Using deterministic SOC analyst provider (no GEMINI_API_KEY set).")
        return MockAIProvider()

async def analyze_incident_safely(incident_context: Dict[str, Any]) -> AIAnalysisSchema:
    """
    Executes AI analysis through the configured provider.
    If the primary LLM provider encounters network timeouts, missing credentials,
    or rate limits, safely falls back to the deterministic security analyst provider
    so that the incident investigation pipeline NEVER crashes or returns 500.
    """
    provider = get_ai_provider()
    try:
        return await provider.analyze_incident(incident_context)
    except Exception as e:
        logger.warning(f"Primary AI provider ({provider.provider_name}) failed: {e}. Falling back to deterministic SOC analyst.")
        mock_provider = MockAIProvider()
        return await mock_provider.analyze_incident(incident_context)
