import json
import logging
import re
from typing import Dict, Any
import httpx

from backend.app.config import settings
from backend.app.ai.base import AIProvider
from backend.app.schemas.ai import AIAnalysisSchema
from backend.app.ai.prompts import SYSTEM_ANALYST_PROMPT, format_incident_for_ai

logger = logging.getLogger("aisoc.ai.local_llm")

class LocalLLMProvider(AIProvider):
    """
    Integrates with local LLM runtimes (such as Ollama, vLLM, or LM Studio running Qwen 2.5)
    via standard OpenAI-compatible `/v1/chat/completions` REST endpoint.
    """
    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = (base_url or settings.LOCAL_LLM_BASE_URL).rstrip("/")
        self.model = model or settings.LOCAL_LLM_MODEL

    @property
    def provider_name(self) -> str:
        return f"local-llm:{self.model}"

    async def analyze_incident(self, incident_context: Dict[str, Any]) -> AIAnalysisSchema:
        user_prompt = format_incident_for_ai(incident_context)
        endpoint = f"{self.base_url}/chat/completions"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_ANALYST_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"}
        }

        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            res_json = response.json()
            content = res_json["choices"][0]["message"]["content"]

            content = re.sub(r"^```json\s*", "", content.strip())
            content = re.sub(r"\s*```$", "", content.strip())
            
            data = json.loads(content)
            data["model_provider"] = self.provider_name
            return AIAnalysisSchema(**data)
