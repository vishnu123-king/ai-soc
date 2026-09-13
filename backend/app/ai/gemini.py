import json
import logging
import re
from typing import Dict, Any
from google import genai
from google.genai import types

from backend.app.config import settings
from backend.app.ai.base import AIProvider
from backend.app.schemas.ai import AIAnalysisSchema
from backend.app.ai.prompts import SYSTEM_ANALYST_PROMPT, format_incident_for_ai

logger = logging.getLogger("aisoc.ai.gemini")

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str = None):
        self.api_key = api_key or settings.GEMINI_API_KEY
        self._client = None

    @property
    def provider_name(self) -> str:
        return "gemini-2.5-flash"

    def _get_client(self):
        if not self._client:
            if not self.api_key:
                raise ValueError("GEMINI_API_KEY is not configured.")
            self._client = genai.Client(api_key=self.api_key)
        return self._client

    async def analyze_incident(self, incident_context: Dict[str, Any]) -> AIAnalysisSchema:
        client = self._get_client()
        user_prompt = format_incident_for_ai(incident_context)

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_ANALYST_PROMPT,
                response_mime_type="application/json",
                temperature=0.2,
            )
        )

        raw_text = response.text or "{}"
        
        # Clean potential markdown wrapping if returned
        raw_text = re.sub(r"^```json\s*", "", raw_text.strip())
        raw_text = re.sub(r"\s*```$", "", raw_text.strip())

        data = json.loads(raw_text)
        data["model_provider"] = self.provider_name
        return AIAnalysisSchema(**data)
