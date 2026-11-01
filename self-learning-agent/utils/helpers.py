import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from config.settings import get_settings


class LLMClient:
    """Unified LLM client wrapping OpenAI / compatible endpoint with async & sync methods."""

    def __init__(self):
        settings = get_settings()
        self.api_key = settings.LLM_API_KEY
        self.base_url = settings.LLM_BASE_URL
        self.model = settings.LLM_MODEL
        self._client = None
        if self.api_key:
            import openai

            self._client = openai.OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
            )

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 1024,
    ) -> str:
        """Generate text completion from LLM."""
        if os.environ.get("REDLOOP_ENABLE_TEST_LLM_STUB") == "1":
            if "verification engine" in system_prompt.casefold():
                return "PASS\nReason: explicit offline test fixture.\nConfidence: 95"
            return (
                "ANSWER: Explicit offline test-fixture response.\n"
                "REASONING: This output is synthetic and must not be treated as analysis.\n"
                "CONFIDENCE: 90\n"
                "LEARNING: Test-only response.\n"
                "UNCERTAINTY: This is not a provider result."
            )

        if self._client:
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    max_tokens=max_tokens,
                    temperature=0.7,
                )
            except Exception as e:
                raise RuntimeError(
                    f"LLM provider request failed ({type(e).__name__})."
                ) from e
            content = response.choices[0].message.content
            if not isinstance(content, str) or not content.strip():
                raise RuntimeError("LLM provider returned an empty response.")
            return content

        raise RuntimeError(
            "LLM_API_KEY is not configured for the optional learning service."
        )


def get_llm_client() -> LLMClient:
    return LLMClient()


def format_timestamp(dt: Optional[datetime] = None) -> str:
    target = dt or datetime.now(timezone.utc)
    return target.strftime("%Y-%m-%d %H:%M:%S")


def safe_json_loads(text: str) -> Optional[Dict[str, Any]]:
    """Safely parse JSON string."""
    try:
        clean = text.strip()
        if clean.startswith("```json"):
            clean = clean[7:]
        if clean.startswith("```"):
            clean = clean[3:]
        if clean.endswith("```"):
            clean = clean[:-3]
        return json.loads(clean.strip())
    except Exception:
        return None
