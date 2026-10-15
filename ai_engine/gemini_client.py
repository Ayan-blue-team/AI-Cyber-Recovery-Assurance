"""
GeminiLLMClient — a free-tier alternative to AnthropicLLMClient, implementing
the same LLMClient protocol (ai_engine.investigation.LLMClient) so it can be
passed anywhere an LLMClient is expected (investigate(), plan_recovery())
without any other code changing.

Why this exists: Anthropic's API requires a minimum $5 prepaid credit
purchase. Google's Gemini API (via Google AI Studio) offers a free tier
that does not require a credit card, which is useful for people who want
to run this project's AI stages without any upfront payment.

Requires: pip install google-genai
(NOT google-generativeai — that package is deprecated as of 2026 and no
longer receives updates; this file uses the current, supported SDK.)

Get a free key at: https://aistudio.google.com/apikey (no credit card
required for the free tier, as of this writing — verify current terms on
sign-up, since free-tier policies and model availability can change;
Gemini 2.5 models are scheduled for shutdown in October 2026, which is why
this client defaults to a Gemini 3 model instead).
"""

from __future__ import annotations

import os
from typing import Optional


class GeminiLLMClient:
    """Implements the same `complete(system, user) -> str` interface as
    AnthropicLLMClient, so it's interchangeable with it everywhere this
    project calls an LLMClient.
    """

    def __init__(self, model: str = "gemini-3-flash-preview", api_key: Optional[str] = None):
        from google import genai  # local import, same pattern as AnthropicLLMClient

        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise RuntimeError(
                "No Gemini API key found. Set the GEMINI_API_KEY environment "
                "variable, or get a free key at https://aistudio.google.com/apikey"
            )
        self._client = genai.Client(api_key=key)
        self._model = model

    def complete(self, system: str, user: str) -> str:
        from google.genai import types

        response = self._client.models.generate_content(
            model=self._model,
            contents=user,
            config=types.GenerateContentConfig(system_instruction=system),
        )
        return response.text
