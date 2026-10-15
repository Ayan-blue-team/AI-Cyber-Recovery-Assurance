"""
GeminiLLMClient — a free-tier alternative to AnthropicLLMClient, implementing
the same LLMClient protocol (ai_engine.investigation.LLMClient) so it can be
passed anywhere an LLMClient is expected (investigate(), plan_recovery())
without any other code changing.

Why this exists: Anthropic's API requires a minimum $5 prepaid credit
purchase. Google's Gemini API (via Google AI Studio) offers a free tier
that does not require a credit card, which is useful for people who want
to run this project's AI stages without any upfront payment.

Requires: pip install google-generativeai
Get a free key at: https://aistudio.google.com/ (no credit card required
for the free tier, as of this writing — verify current terms on sign-up,
since free-tier policies can change).
"""

from __future__ import annotations

import os
from typing import Optional


class GeminiLLMClient:
    """Implements the same `complete(system, user) -> str` interface as
    AnthropicLLMClient, so it's interchangeable with it everywhere this
    project calls an LLMClient.
    """

    def __init__(self, model: str = "gemini-1.5-flash", api_key: Optional[str] = None):
        import google.generativeai as genai  # local import, same pattern as AnthropicLLMClient

        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise RuntimeError(
                "No Gemini API key found. Set the GEMINI_API_KEY environment "
                "variable, or get a free key at https://aistudio.google.com/"
            )
        genai.configure(api_key=key)
        self._model = genai.GenerativeModel(model_name=model)

    def complete(self, system: str, user: str) -> str:
        # Gemini's SDK takes the system instruction separately from the
        # generative model constructor in some versions; passing it as a
        # prefixed user turn here keeps this compatible across SDK versions
        # without depending on a specific one.
        prompt = f"{system}\n\n{user}"
        response = self._model.generate_content(prompt)
        return response.text
