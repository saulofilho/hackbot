from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI

from .config import Settings


def build_llm(settings: Settings) -> BaseChatModel:
    if settings.llm_provider == "anthropic":
        if not settings.anthropic_api_key:
            raise RuntimeError("PH_ANTHROPIC_API_KEY ausente")
        return ChatAnthropic(
            model=settings.llm_model,
            api_key=settings.anthropic_api_key,
            temperature=settings.llm_temperature,
        )
    if not settings.openai_api_key:
        raise RuntimeError("PH_OPENAI_API_KEY ausente")
    kwargs: dict = {
        "model": settings.llm_model,
        "api_key": settings.openai_api_key,
        "temperature": settings.llm_temperature,
    }
    if settings.llm_base_url:
        kwargs["base_url"] = settings.llm_base_url
    return ChatOpenAI(**kwargs)
