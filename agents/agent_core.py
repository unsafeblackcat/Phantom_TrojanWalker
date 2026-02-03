import json
import logging
import asyncio
from typing import Any, Dict, List, Optional

from langchain_openai import ChatOpenAI
from config_loader import load_config
from exceptions import LLMResponseError
from langchain.messages import SystemMessage, HumanMessage
from langchain_core.rate_limiters import InMemoryRateLimiter

logger = logging.getLogger(__name__)


def _response_to_text(resp: Any) -> str:
    content = getattr(resp, "content", None)
    return str(content) if content is not None else str(resp)


def _json_or_error_payload(agent_name: str, content: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
        # LLM should return JSON object; normalize non-dict JSON into an error payload.
        return {
            "error": "LLM JSON is not an object.",
            "agent": agent_name,
            "raw_response": content,
        }
    except Exception:
        return {
            "error": "Failed to parse AI JSON response.",
            "agent": agent_name,
            "raw_response": content,
        }


def _validate_api_key(agent_label: str, api_key: Optional[str]) -> None:
    """Validate LLM API key presence.

    Refactor note: isolate validation for reuse across agents.
    """
    if not api_key or api_key.strip() in {"", "YOUR_API_KEY_HERE"}:
        raise ValueError(
            f"Missing LLM API key in agents/config.yaml ({agent_label}.llm.api_key)"
        )


def _build_rate_limiter(rate_limit_cfg: Optional[Any]) -> Optional[InMemoryRateLimiter]:
    """Create a rate limiter if config is provided.

    Refactor note: reduces repeated construction logic.
    """
    if not rate_limit_cfg:
        return None
    return InMemoryRateLimiter(
        requests_per_second=rate_limit_cfg.requests_per_second,
        check_every_n_seconds=rate_limit_cfg.check_every_n_seconds,
        max_bucket_size=rate_limit_cfg.max_bucket_size,
    )


def _build_llm_params(agent_name: str, agent_cfg: Any, rate_limiter: Optional[InMemoryRateLimiter]) -> Dict[str, Any]:
    """Build LLM init params while filtering None values.

    Refactor note: centralizes default handling for consistency.
    """
    # Build model_kwargs, only including extra_body if it's not None
    model_kwargs = {"response_format": {"type": "json_object"}}
    if agent_cfg.llm.extra_body is not None:
        model_kwargs["extra_body"] = agent_cfg.llm.extra_body

    params = {
        "name": agent_name,
        "base_url": agent_cfg.llm.base_url,
        "model": agent_cfg.llm.model_name,
        "api_key": agent_cfg.llm.api_key,
        "max_retries": agent_cfg.llm.max_retries,
        "timeout": agent_cfg.llm.timeout,
        "max_completion_tokens": agent_cfg.llm.max_completion_tokens,
        "rate_limiter": rate_limiter,
        "model_kwargs": model_kwargs,
    }
    # 过滤掉为 None 的参数，确保空值时使用 LangChain 或 Provider 的默认值
    return {k: v for k, v in params.items() if v is not None}


def _create_llm(agent_name: str, agent_cfg: Any) -> ChatOpenAI:
    """Create a ChatOpenAI client with shared initialization logic."""
    _validate_api_key(agent_name, agent_cfg.llm.api_key)
    rate_limiter = _build_rate_limiter(agent_cfg.rate_limit)
    llm_params = _build_llm_params(agent_name, agent_cfg, rate_limiter)
    return ChatOpenAI(**llm_params)

class FunctionAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.FunctionAnalysisAgent
        self.llm = _create_llm("FunctionAnalysisAgent", self.agent_config)
        # Retry attempts for JSON parse failures (fallback if not configured)
        self._json_retry_attempts = self._resolve_json_retry_attempts()

    async def _ainvoke_with_retry(self, messages: List[Any], agent_label: str) -> Any:
        """Invoke LLM with retry to handle transient provider/parsing failures.

        Refactor note: centralize retry for provider-side NoneType/parse errors.
        """
        last_exc: Exception | None = None
        for attempt in range(1, self._json_retry_attempts + 1):
            try:
                return await self.llm.ainvoke(messages)
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "%s LLM invoke failed (attempt %d/%d): %s",
                    agent_label,
                    attempt,
                    self._json_retry_attempts,
                    exc,
                )
                # Small backoff to avoid tight retry loop
                await asyncio.sleep(min(0.5 * attempt, 2.0))
        if last_exc:
            raise last_exc

    def _resolve_json_retry_attempts(self) -> int:
        # Prefer configured max_retries; ensure at least 1 attempt.
        max_retries = getattr(self.agent_config.llm, "max_retries", None)
        if isinstance(max_retries, int) and max_retries > 0:
            return max_retries
        return 3

    def _truncate_code_for_context(self, code: str) -> str:
        max_input_tokens = getattr(self.agent_config.llm, "max_input_tokens", None)
        if not isinstance(max_input_tokens, int) or max_input_tokens <= 0:
            return code
        # Conservative approximation: keep a buffer for prompt + tool wrappers.
        max_char_limit = max(0, max_input_tokens - 10000)
        if max_char_limit > 0 and len(code) > max_char_limit:
            return code[:max_char_limit] + "\n... [Code truncated for AI analysis due to context limits] ..."
        return code

    async def analyze(self, code: str) -> dict:
        messages = [
            SystemMessage(content=self.agent_config.system_prompt),
            HumanMessage(content=f"{code}")
        ]
        last_content = ""
        for attempt in range(1, self._json_retry_attempts + 1):
            response = await self._ainvoke_with_retry(messages, "FunctionAnalysisAgent")
            content = _response_to_text(response)
            last_content = content
            parsed = _json_or_error_payload("FunctionAnalysisAgent", content)
            if "error" not in parsed:
                return parsed
            logger.warning(
                "FunctionAnalysisAgent JSON parse failed (attempt %d/%d)",
                attempt,
                self._json_retry_attempts,
            )
        raise LLMResponseError(
            "Failed to parse JSON response from FunctionAnalysisAgent",
            raw_response=last_content,
        )

    async def analyze_decompiled_batch(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch analyze decompiled functions.

        Input: [{"name": str, "code": str}, ...]
        Output: [{"name": str, "analysis": dict}, ...]

                Notes:
                - Sequentially invokes the LLM per function.
                - JSON parse failures raise an error to avoid partial results.
        """
        if not items:
            return []

        prepared_names: List[str] = []
        prepared_codes: List[str] = []
        for item in items:
            name = item.get("name")
            if not name:
                continue
            code = item.get("code") or ""
            code = self._truncate_code_for_context(str(code))
            prepared_names.append(str(name))
            prepared_codes.append(code)

        if not prepared_names:
            return []

        async def _analyze_one(name: str, code: str) -> Dict[str, Any]:
            messages = [
                SystemMessage(content=self.agent_config.system_prompt),
                HumanMessage(content=str(code)),
            ]
            last_content = ""
            parsed = None
            for attempt in range(1, self._json_retry_attempts + 1):
                response = await self._ainvoke_with_retry(messages, "FunctionAnalysisAgent")
                content = _response_to_text(response)
                last_content = content
                parsed = _json_or_error_payload("FunctionAnalysisAgent", content)
                if "error" not in parsed:
                    break
                logger.warning(
                    "FunctionAnalysisAgent JSON parse failed for %s (attempt %d/%d)",
                    name,
                    attempt,
                    self._json_retry_attempts,
                )
            if not parsed or "error" in parsed:
                raise LLMResponseError(
                    "Failed to parse JSON response from FunctionAnalysisAgent",
                    raw_response=last_content,
                )
            return parsed

        analyses = await asyncio.gather(
            *[_analyze_one(name, code) for name, code in zip(prepared_names, prepared_codes)]
        )

        return [
            {"name": name, "analysis": analysis}
            for name, analysis in zip(prepared_names, analyses)
        ]

class MalwareAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.MalwareAnalysisAgent
        self.llm = _create_llm("MalwareAnalysisAgent", self.agent_config)

    async def _ainvoke_with_retry(self, messages: List[Any]) -> Any:
        """Invoke LLM with retry to handle transient provider/parsing failures."""
        max_attempts = 3
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return await self.llm.ainvoke(messages)
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "MalwareAnalysisAgent LLM invoke failed (attempt %d/%d): %s",
                    attempt,
                    max_attempts,
                    exc,
                )
                await asyncio.sleep(min(0.5 * attempt, 2.0))
        if last_exc:
            raise last_exc

    async def analyze(self, analysis_results: list, metadata: dict) -> dict:
        context = {
            "metadata": metadata,
            "function_analyses": analysis_results
        }
        messages = [
            SystemMessage(content=self.agent_config.system_prompt),
            HumanMessage(content=f"{json.dumps(context, ensure_ascii=False, indent=2)}")
        ]
        response = await self._ainvoke_with_retry(messages)
        content = _response_to_text(response)
        parsed = _json_or_error_payload("MalwareAnalysisAgent", content)
        if "error" in parsed:
            raise LLMResponseError(
                "Failed to parse JSON response from MalwareAnalysisAgent",
                raw_response=content,
            )
        return parsed
