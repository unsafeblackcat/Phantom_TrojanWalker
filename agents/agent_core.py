import json
import logging
from typing import Any, Dict, List

from langchain_openai import ChatOpenAI
from langchain_deepseek import ChatDeepSeek
from langchain.agents import create_agent
from config_loader import load_config
from exceptions import LLMResponseError
from langchain.messages import AIMessage, SystemMessage, HumanMessage
from langchain_core.rate_limiters import InMemoryRateLimiter

logger = logging.getLogger(__name__)


def _response_to_text(resp: Any) -> str:
    content = getattr(resp, "content", None)
    if content is None:
        return str(resp)
    return str(content)


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

class FunctionAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.FunctionAnalysisAgent
        if not self.agent_config.llm.api_key or self.agent_config.llm.api_key.strip() in {"", "YOUR_API_KEY_HERE"}:
            raise ValueError("Missing LLM API key in agents/config.yaml (FunctionAnalysisAgent.llm.api_key)")
        
        # 从配置中初始化 Rate Limiter
        rl_config = self.agent_config.rate_limit
        rate_limiter = None
        if rl_config:
            rate_limiter = InMemoryRateLimiter(
                requests_per_second=rl_config.requests_per_second,
                check_every_n_seconds=rl_config.check_every_n_seconds,
                max_bucket_size=rl_config.max_bucket_size,
            )

        llm_params = {
            "name": "FunctionAnalysisAgent",
            "base_url": self.agent_config.llm.base_url,
            "model": self.agent_config.llm.model_name,
            "api_key": self.agent_config.llm.api_key,
            "max_retries": self.agent_config.llm.max_retries,
            "timeout": self.agent_config.llm.timeout,
            "max_completion_tokens": self.agent_config.llm.max_completion_tokens,
            "rate_limiter": rate_limiter,
            "model_kwargs": {"response_format": {"type": "json_object"}}
        }
        # 过滤掉为 None 的参数，确保空值时使用 LangChain 或 Provider 的默认值
        llm_params = {k: v for k, v in llm_params.items() if v is not None}
        self.llm = ChatOpenAI(**llm_params)

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
        response = await self.llm.ainvoke(messages)
        content = _response_to_text(response)
        parsed = _json_or_error_payload("FunctionAnalysisAgent", content)
        # For single-call analyze, keep strict behavior by raising on parse failure.
        if "error" in parsed:
            raise LLMResponseError(
                "Failed to parse JSON response from FunctionAnalysisAgent",
                raw_response=content,
            )
        return parsed

    async def analyze_decompiled_batch(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch analyze decompiled functions.

        Input: [{"name": str, "code": str}, ...]
        Output: [{"name": str, "analysis": dict}, ...]

        Notes:
        - Uses LangChain batch APIs with max_concurrency.
        - Per-item JSON parse failures are returned as an "analysis" error payload
          rather than failing the whole batch.
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

        message_batches = [
            [
                SystemMessage(content=self.agent_config.system_prompt),
                HumanMessage(content=str(code)),
            ]
            for code in prepared_codes
        ]
        config = {"max_concurrency": self.agent_config.max_concurrency}

        try:
            try:
                responses = await self.llm.abatch(message_batches, config=config)
            except AttributeError:
                responses = self.llm.batch(message_batches, config=config)
        except Exception as e:
            # Normalize LLM invocation errors into a typed application exception.
            raise LLMResponseError(
                f"FunctionAnalysisAgent batch invocation failed: {e}",
                raw_response=None,
            ) from e

        analyses: List[Dict[str, Any]] = []
        for resp in responses:
            content = _response_to_text(resp)
            parsed = _json_or_error_payload("FunctionAnalysisAgent", content)
            if "error" in parsed:
                logger.error("Failed to parse JSON from LLM response", exc_info=True)
            analyses.append(parsed)

        return [
            {"name": name, "analysis": analysis}
            for name, analysis in zip(prepared_names, analyses)
        ]

class MalwareAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.MalwareAnalysisAgent
        if not self.agent_config.llm.api_key or self.agent_config.llm.api_key.strip() in {"", "YOUR_API_KEY_HERE"}:
            raise ValueError("Missing LLM API key in agents/config.yaml (MalwareAnalysisAgent.llm.api_key)")

        # 从配置中初始化 Rate Limiter
        rl_config = self.agent_config.rate_limit
        rate_limiter = None
        if rl_config:
            rate_limiter = InMemoryRateLimiter(
                requests_per_second=rl_config.requests_per_second,
                check_every_n_seconds=rl_config.check_every_n_seconds,
                max_bucket_size=rl_config.max_bucket_size,
            )

        llm_params = {
            "name": "MalwareAnalysisAgent",
            "base_url": self.agent_config.llm.base_url,
            "model": self.agent_config.llm.model_name,
            "api_key": self.agent_config.llm.api_key,
            "max_retries": self.agent_config.llm.max_retries,
            "timeout": self.agent_config.llm.timeout,
            "max_completion_tokens": self.agent_config.llm.max_completion_tokens,
            "rate_limiter": rate_limiter,
            "model_kwargs": {"response_format": {"type": "json_object"}}
        }
        # 过滤掉为 None 的参数，确保空值时使用 LangChain 或 Provider 的默认值
        llm_params = {k: v for k, v in llm_params.items() if v is not None}
        self.llm = ChatOpenAI(**llm_params)

    async def analyze(self, analysis_results: list, metadata: dict) -> dict:
        context = {
            "metadata": metadata,
            "function_analyses": analysis_results
        }
        messages = [
            SystemMessage(content=self.agent_config.system_prompt),
            HumanMessage(content=f"{json.dumps(context, ensure_ascii=False, indent=2)}")
        ]
        response = await self.llm.ainvoke(messages)
        content = _response_to_text(response)
        parsed = _json_or_error_payload("MalwareAnalysisAgent", content)
        if "error" in parsed:
            raise LLMResponseError(
                "Failed to parse JSON response from MalwareAnalysisAgent",
                raw_response=content,
            )
        return parsed

