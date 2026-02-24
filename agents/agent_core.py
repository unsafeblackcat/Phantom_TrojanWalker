import json
import logging
import asyncio
from typing import Any, Dict, List, Optional

from langchain_openai import ChatOpenAI
from config_loader import load_config
from exceptions import LLMResponseError
from langchain.messages import SystemMessage, HumanMessage
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_mcp_adapters.client import MultiServerMCPClient

logger = logging.getLogger(__name__)

# Keep retries controlled by agent-level loops only.
# This prevents N (agent) * M (SDK) retry multiplication.
SDK_MAX_RETRIES = 0


def _log_exception_group(prefix: str, exc: Exception) -> None:
    logger.exception("%s: %s", prefix, exc)
    group_type = getattr(__import__("builtins"), "BaseExceptionGroup", None)
    if group_type and isinstance(exc, group_type):
        for idx, sub_exc in enumerate(exc.exceptions):
            logger.error("%s sub[%d]: %r", prefix, idx, sub_exc)


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


def _build_llm_params(
    agent_name: str,
    agent_cfg: Any,
    rate_limiter: Optional[InMemoryRateLimiter],
    include_response_format: bool = True,
) -> Dict[str, Any]:
    """Build LLM init params while filtering None values.

    Refactor note: centralizes default handling for consistency.
    """
    model_kwargs: Dict[str, Any] = {}
    if include_response_format:
        model_kwargs["response_format"] = {"type": "json_object"}
    if agent_cfg.llm.extra_body:
        model_kwargs["extra_body"] = agent_cfg.llm.extra_body

    params = {
        "name": agent_name,
        "base_url": agent_cfg.llm.base_url,
        "model": agent_cfg.llm.model_name,
        "api_key": agent_cfg.llm.api_key,
        # Disable SDK/internal retries; outer retry loop remains the single source of truth.
        "max_retries": SDK_MAX_RETRIES,
        "timeout": agent_cfg.llm.timeout,
        "max_completion_tokens": agent_cfg.llm.max_completion_tokens,
        "rate_limiter": rate_limiter,
        "model_kwargs": model_kwargs or None,
    }
    # 过滤掉为 None 的参数，确保空值时使用 LangChain 或 Provider 的默认值
    return {k: v for k, v in params.items() if v is not None}


def _create_llm(agent_name: str, agent_cfg: Any) -> ChatOpenAI:
    """Create a ChatOpenAI client with shared initialization logic."""
    _validate_api_key(agent_name, agent_cfg.llm.api_key)
    rate_limiter = _build_rate_limiter(agent_cfg.rate_limit)
    llm_params = _build_llm_params(agent_name, agent_cfg, rate_limiter, include_response_format=True)
    return ChatOpenAI(**llm_params)


def _create_summary_llm(agent_name: str, agent_cfg: Any) -> ChatOpenAI:
    """Create a lightweight ChatOpenAI client for summarization."""
    _validate_api_key(agent_name, agent_cfg.llm.api_key)
    rate_limiter = _build_rate_limiter(agent_cfg.rate_limit)
    llm_params = _build_llm_params(agent_name, agent_cfg, rate_limiter, include_response_format=False)
    return ChatOpenAI(**llm_params)

class FunctionAnalysisAgent:
    def __init__(self):
        self.config = load_config()
        self.agent_config = self.config.FunctionAnalysisAgent
        self.llm = _create_llm("FunctionAnalysisAgent", self.agent_config)
        # Retry attempts for JSON parse failures (fallback if not configured)
        self._json_retry_attempts = self._resolve_json_retry_attempts()

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
            try:
                response = await self.llm.ainvoke(messages)
            except Exception as exc:
                last_content = str(exc)
                logger.warning(
                    "FunctionAnalysisAgent LLM call failed (attempt %d/%d): %s",
                    attempt,
                    self._json_retry_attempts,
                    exc,
                )
                continue
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
                - JSON parse failures are captured per function to avoid aborting the batch.
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
            for attempt in range(1, self._json_retry_attempts + 1):
                try:
                    response = await self.llm.ainvoke(messages)
                except Exception as exc:
                    last_content = str(exc)
                    logger.warning(
                        "FunctionAnalysisAgent LLM call failed for %s (attempt %d/%d): %s",
                        name,
                        attempt,
                        self._json_retry_attempts,
                        exc,
                    )
                    continue
                content = _response_to_text(response)
                last_content = content
                parsed = _json_or_error_payload("FunctionAnalysisAgent", content)
                if "error" not in parsed:
                    return parsed
                logger.warning(
                    "FunctionAnalysisAgent JSON parse failed for %s (attempt %d/%d)",
                    name,
                    attempt,
                    self._json_retry_attempts,
                )
            return {
                "error": "Failed to parse JSON response from FunctionAnalysisAgent",
                "agent": "FunctionAnalysisAgent",
                "raw_response": last_content,
            }

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
        self.summary_llm = _create_summary_llm("MalwareAnalysisAgentSummary", self.agent_config)
        self.mcp_base_url = self._resolve_mcp_base_url()
        self._json_retry_attempts = self._resolve_json_retry_attempts()

    def _resolve_json_retry_attempts(self) -> int:
        # Prefer configured max_retries; ensure at least 1 attempt.
        max_retries = getattr(self.agent_config.llm, "max_retries", None)
        if isinstance(max_retries, int) and max_retries > 0:
            return max_retries
        return 3

    def _retry_delay(self, attempt: int) -> float:
        # Simple bounded backoff to avoid hammering the provider.
        return float(min(2 * attempt, 10))

    def _resolve_mcp_base_url(self) -> Optional[str]:
        plugins = getattr(self.config, "plugins", {})
        mcp_cfg = plugins.get("mcp") if isinstance(plugins, dict) else None
        base_url = getattr(mcp_cfg, "base_url", None)
        return str(base_url).rstrip("/") if base_url else None

    async def _call_mcp_tool(self, tool: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(tool, "ainvoke"):
                result = await tool.ainvoke(args)
            else:
                result = tool.invoke(args)
        except Exception as exc:
            logger.warning("MCP tool call failed: %s", exc)
            return {"error": str(exc)}

        if isinstance(result, dict):
            return result
        return {"data": result}

    async def _fetch_mcp_enrichment(self, analysis_results: list) -> List[Dict[str, Any]]:
        targets = []
        for item in analysis_results:
            name = item.get("name") if isinstance(item, dict) else None
            if name:
                targets.append(str(name))

        if not targets or not self.mcp_base_url:
            return []

        logger.info(
            "MCP enrichment enabled: base_url=%s targets=%d",
            self.mcp_base_url,
            len(targets),
        )

        client = MultiServerMCPClient(
            {
                "ghidra": {
                    "transport": "http",
                    "url": self.mcp_base_url,
                }
            }
        )
        try:
            tools = await client.get_tools()
        except Exception as exc:
            _log_exception_group("MCP get_tools failed", exc)
            return []

        tool_map = {tool.name: tool for tool in tools}
        if not tool_map:
            logger.warning("MCP returned no tools from server")

        def _resolve_tool(name: str) -> Optional[Any]:
            direct = tool_map.get(name)
            if direct:
                return direct
            # Some MCP adapters prefix tool names with server identifiers.
            for tool_name, tool in tool_map.items():
                if tool_name.endswith(name):
                    return tool
            return None

        decompile_tool = _resolve_tool("decompile_function")
        xrefs_tool = _resolve_tool("function_xrefs")
        if not decompile_tool or not xrefs_tool:
            logger.warning("MCP tools missing from server: %s", list(tool_map.keys()))
            return []

        enrichment: List[Dict[str, Any]] = []
        for name in targets:
            decompiled = await self._call_mcp_tool(
                decompile_tool,
                args={"target": name},
            )
            xrefs = await self._call_mcp_tool(
                xrefs_tool,
                args={"target": name},
            )
            enrichment.append({
                "name": name,
                "decompile": decompiled,
                "xrefs": xrefs,
            })

        return enrichment

    async def analyze(self, analysis_results: list, metadata: dict) -> dict:
        context = {
            "metadata": metadata,
            "function_analyses": analysis_results,
        }

        if self.mcp_base_url:
            try:
                context["mcp_enrichment"] = await self._fetch_mcp_enrichment(analysis_results)
            except Exception as exc:
                logger.warning("MCP enrichment failed: %s", exc)

        messages = [
            {"role": "system", "content": self.agent_config.system_prompt},
            {"role": "user", "content": json.dumps(context, ensure_ascii=False, indent=2)},
        ]

        last_content = ""
        for attempt in range(1, self._json_retry_attempts + 1):
            try:
                content = await self._invoke_with_summarization_middleware(messages)
            except Exception as exc:
                last_content = str(exc)
                logger.warning(
                    "MalwareAnalysisAgent LLM call failed (attempt %d/%d): %s",
                    attempt,
                    self._json_retry_attempts,
                    exc,
                )
            else:
                last_content = content
                parsed = _json_or_error_payload("MalwareAnalysisAgent", content)
                if "error" not in parsed:
                    return parsed
                logger.warning(
                    "MalwareAnalysisAgent JSON parse failed (attempt %d/%d)",
                    attempt,
                    self._json_retry_attempts,
                )

            if attempt < self._json_retry_attempts:
                await asyncio.sleep(self._retry_delay(attempt))

        raise LLMResponseError(
            "Failed to parse JSON response from MalwareAnalysisAgent",
            raw_response=last_content,
        )

    async def _invoke_with_summarization_middleware(self, messages: List[Dict[str, str]]) -> str:
        from langchain.agents import create_agent
        from langchain.agents.middleware import SummarizationMiddleware

        max_input_tokens = getattr(self.agent_config.llm, "max_input_tokens", None)
        trigger_tokens = 100000
        if isinstance(max_input_tokens, int) and max_input_tokens > 0:
            trigger_tokens = int(max_input_tokens * 0.9)

        middleware = SummarizationMiddleware(
            model=self.summary_llm,
            trigger=("tokens", trigger_tokens),
            keep=("messages", 10),
            summary_prompt="你是一位拥有深厚逆向工程背景的**资深恶意软件分析师**，以下是你之前的分析结果，由于上下文长度限制，需要对其进行总结以便继续分析：",
        )
        agent = create_agent(
            model=self.llm,
            tools=[],
            middleware=[middleware],
        )
        if hasattr(agent, "ainvoke"):
            result = await agent.ainvoke({"messages": messages})
        else:
            result = agent.invoke({"messages": messages})

        if isinstance(result, dict) and "output" in result:
            return _response_to_text(result["output"])
        if isinstance(result, dict) and "messages" in result and result["messages"]:
            return _response_to_text(result["messages"][-1])
        return _response_to_text(result)
