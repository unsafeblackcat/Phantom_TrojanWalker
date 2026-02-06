import json
import os
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, field_validator, Field

class LLMConfig(BaseModel):
    model_name: str
    api_key: str
    temperature: Optional[float] = None
    base_url: Optional[str] = None
    max_retries: Optional[int] = None
    timeout: Optional[float] = None
    max_completion_tokens: Optional[int] = None
    max_input_tokens: Optional[int] = None
    extra_body: Optional[Dict[str, Any]] = None

    @field_validator("extra_body", mode="before")
    @classmethod
    def _parse_extra_body(cls, value: Any) -> Any:
        if value is None or isinstance(value, dict):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"LLM extra_body must be valid JSON: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("LLM extra_body must be a JSON object.")
            return parsed
        raise ValueError("LLM extra_body must be a JSON object or JSON string.")

class RateLimitConfig(BaseModel):
    requests_per_second: float = 1.0
    check_every_n_seconds: float = 0.1
    max_bucket_size: float = 1.0

class PluginConfig(BaseModel):
    base_url: str
    endpoints: Dict[str, str] = Field(default_factory=dict)

class AgentConfig(BaseModel):
    system_prompt: str = ""
    system_prompt_path: Optional[str] = None
    llm: LLMConfig
    rate_limit: Optional[RateLimitConfig] = None

class AppConfig(BaseModel):
    plugins: Dict[str, PluginConfig]
    FunctionAnalysisAgent: AgentConfig
    MalwareAnalysisAgent: AgentConfig

def load_config(config_path: str | None = None) -> AppConfig:
    resolved_path = _resolve_config_path(config_path)
    config = _load_yaml_config(resolved_path)
    _apply_env_overrides(config)
    _load_agent_prompts(config, resolved_path)
    return config


def _resolve_config_path(config_path: Optional[str]) -> str:
    """Resolve config path with a sensible default.

    Refactor note: isolate path resolution for readability and testability.
    """
    if config_path:
        return config_path
    # 默认查找与当前文件同目录下的 config.yaml
    return os.path.join(os.path.dirname(__file__), "config.yaml")


def _load_yaml_config(config_path: str) -> AppConfig:
    """Load YAML config file into AppConfig.

    Refactor note: keep I/O isolated for clearer error surface.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return AppConfig(**data)


def _apply_env_overrides(config: AppConfig) -> None:
    """Apply environment variable overrides.

    Refactor note: use a guard clause to reduce nesting.
    """
    ghidra_base_url = os.getenv("PTW_GHIDRA_BASE_URL")
    if ghidra_base_url and "ghidra" in config.plugins:
        config.plugins["ghidra"].base_url = ghidra_base_url

    mcp_base_url = os.getenv("PTW_MCP_BASE_URL")
    if mcp_base_url and "mcp" in config.plugins:
        config.plugins["mcp"].base_url = mcp_base_url


def _load_agent_prompts(config: AppConfig, config_path: str) -> None:
    """Load system prompts for agents from their configured paths.

    Refactor note: centralize prompt loading and path normalization.
    """
    config_dir = os.path.dirname(config_path)
    for agent_name in ["FunctionAnalysisAgent", "MalwareAnalysisAgent"]:
        agent_config = getattr(config, agent_name)
        prompt_path = agent_config.system_prompt_path
        if not prompt_path:
            continue  # Guard clause to simplify flow

        resolved_prompt_path = _resolve_prompt_path(prompt_path, config_dir)
        if not os.path.exists(resolved_prompt_path):
            continue

        with open(resolved_prompt_path, "r", encoding="utf-8") as f:
            agent_config.system_prompt = f.read()


def _resolve_prompt_path(prompt_path: str, config_dir: str) -> str:
    """Resolve prompt path relative to config directory if needed."""
    if os.path.isabs(prompt_path):
        return prompt_path
    return os.path.join(config_dir, prompt_path)

if __name__ == "__main__":
    config = load_config()
    print(config.model_dump())
