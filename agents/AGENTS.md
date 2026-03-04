# agents/AGENTS.md

本模块是 **AI 编排层**：负责调用 Ghidra HTTP 服务获取静态分析/反编译结果，并将结果组织成上下文，调用 LLM 生成"函数级分析"与"最终恶意软件报告"。

> 推荐调用链路：`backend/worker` -> `backend/core/factory.create_coordinator()` -> `agents/analysis_coordinator.AnalysisCoordinator`。

---

## 1. 模块边界与职责

**本模块做什么**
- 定义并实现"分析流水线"（上传样本 -> Ghidra 深度分析 -> 拉取元数据/函数/字符串/调用图 -> 批量反编译 -> LLM 批量函数分析 -> 过滤关键函数 -> LLM 总结报告）。
- 封装 Ghidra HTTP 服务的客户端与接口契约（endpoint key -> path 映射、超时、重试）。
- 封装两类 LLM Agent，并强制 **JSON object** 输出格式，供后端落库。

**本模块不做什么**
- 不负责持久化、任务排队、去重（这些在 `backend/`）。
- 不负责前端展示与交互（这些在 `frontend/`）。
- 不负责多样本并发隔离（Ghidra 服务侧存在全局状态，单并发策略在 `backend/worker` 强制）。

---

## 2. 目录与关键文件

- `analysis_coordinator.py`
  - `AnalysisCoordinator`: 分析编排入口；实现完整流水线。
- `ghidra_client.py`
  - `GhidraClient`: Ghidra HTTP 客户端；封装请求、超时、重试、返回解析。
- `agent_core.py`
  - `FunctionAnalysisAgent`: 对单个函数反编译文本做结构化分析（JSON）。
  - `MalwareAnalysisAgent`: 汇总关键函数分析 + metadata 生成最终报告（JSON）。
  - `LLMResponseError`: JSON 解析失败/调用失败的统一异常（来自 `exceptions.py`）。
- `config_loader.py`
  - `AppConfig`/`PluginConfig`/`AgentConfig`: Pydantic 配置模型。
  - `load_config()`: 加载 `agents/config.yaml`，并支持通过环境变量覆盖部分配置。
- `config.yaml` / `config.yaml.example`
  - Ghidra 插件 base_url 与 endpoints 映射；两类 Agent 的模型、key、prompt 路径、并发等。
- `exceptions.py`
  - `GhidraBackendError`, `LLMResponseError` 等异常类型。
- `main.py`
  - FastAPI 聚合服务（**更像 legacy/实验入口**）。生产/容器编排通常以 `backend` 为主入口。

---

## 3. 分析流水线（核心架构）

入口：`AnalysisCoordinator.analyze_content(filename: str, content: bytes, content_type: str)`

### 3.1 端到端步骤
`AnalysisCoordinator` 当前实现的流水线（按代码日志顺序）：

1. **健康检查**：`GhidraClient.check_health()`
2. **上传样本**：`GhidraClient.upload_file(filename, content, content_type)`
3. **深度分析**：`GhidraClient.trigger_analysis()`（Ghidra analyzeAll）
4. **元数据**：`GhidraClient.get_metadata()`（包含 core 和 bin 信息）
5. **函数列表**：`GhidraClient.get_functions()`（来自 FunctionManager）并整理为 `functions_data`
5.5 **导出表**：`GhidraClient.get_exports()`（GET `/exports`，每项固定 `{name, offset}`）
6. **字符串**：`GhidraClient.get_strings()`（来自 Listing DefinedData）
7. **全局调用图**：`GhidraClient.get_callgraph()`（来自 ReferenceManager）
7.5 **函数交叉引用**：`GhidraClient.get_function_xrefs_batch(func_names)`（POST `/xrefs_batch`）
8. **批量反编译**：`GhidraClient.get_decompiled_codes_batch(func_names)`（POST `/decompile_batch`）
9. **函数级 AI 分析**：`FunctionAnalysisAgent.analyze_decompiled_batch(target_funcs)`
9.5 **筛选关键函数**：仅保留 `attack_matches` 非空的函数交给最终报告（ATT&CK 聚焦降噪）
10. **最终报告**：`MalwareAnalysisAgent.analyze(analysis_results=key_functions, metadata=metadata)`

最终返回（供 backend 落库）字段：
- `metadata`
- `functions`
- `strings`
- `decompiled_code`
- `function_xrefs`
- `function_analyses`
- `malware_report`

### 3.2 目标函数选择策略
`AnalysisCoordinator` 会从反编译结果中选出要喂给 LLM 的目标函数：
- `FUN_*` 自动命名函数（Ghidra 常见前缀）
- 常见入口点：`main/WinMain/DllMain/_start` 及若干 CRT 启动符号（见 `_is_ai_target_function()`）
- 导出表函数：按导出名匹配，并结合导出地址（offset）与函数入口地址匹配，避免导出符号被漏掉

这样做的目的：减少无关函数带来的 token 成本与噪音。

---

## 4. GhidraClient 与 HTTP 契约

### 4.1 endpoint key -> path 映射
`GhidraClient` 使用 `config.plugins["ghidra"].endpoints` 将 key 映射到 path。
- 文档/实现约定：新增/修改 Ghidra HTTP 路由时，**必须同步更新** `agents/config.yaml` 的 `plugins.ghidra.endpoints`。

默认 endpoints 参考：`agents/config.yaml.example`。

### 4.2 超时与重试
`GhidraClient` 基于 httpx：
- 默认 timeout：`httpx.Timeout(60.0, connect=10.0)`，单个接口可覆盖。
- transport 重试：`httpx.AsyncHTTPTransport(retries=3)`。
- 分析与反编译超时更长：
  - `trigger_analysis()`：300s（Ghidra 分析比 Rizin 慢）
  - `get_decompiled_codes_batch()`：900s

### 4.3 重要返回形状（简要）
- `GET /exports` 出参：`[{"name": "<export_name>", "offset": <int>}, ...]`
- `POST /decompile_batch` 入参：JSON 数组 `List[str]`（地址或函数名）
- `POST /decompile_batch` 出参：`[{"address": "<name_or_addr>", "code": "..."}, ...]`
  - 注意：ghidra_pipe 端会"吞异常并跳过失败项"，上游必须容忍缺项。

---

## 5. LLM Agents（严格 JSON 输出）

### 5.1 输出必须为 JSON object
两类 Agent 都在 `ChatOpenAI` 的 `model_kwargs` 设置：
- `{"response_format": {"type": "json_object"}}`

解析策略：
- **单次** `FunctionAnalysisAgent.analyze()`：解析失败会抛 `LLMResponseError`（强失败）。
- **批量** `FunctionAnalysisAgent.analyze_decompiled_batch()`：逐项解析，解析失败不会整体抛错，而是返回包含 `error/raw_response` 的 payload（便于最终报告过滤/落库）。
- `MalwareAnalysisAgent.analyze()`：解析失败会抛 `LLMResponseError`。

### 5.2 并发与截断
- 批量分析：`FunctionAnalysisAgent.analyze_decompiled_batch()` 逐个函数顺序调用 LLM。
- 输入截断：`_truncate_code_for_context()` 会依据 `llm.max_input_tokens` 做保守截断，避免超上下文。

---

## 6. 配置（config.yaml）与环境变量

### 6.1 YAML 配置
`agents/config.yaml`（与 `.example` 对齐）主要包含：
- `plugins.ghidra.base_url`：Ghidra HTTP 服务地址
- `plugins.ghidra.endpoints`：key->path
- `FunctionAnalysisAgent` 与 `MalwareAnalysisAgent`：
  - `system_prompt_path`：prompt 文件路径（相对 `agents/`）
  - `llm.*`：`model_name/base_url/api_key/timeout/max_retries/max_completion_tokens/max_input_tokens/extra_body` 等
  - `rate_limit.*`：速率限制参数

### 6.2 环境变量覆盖
`config_loader.load_config()` 支持：
- `PTW_GHIDRA_BASE_URL`：覆盖 `plugins.ghidra.base_url`（Docker/生产常用）。

---

## 7. 并发与全局状态约束（重要）

- Ghidra 服务（`module/ghidra_pipe`）维护"当前打开二进制"的 **全局 analyzer** 状态。
- 因此系统级约束是：**同一时刻只能分析一个样本**，否则会互相覆盖。
- `backend/worker` 通过 `_analysis_lock` 强制单并发（这不是 bug，是设计约束）。

---

## 8. 扩展点与开发指引

### 8.1 新增/修改 Ghidra 能力
1. 在 `module/ghidra_pipe/analyzer.py` 增加方法
2. 在 `module/ghidra_pipe/main.py` 增加路由
3. 同步 `agents/config.yaml` 的 endpoints
4. 在 `agents/ghidra_client.py` 增加对应方法
5. 在 `analysis_coordinator.py` 接入并把结果打包到返回结构（如需要落库，亦需同步 backend 模型列）

### 8.2 新增分析策略
- 函数筛选：修改 `AnalysisCoordinator._is_ai_target_function()` 或新增规则
- 重点函数过滤：修改 `attack_matches` 选择逻辑（当前是"非空即重点"）

### 8.3 新增报告字段
- 扩展两类 Agent prompt + 解析后的 JSON schema
- 同步 `backend/models/task.py` 分列字段与 `backend/api` 返回字段
- 同步前端渲染（`frontend/src/components/ReportView.jsx`）

---

## 9. 与其他模块的契约（速查）

- Ghidra HTTP：默认 `http://localhost:8000`（由 `PTW_GHIDRA_BASE_URL` 覆盖）
- Backend 会通过 `backend/core/factory.py` 创建 coordinator 并驱动本模块
- 前端不直接调用本模块，只调用 backend 的 `/api/*`
