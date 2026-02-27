# module/AGENTS.md

本模块目前包含 `ghidra_pipe/` 与 `ghidra_mcp/`：
- `ghidra_pipe/`：**Ghidra 引擎 HTTP 服务**（FastAPI），封装 pyghidra 调用，为上层提供结构化的二进制分析数据、交叉引用与反编译结果。
- `ghidra_mcp/`：**FastMCP 工具服务**（HTTP），对外暴露反编译与交叉引用工具，复用 ghidra_pipe 的当前 analyzer 状态。

> 关键设计：服务端维护"当前打开的二进制"的全局状态，因此系统整体分析必须单并发执行（由 backend worker 强制）。

---

## 1. 模块边界与职责

**本模块做什么**
- 启动一个 HTTP 服务（默认 :8000），暴露 `upload/analyze/metadata/functions/exports/strings/callgraph/xrefs/xrefs_batch/decompile_batch` 等接口。
- 管理 pyghidra 生命周期：初始化 JVM、打开二进制、执行分析、返回 JSON。
- 通过 Ghidra DecompInterface 提供反编译能力。
- 启动一个 MCP 服务（默认 :9000），提供只读工具 `decompile_function` 与 `function_xrefs`。

**本模块不做什么**
- 不做任务排队/去重/落库（backend 负责）。
- 不做 AI/LLM 分析（agents 负责）。

---

## 2. 目录与关键文件

- `ghidra_pipe/main.py`
  - FastAPI 路由定义
  - 全局变量：`analyzer`（当前打开的二进制）、`analyzer_lock`（RLock）
  - 上传目录：`<repo_root>/data/uploads/`
- `ghidra_pipe/analyzer.py`
   - `ghidra_mcp/main.py`
    - FastMCP server，基于 `/decompile` 与 `/xrefs` 封装为 MCP 工具
    - 运行地址默认 `http://localhost:9000/mcp`
  - `GhidraAnalyzer`：对 pyghidra 的轻量封装，统一返回结构化 JSON。
  - 关键功能映射：
    - `get_info()`：元信息（format, arch, bits 等）
    - `get_functions()`：函数列表
    - `get_strings()`：字符串
    - `get_global_call_graph()`：全局调用图
    - `get_decompiled_code_batch()`：批量反编译（DecompInterface）
    - `get_function_xrefs()` / `get_function_xrefs_batch()`：函数 callers/callees

---

## 3. 全局状态模型（最重要的设计点）

`ghidra_pipe/main.py` 维持一个全局 `analyzer`：
- `POST /upload` 会关闭旧 analyzer、打开新 analyzer。
- 其余接口都依赖"当前 analyzer 已打开"。

因此：
- **该服务不支持多样本并发**。
- 即便服务端使用锁保证一次只处理一个请求，也无法保证跨样本隔离（因为 analyzer 本身就是单实例）。
- 上层必须保证同一时刻只驱动一个样本分析：当前由 `backend/worker/AnalysisWorker._analysis_lock` 强制。

---

## 4. HTTP API（ghidra_pipe 服务）

路由定义：`ghidra_pipe/main.py`

### 4.1 GET /health_check
返回：`{"status": "ok"}`

### 4.2 POST /upload
输入：multipart/form-data `file`

行为：
- 将上传文件写入 `<repo_root>/data/uploads/`。
- 文件名进行白名单过滤并加 uuid 前缀，避免路径/文件系统问题。
- 切换全局 `analyzer` 到新文件。

返回：`{"status": "ok"}`（刻意不返回服务器文件路径，避免路径泄露）。

### 4.3 GET /analyze?level=full
行为：
- 执行 Ghidra 自动分析（analyzeAll）。
- 返回：`{"status": "done"}` 或 error。

### 4.4 GET /metadata
返回：`GhidraAnalyzer.get_info()` -> 包含 core 和 bin 信息的 JSON

### 4.5 GET /functions
返回：`GhidraAnalyzer.get_functions()` -> JSON 列表
- 每个函数：`{name, offset, size, signature}`

### 4.6 GET /strings
返回：`GhidraAnalyzer.get_strings()` -> JSON 列表
- 每个字符串：`{string, vaddr, section, type, length}`

### 4.6.1 GET /exports
返回：`GhidraAnalyzer.get_exports()` -> JSON 列表
- 每个导出项固定为：`{name, offset}`

### 4.7 GET /callgraph
返回：`GhidraAnalyzer.get_global_call_graph()`
- `{nodes: [{id, name, offset}, ...], edges: [{from, to}, ...]}`

### 4.8 POST /decompile_batch
输入：JSON 数组 `List[str]`
- 每一项可以是函数名或地址（例如 `main`、`FUN_00001234`、`0x401000`）。

输出：JSON 列表
- `[{"address": "<name_or_addr>", "code": "<decompiled_text>"}, ...]`

### 4.9 GET /xrefs
输入：query 参数 `addr=<function_name_or_addr>`

输出：
- `{name, offset, callers, callees}`

### 4.10 POST /xrefs_batch
输入：JSON 数组 `List[str]`

输出：
- `[{name, offset, callers, callees}, ...]`

重要语义：
- 批量反编译逐个执行 DecompInterface.decompileFunction。
- 某个函数反编译失败时会被 try/except 吞掉，该项 **不会出现在返回列表中**（"缺项语义"）。
- 上游（agents）必须容忍并以"能拿到多少算多少"的策略继续。

---

## 4.11 MCP API（ghidra_mcp 服务）

### 4.11.1 Tool: decompile_function
输入：`target`（函数名或地址）
输出：`{address, code}`（来自 ghidra_pipe /decompile）

### 4.11.2 Tool: function_xrefs
输入：`target`（函数名或地址）
输出：`{name, offset, callers, callees}`（来自 ghidra_pipe /xrefs）

## 5. GhidraAnalyzer 封装约定

实现：`ghidra_pipe/analyzer.py`

- 使用 `pyghidra.open_program()` 打开二进制。
- 使用 `flat_api.analyzeAll(program)` 执行分析。
- 反编译通过 `DecompInterface` + `decompileFunction()` 实现。
- 字符串通过遍历 Listing 的 DefinedData 提取。
- 调用图通过 ReferenceManager 查找 CALL 类型引用构建。

---

## 6. 部署与依赖

- 运行方式：
  - 本地：`python module/ghidra_pipe/main.py`（默认 8000）
  - 本地 MCP：`python module/ghidra_mcp/main.py`（默认 9000）
  - Docker：见 `docker/Dockerfile.ghidra` 与 `docker-compose.yml`
- 依赖：
  - `pyghidra` Python 包（需要 Ghidra 12+）
  - `JPype1` 用于 Python-Java 桥接
  - 容器/系统内的 Ghidra 安装（`GHIDRA_INSTALL_DIR` 环境变量）
  - JDK/JRE（Ghidra 12 需要 JDK 21+）

---

## 7. 扩展点与开发指引

### 7.1 新增能力（新增路由/新增功能）
建议流程：
1. 在 `GhidraAnalyzer` 中新增一个方法
2. 在 `ghidra_pipe/main.py` 中新增对应 FastAPI 路由
3. 在 `agents/config.yaml` 同步新增 endpoints 映射
4. 在 `agents/ghidra_client.py` 新增客户端方法
5. 在 `agents/analysis_coordinator.py` 中接入并决定是否需要落库

### 7.2 并发升级路线图
若要支持多样本并发：
- 需要将 ghidra_pipe 从"全局 analyzer"改为"每任务独立 analyzer"（会话 ID、或多进程/多容器池化）。
- 同时需要重新设计 API：upload 返回 session_id，后续所有请求携带 session_id。
- 考虑 Ghidra/JVM 内存占用较大，建议采用多容器池化方案。

---

## 8. 与其他模块的契约（速查）

- agents 通过 `GhidraClient` 调用本服务（base_url 由 `PTW_GHIDRA_BASE_URL` 或 config.yaml 指定）。
- backend 通过 worker 单并发驱动 agents，从而间接使用本服务。
