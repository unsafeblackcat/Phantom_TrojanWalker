# module/AGENTS.md

本模块目前主要包含 `rz_pipe/`：一个 **Rizin 引擎 HTTP 服务**（FastAPI），封装 rzpipe 调用，为上层提供结构化的二进制分析数据与反编译结果。

> 关键设计：服务端维护“当前打开的二进制”的全局状态，因此系统整体分析必须单并发执行（由 backend worker 强制）。

---

## 1. 模块边界与职责

**本模块做什么**
- 启动一个 HTTP 服务（默认 :8000），暴露 `upload/analyze/metadata/functions/strings/callgraph/decompile_batch` 等接口。
- 管理 rzpipe 生命周期：打开二进制、执行分析命令、返回 JSON。
- 通过 rizin-ghidra 插件提供反编译能力（`pdgj`）。

**本模块不做什么**
- 不做任务排队/去重/落库（backend 负责）。
- 不做 AI/LLM 分析（agents 负责）。

---

## 2. 目录与关键文件

- `rz_pipe/main.py`
  - FastAPI 路由定义
  - 全局变量：`analyzer`（当前打开的二进制）、`analyzer_lock`（RLock）
  - 上传目录：`<repo_root>/data/uploads/`
- `rz_pipe/analyzer.py`
  - `RizinAnalyzer`：对 rzpipe 的轻量封装，统一用 `cmdj()` 获取结构化 JSON。
  - 关键命令映射：
    - `ij`：元信息
    - `aflj`：函数列表
    - `izj`：字符串
    - `agC json`：全局调用图
    - `pdgj`：反编译（rizin-ghidra）

---

## 3. 全局状态模型（最重要的设计点）

`rz_pipe/main.py` 维持一个全局 `analyzer`：
- `POST /upload` 会关闭旧 analyzer、打开新 analyzer。
- 其余接口都依赖“当前 analyzer 已打开”。

因此：
- **该服务不支持多样本并发**。
- 即便服务端使用锁保证一次只处理一个请求，也无法保证跨样本隔离（因为 analyzer 本身就是单实例）。
- 上层必须保证同一时刻只驱动一个样本分析：当前由 `backend/worker/AnalysisWorker._analysis_lock` 强制。

---

## 4. HTTP API（rz_pipe 服务）

路由定义：`rz_pipe/main.py`

### 4.1 GET /health_check
返回：`{"status": "ok"}`

### 4.2 POST /upload
输入：multipart/form-data `file`

行为：
- 将上传文件写入 `<repo_root>/data/uploads/`。
- 文件名进行白名单过滤并加 uuid 前缀，避免路径/文件系统问题。
- 切换全局 `analyzer` 到新文件。

返回：`{"status": "ok"}`（刻意不返回服务器文件路径，避免路径泄露）。

### 4.3 GET /analyze?level=aaa
行为：
- 默认执行 `aaa` 深度分析。
- 返回：`{"status": "done"}` 或 error。

### 4.4 GET /metadata
返回：`RizinAnalyzer.get_info()` -> `ij` 的 JSON

### 4.5 GET /functions
返回：`RizinAnalyzer.get_functions()` -> `aflj` 的 JSON 列表

### 4.6 GET /strings
返回：`RizinAnalyzer.get_strings()` -> `izj` 的 JSON 列表

### 4.7 GET /callgraph
返回：`RizinAnalyzer.get_global_call_graph()` -> `agC json`

### 4.8 POST /decompile_batch
输入：JSON 数组 `List[str]`
- 每一项可以是函数名或地址（例如 `sym.main`、`fcn.00001234`、`0x401000`）。

输出：JSON 列表
- `[{"address": "<name_or_addr>", "code": "<decompiled_text>"}, ...]`

重要语义：
- 批量反编译逐个执行 `pdgj @ <addr_or_name>`。
- 某个函数反编译失败时会被 try/except 吞掉，该项 **不会出现在返回列表中**（“缺项语义”）。
- 上游（agents）必须容忍并以“能拿到多少算多少”的策略继续。

---

## 5. RizinAnalyzer 封装约定

实现：`rz_pipe/analyzer.py`

- 优先使用 `cmdj()` 获取结构化输出（JSON），便于上层消费。
- `open()`：
  - `rzpipe.open(file_path, flags=['-2'])`：减少 stderr 输出
  - `e ghidra.verbose=false`：降低 ghidra 插件日志噪音
- 反编译命令：`pdgj @ <addr_or_name>`（依赖 rizin-ghidra）

---

## 6. 部署与依赖

- 运行方式：
  - 本地：`python module/rz_pipe/main.py`（默认 8000）
  - Docker：见 `docker/Dockerfile.rzpipe` 与 `docker-compose.yml`
- 依赖：
  - `rzpipe` Python 包
  - 容器/系统内的 `rizin`
  - 反编译需 `rizin-ghidra` 插件（提供 `pdgj`）

---

## 7. 扩展点与开发指引

### 7.1 新增能力（新增路由/新增 rz 命令）
建议流程：
1. 在 `RizinAnalyzer` 中新增一个方法（优先 `cmdj()`）
2. 在 `rz_pipe/main.py` 中新增对应 FastAPI 路由
3. 在 `agents/config.yaml` 同步新增 endpoints 映射
4. 在 `agents/rizin_client.py` 新增客户端方法
5. 在 `agents/analysis_coordinator.py` 中接入并决定是否需要落库

### 7.2 并发升级路线图
若要支持多样本并发：
- 需要将 rz_pipe 从“全局 analyzer”改为“每任务独立 analyzer”（会话 ID、或多进程/多容器池化）。
- 同时需要重新设计 API：upload 返回 session_id，后续所有请求携带 session_id。

---

## 8. 与其他模块的契约（速查）

- agents 通过 `RizinClient` 调用本服务（base_url 由 `PTW_RIZIN_BASE_URL` 或 config.yaml 指定）。
- backend 通过 worker 单并发驱动 agents，从而间接使用本服务。
