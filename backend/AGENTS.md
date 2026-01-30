# backend/AGENTS.md

本模块是 **后端任务系统 + 对外 API**：负责上传样本、按 sha256 去重、创建任务、持久化分析结果，并通过 worker 异步驱动 `agents/` 的分析编排。

> 前端只应调用 `backend` 的 `/api/*`，不要直接访问 `agents` 或 `module/rz_pipe`。

---

## 1. 模块边界与职责

**本模块做什么**
- 提供对前端稳定的 API：上传分析、查询任务、按 hash 查结果、历史列表。
- 上传落盘并计算 sha256；按内容去重以复用既有任务。
- 维护任务表（SQLite），将分析结果拆分为多列 JSON 字段落库。
- 启动后台 worker：出队任务，调用 coordinator 进行分析，写回任务状态与结果。

**本模块不做什么**
- 不直接解析二进制，不直接运行 rzpipe；这些在 `module/rz_pipe`。
- 不直接实现 AI prompt/LLM 调用；这些在 `agents/`。

---

## 2. 目录与关键文件

- `main.py`
  - FastAPI app 入口；通常负责挂载路由、CORS、启动 worker（取决于实现）。
- `api/endpoints.py`
  - `/api/analyze`：上传并创建/复用任务（去重逻辑在这里）。
  - `/api/tasks/{task_id}`：查询任务状态与完整结果。
  - `/api/result/{sha256}`：按 hash 查询最近一次分析。
  - `/api/history`：最近任务摘要。
- `models/task.py`
  - `AnalysisTask`：任务表模型，结果按列拆分（metadata/functions/strings/decompiled_code/function_analyses/malware_report）。
- `worker/worker.py`
  - `AnalysisWorker`：内存队列 + requeue + 单并发分析锁。
- `database.py`
  - SQLAlchemy engine/session；默认 SQLite 文件。
- `core/factory.py`
  - `create_coordinator()`：加载 `agents/config.yaml`，创建 `RizinClient` 与 LLM agents，返回 `AnalysisCoordinator`。

---

## 3. 核心数据模型（AnalysisTask）

定义见 `models/task.py`。

### 3.1 关键字段
- `task_id`：对外暴露的 UUID（前端用它轮询）
- `sha256`：内容哈希（去重键）
- `filename`：原始文件名（展示用途）
- `file_path`：后端本地存储路径（内部字段，不应对外泄露）
- `status`：`pending | processing | completed | failed`

### 3.2 结果分列（重要约定）
为避免把所有结果塞到一个大 blob，本项目将结果拆到多列 JSON：
- `metadata_info`
- `functions`
- `strings`
- `decompiled_code`
- `function_analyses`
- `malware_report`

worker 会将 coordinator 返回的 dict 逐列写回（见 `worker/worker.py`）。

---

## 4. 对外 HTTP API（/api）

路由定义：`api/endpoints.py`（router 通常在 `backend/main.py` 挂载到 `/api` 前缀）。

### 4.1 POST /api/analyze
用途：上传样本并创建任务，或复用已存在任务。

输入：multipart/form-data
- `file`: UploadFile（必填）
- `sha256`: str（可选；客户端预计算的 sha256，用于校验/去重提示；服务端仍会自行计算）

行为要点：
- 服务端流式写入临时文件，同时增量计算 sha256（避免一次性读入大文件）。
- 校验 `sha256` 格式（如果提供）且必须与服务端计算值一致。
- 去重：如果 DB 中存在相同 sha256 且状态为 `completed/pending/processing`，直接返回现有任务。
- 最终落盘文件名使用 sha256（稳定、安全，避免路径问题）。

返回（典型字段）：
- `task_id`, `status`, `message`, `sha256`

### 4.2 GET /api/tasks/{task_id}
用途：前端轮询任务状态与结果。

返回包含：
- 元信息：`task_id/status/sha256/filename/created_at/finished_at/error`
- 结果列：`metadata/functions/strings/decompiled_code/function_analyses/malware_report`

### 4.3 GET /api/result/{sha256}
用途：按 hash 直接获取最近一次任务结果（常用于“已分析过的样本”快速查询）。

### 4.4 GET /api/history?limit=10
用途：获取最近任务摘要列表（当前前端未必已接入，可作为扩展点）。

---

## 5. 上传存储与安全约束

实现要点在 `api/endpoints.py`：
- 临时文件：`.tmp_<uuid>`
- 存储目录：`<repo_root>/data/uploads/`
- 最终文件名：`<sha256>`
- 使用 `os.path.commonpath` 校验，防路径穿越。
- `PTW_MAX_UPLOAD_BYTES` 控制最大上传大小（默认 200MB）。

---

## 6. Worker 架构（异步、单并发）

实现：`worker/worker.py`

### 6.1 队列与启动恢复
- 使用 `asyncio.Queue()`（内存队列）。
- worker 启动时执行 `_requeue_unfinished_tasks()`：
  - 把 DB 中 `processing` 的任务回滚为 `pending`
  - 将 `pending/processing` 的任务重新入队

### 6.2 单并发分析（系统级约束）
- `AnalysisWorker` 使用 `_analysis_lock = asyncio.Lock()` 包裹每次 `run_analysis()`。
- 根因：`module/rz_pipe` 维护“当前打开二进制”的全局 analyzer 状态，多任务并发会互相覆盖。

这意味着：
- 后端可以同时接受多个上传并创建多个 pending 任务。
- 但分析执行是串行的，长队列时前端会看到较长的 pending/processing。

### 6.3 分析执行与落库
`run_analysis(task_id)`：
- 标记任务 `processing`
- 从 `file_path` 读取内容
- 调用 `self.coordinator.analyze_content(task.sha256, content)`
- 成功：写回结果分列 + `finished_at` + `completed`
- 失败：写 `failed` + `error_message`

---

## 7. 配置与环境变量

### 7.1 backend 环境变量
- `PTW_MAX_UPLOAD_BYTES`：最大上传字节数
- `PTW_CORS_ORIGINS`：允许跨域来源列表（逗号分隔）。未设置时默认允许：
  - `http://localhost:5173`（Vite dev）
  - `http://localhost:3000`
  - `http://localhost:8080`（frontend server.mjs）
- `BACKEND_HOST`：后端监听地址（默认 `0.0.0.0`）
- `BACKEND_PORT`：后端端口（默认 `8001`）
- `BACKEND_RELOAD`：是否开启 uvicorn reload（默认开启，`1/true/yes/y`）

### 7.2 下游 agents/rz_pipe 配置
- `core/factory.py` 加载 `agents/config.yaml`
- `agents/config_loader.py` 支持 `PTW_RIZIN_BASE_URL` 覆盖 Rizin base_url（Docker 中由 compose 注入）

---

## 8. 扩展点与开发指引

### 8.1 新增结果字段
- 扩展 `AnalysisTask` 增加新列
- 修改 `worker.run_analysis()` 将 coordinator 输出写入新列
- 修改 `api/endpoints.py` 的返回 payload 暴露该列
- 同步前端渲染

### 8.2 新增 API
- 在 `api/endpoints.py` 增加路由
- 注意避免泄露内部字段（例如 `file_path`）

### 8.3 并发升级（路线图）
若未来要支持多样本并发分析：
- 需要 `module/rz_pipe` 从“全局 analyzer”升级为“会话隔离/多实例”，或引入多进程/多容器的 rzpipe 池。
- 对应地，backend 的 `_analysis_lock` 才能放开。

---

## 9. 与其他模块的契约（速查）

- 前端：调用 `backend` 的 `/api/*`（Vite dev proxy 或生产 server-side proxy）。
- agents：由 `backend/core/factory.py` 创建 coordinator 间接使用。
- rz_pipe：由 `agents/RizinClient` 调用（base_url 通常指向 `http://<rzpipe>:8000`）。
