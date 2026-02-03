# frontend/AGENTS.md

本模块是 **前端 UI（React + Vite）**：负责样本上传、任务状态轮询、结果展示（元数据、LLM 报告等）。前端不直接访问 ghidra_pipe，也不直接访问 agents；所有数据都通过 `backend` 的 `/api/*` 获取。

---

## 1. 模块边界与职责

**本模块做什么**
- 提供交互界面：选择文件、计算 sha256、提交分析、展示进度、展示报告。
- 对接后端 API：`POST /api/analyze`、`GET /api/tasks/{task_id}`、`GET /api/result/{sha256}`。
- 在开发态通过 Vite proxy 解决跨域，在生产态通过 `server.mjs` 进行同源反向代理。

**本模块不做什么**
- 不保存任务数据到 DB（由 backend 完成）。
- 不做二进制分析/反编译（由 ghidra_pipe 完成）。
- 不做 LLM 调用（由 agents 完成）。

---

## 2. 目录与关键文件

- `src/App.jsx`
  - 上传/查询主逻辑：sha256 计算、任务创建/复用、轮询任务、状态管理。
- `src/components/ReportView.jsx`
  - 报告渲染：展示 `malware_report`（风险、链路、ATT&CK、IOCs 等），并对文本/代码高亮。
- `vite.config.js`
  - 开发/preview 代理：将 `/api` 转发到 `http://localhost:8001`。
- `server.mjs`
  - 生产静态服务器 + server-side proxy：将 `/api/*` 转发到 `PTW_BACKEND_BASE_URL`。
- `public/runtime-config.js`
  - 运行时配置占位（当前实现可能未实际读取；作为后续“无需重建即可切换 API base”的扩展点）。

---

## 3. 前端数据流（核心流程）

主要流程在 `src/App.jsx`。

### 3.1 上传前的 sha256 预计算与预查
- 浏览器端优先使用 WebCrypto 计算 sha256（用于：1）上传时可带上 sha256；2）先走“按 hash 查结果”的快速路径）。
- 预查：先请求 `GET /api/result/{sha256}`，若命中且任务状态不是 `failed`，直接复用展示。
- 若未命中或命中但为 `failed`，则继续上传分析。

> 语义说明：后端去重会复用 `pending/processing/completed`，但通常不会复用 `failed`；前端这里的策略与后端契约保持一致。

### 3.2 创建任务与轮询
- 创建任务：`POST /api/analyze`（multipart form-data：`file` + 可选 `sha256`）。
- 轮询：获取 `task_id` 后，每隔一段时间请求 `GET /api/tasks/{task_id}`。
  - `pending/processing`：继续轮询
  - `completed`：渲染结果
  - `failed`：展示错误并允许重试

### 3.3 报告渲染
`ReportView.jsx` 主要消费后端返回中的：
- `malware_report`：LLM 汇总报告（字段依赖 prompt 约定）
- `metadata`：二进制元信息
- （可扩展）`functions/strings/decompiled_code/function_analyses`

建议把“报告字段 schema”视为可演进契约：修改 prompt/字段时需要同时更新渲染层。

---

## 4. API 代理与部署形态

### 4.1 开发态：Vite proxy
定义在 `vite.config.js`：
- 访问 `/api/*` -> 代理到 `http://localhost:8001`

好处：
- 浏览器同源请求，无需在 dev 环境处理 CORS。

### 4.2 生产态：静态服务器 + server-side proxy
`server.mjs` 行为：
- 提供静态文件（dist）
- 将 `/api/*` 服务器端转发到 `PTW_BACKEND_BASE_URL`（默认 `http://host.docker.internal:8001`）

好处：
- 浏览器永远只访问同源 `/api`，后端地址不暴露给浏览器。

---

## 5. 依赖与技术栈

- React + Vite
- 网络：通常使用 axios（按实现）
- UI/渲染：Tailwind、Markdown 渲染/代码高亮等

---

## 6. 并发与性能注意事项

- 系统级约束：后端 worker 单并发分析（由 rz_pipe 全局状态导致），因此任务可能排队较久。
- 前端应把 `pending`/`processing` 明确区分并提示用户“排队/分析中”。
- 大文件计算 sha256 可能耗时：可在 UI 上显示 hash 计算进度（当前实现若无进度条，可作为增强）。

---

## 7. 扩展点与开发指引

### 7.1 接入历史任务列表
后端已有 `GET /api/history`，前端可新增页面或侧边栏展示最近任务。

### 7.2 展示更细粒度分析结果
- 字符串列表（`strings`）
- 反编译列表（`decompiled_code`）
- 函数级 AI 分析（`function_analyses`）

### 7.3 运行时配置化 API Base（路线图）
如果希望无需重建即可切换 API：
- 可以让前端读取 `public/runtime-config.js` 注入的变量（例如 `window.__RUNTIME_CONFIG__`），再决定 API base。
- 但当前生产态更推荐保持 `/api` 同源，并通过 `PTW_BACKEND_BASE_URL` 在服务器侧切换。

---

## 8. 与其他模块的契约（速查）

- 只调用 backend：`/api/analyze`、`/api/tasks/{task_id}`、`/api/result/{sha256}`、（可选）`/api/history`
- 不直接访问 ghidra_pipe（:8000）与 agents（legacy :8002）
