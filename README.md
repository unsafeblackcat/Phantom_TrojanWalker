# Phantom TrojanWalker - AI 恶意软件自动化分析框架

Phantom TrojanWalker 是一个高度模块化的二进制分析与威胁检测平台。它创新性地结合了 **Ghidra** 的底层逆向能力、**LangChain** 的 AI 编排能力以及 **DeepSeek** 的大规模语言模型专家知识，旨在为安全研究员提供全自动化的恶意代码审计与风险评估。

## 🚀 核心能力

- **🤖 AI 协同分析**: 集成 LangChain ReAct 模式，由 AI 智能体自主调用 Ghidra 引擎获取函数、字符串、调用图等关键信息。
- **🔍 深度逆向解析**: 基于 `pyghidra` 和 Ghidra DecompInterface，支持多架构反编译、符号恢复及全局调用图提取。
- **📊 任务化管理 (v2.0)**: 提供基于任务队列的异步分析模式，支持历史任务查询、SHA256 去重及状态追踪。
- **💻 现代化看板**: 基于 React + TailwindCSS + Lucide 构建的实时分析控制台，直观展示恶意评分与证据链。

## 🏗 系统架构

```mermaid
graph TD
    %% 定义样式
    classDef userClass fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef apiClass fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    classDef dbClass fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef workerClass fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef aiClass fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef binaryClass fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef knowledgeClass fill:#fff8e1,stroke:#f57c00,stroke-width:2px

    %% 用户层
    User(["用户/前端"]):::userClass

    %% 后端层
    API["Backend (FastAPI)"]:::apiClass
    DB[("Workdir/SQLite")]:::dbClass
    Worker["Async Worker"]:::workerClass

    %% AI 核心 - 调整水平布局
    subgraph AI_Core ["AI Analysis Engine"]
        direction TB
        Coord["Analysis Coordinator"]:::aiClass
        
        %% 强制水平排列顺序
        subgraph Agents [" "]
            direction LR
            GhidraClient["Ghidra Client"]:::aiClass
            FAA["FunctionAnalysisAgent<br/>(函数分析 + ATT&CK 匹配)"]:::aiClass
            MAA["MalwareAnalysisAgent<br/>(总体研判)"]:::aiClass
            
            GhidraClient ~~~ FAA ~~~ MAA
        end
    end

    %% 二进制引擎
    subgraph Binary_Engine ["底层分析引擎"]
        GhidraAPI["Ghidra Pipe Module"]:::binaryClass
        GhidraMCP["Ghidra MCP"]:::binaryClass
        GhidraCore["Ghidra Core"]:::binaryClass
        BSim["BSim"]:::binaryClass
        FunctionID["FunctionID"]:::binaryClass
    end

    %% 知识支撑
    subgraph Knowledge ["AI 能力支撑"]
        lite["Lite模型<br/>Qwen3-30b-a3b-thinking<br/>GLM-4.7-Flash"]:::knowledgeClass
        max["Max模型<br/>DeepSeek-Reasoner<br/>GLM-4.7"]:::knowledgeClass
    end

    %% 连接
    User -->|"上传文件/查询"| API
    API -->|"写入/查询"| DB
    API -->|"下发任务"| Worker

    Worker -->|"调度"| Coord
    Coord -->|"信息收集"| GhidraClient
    Coord -->|"输入函数信息"| FAA
    FAA -->|"输出重点函数"| Coord
    Coord -->|"输入重点函数"| MAA
    MAA -->|"生成研判报告"| Coord

    GhidraClient --> GhidraAPI
    MAA --> GhidraMCP
    GhidraMCP --> GhidraAPI
    GhidraAPI --> GhidraCore
    BSim --> GhidraCore
    FunctionID --> GhidraCore

    lite --> FAA
    max --> MAA
    Coord -->|"结果落库"| DB
```

## 🛠️ 环境准备

### 1. 基础环境
- **Python**: 3.10+
- **Node.js**: 18+ (用于前端构建)
- **Ghidra**: 12.0+ (Docker 镜像内置，或本地安装并设置 `GHIDRA_INSTALL_DIR`)
- **JDK**: 21+ (Ghidra 12 需要)

### 2. 依赖安装
```bash
# 安装 Python 依赖
pip install -r requirements.txt

# 安装前端依赖
cd frontend
npm install
```

### 3. 配置信息
在 `agents/config.yaml` 中配置 Ghidra 插件地址与两个 Agent 的 LLM 参数（字段名以代码为准，见 `agents/config_loader.py`）：
```yaml
plugins:
  ghidra:
    base_url: "http://localhost:8000"
    endpoints:
      upload: "/upload"
      analyze: "/analyze"
      functions: "/functions"

FunctionAnalysisAgent:
  system_prompt_path: "prompt/FunctionAnalysisAgent.md"
  llm:
    model_name: deepseek-reasoner
    api_key: "YOUR_API_KEY_HERE"
```

提示词会在后端/worker 启动时从 `system_prompt_path` 读取；修改 prompt 后需要重启后端/worker 生效。

## 🚦 快速启动
推荐优先使用 docker-compose 启动全套服务，其次再用"纯本地三进程"调试。

### 方式 A（推荐）：Docker Compose
```bash
git clone https://github.com/MICHAEL-888/Phantom_TrojanWalker.git
cd Phantom_TrojanWalker/agents
mv config.yaml.example config.yaml
# 编辑 config.yaml，填入 Base URL 与 LLM Key
```
```bash
docker compose up --build
```
默认端口：Ghidra `127.0.0.1:8000`、Backend `127.0.0.1:8001`（API 前缀 `/api`）、Frontend `127.0.0.1:8080`。

### 方式 B：纯本地（开发调试）
按顺序启动以下三个服务：

### Step 1: 启动 Ghidra 底层引擎
```bash
# 需要设置 GHIDRA_INSTALL_DIR 环境变量
export GHIDRA_INSTALL_DIR=/path/to/ghidra
python module/ghidra_pipe/main.py
# 默认监听: http://127.0.0.1:8000
```

### Step 2: 启动 分析后台 (Task Logic)
```bash
python backend/main.py
# 默认监听: http://127.0.0.1:8001
```

### Step 3: 启动 前端看板
```bash
cd frontend
npm install
npm run dev
# 默认访问: http://localhost:5173
```

后端核心 API：`POST /api/analyze`（上传并排队）+ `GET /api/tasks/{task_id}`（轮询结果）。

## 📂 目录结构

```text
├── agents/             # AI 智能体核心 (Coordinator, Tools, Prompts)
├── backend/            # 业务持久化后端 (FastAPI, SQLite, Worker)
├── frontend/           # React 前端看板
├── module/ghidra_pipe/ # Ghidra API 封装层 (底层引擎)
├── data/               # 文件上传及任务数据存储
├── tests/              # pytest 测试用例
└── docker-compose.yml  # 一键启动（推荐）
```

## 🧪 测试

运行测试（需要 Ghidra 环境）：
```bash
# 设置 Ghidra 安装目录
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# 运行所有测试
pytest tests/ -v

# 运行 Ghidra 模块测试
pytest tests/test_ghidra_pipe.py -v -s
```

如果没有 Ghidra 环境，相关测试会自动跳过。

## ⚖️ 法律声明

本项目仅供安全研究与教学使用。用户在使用本工具进行法律允许范围外的操作时，由此产生的法律后果由使用者本人承担。

## 🔗 参考资料

- [基于大模型的病毒木马文件云鉴定](https://mp.weixin.qq.com/s/G6LyMtzMxtwk5uAMo44euQ)
- [二进制安全新风向：AI大语言模型协助未知威胁检测与逆向分析](https://www.huorong.cn/document/info/classroom/1887)

