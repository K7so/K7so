# K7so

本地运行的安全评估工作台。给它一个域名或 IP，它自己去抓页面、读前端脚本、整理接口，再按你勾选的能力逐项验证，最后交出带请求包和响应包的漏洞清单。整个过程在对话里完成，不需要选模块、配策略、点下一步。

技术栈是 FastAPI + 原生 HTML/CSS/JS + SQLite，运行时只依赖 4 个 Python 包，前端没有任何第三方库。数据全部落在本机的 `data/` 目录，不联网上报。

这个工具只对已获得授权的资产使用。登录时确认的免责声明就是操作授权依据，会跟着作业和审计日志一起存下来。

## 主要功能

**智能工作**　核心页面。用一句话交代目标，模型自己决定先看哪个接口、发什么包、怎么判断。它能跑 shell 命令、跑 Python 脚本、发原始 HTTP 请求，不是只会给建议。每步留一条「已…，接下来…」的进展，翻回去就是完整的执行过程。

**模型能力**　64 项测试能力分 7 组，每项可设 1–5 的权重和一段用户提示。勾选即承诺：只要清单里还有没结论的项，这一轮就不算做完，平台会把模型推回去继续测。

**资产监管**　xlsx、docx、pdf、txt、md 直接丢进去，平台自己解出域名和 IP。子域名收集有三条路：126 个常见前缀枚举、DNS 记录线索、证书透明日志。模块按月建，两个模块一比就能看出这段时间新增了哪些资产。

**漏洞结果**　按主机名归组，一个站点一行，展开看 URL、说明、请求包、响应包。漏洞在归档的那一刻就推到对话里，不用等整轮跑完。

**K7so 工具**　把你自己的 py、exe、jar、bin 放进来，用同一套界面运行，输出实时滚动。

**API 中心**　28 个连接器：15 家大模型、6 家资产测绘、2 家情报、2 家漏洞平台，另有 Nmap / Nuclei / HTTPX 本地工具链检测。

**批量作业**　不对话也能跑固定的流水线：可用性检查 → 被动测绘 → HTTP 存活与配置 → 端口探测 → 模板检测 → AI 研判。进度用 SSE 推，随时可取消。

**审计日志**　记录操作人、时间、来源地址、动作、目标和结果，界面上删不掉。

## 快速开始

需要 Python 3.10 以上。nmap、nuclei、java 都是可选的，不装也能用其余功能，缺什么界面会直接说明。

Windows 双击 `start.bat`，首次运行会自动建虚拟环境、装依赖。

手动启动：

```bash
python -m venv .venv
.venv\Scripts\activate          # macOS / Linux: source .venv/bin/activate
pip install -r requirements.txt
python run.py                   # http://127.0.0.1:8000
```

改监听地址或端口：`python run.py --host 0.0.0.0 --port 9000`。国内装依赖慢，可以加 `-i https://pypi.tuna.tsinghua.edu.cn/simple`。

第一次登录用账号 `admin`。口令是首次启动时随机生成的，写在 `data/初始口令.txt` 里，启动日志也会打一行。仓库里没有任何固定口令。登进去之后到「账号」页改成自己的。

想跳过随机口令、固定用某个口令启动（自动化部署用）：

```bash
K7so_ADMIN_PASSWORD='你的口令' python run.py
```

进系统后的顺序：API 中心选一家大模型填 Key 并检测 → 模型能力里勾要测的类型 → 智能工作输入「帮我把 example.com 测一遍」。

## 内置工具

模型能做的事都在这张表里，没有隐藏通道。

| 工具 | 说明 |
| --- | --- |
| `http_request` | 内置 HTTP 客户端，返回状态码、响应头、响应体，以及可归档的请求包和响应包 |
| `run_shell` | 跑外部命令（curl、nmap、nuclei、ffuf 等），Windows 走 `cmd /d /c`，类 Unix 走 `/bin/sh -c` |
| `run_python` | 直接跑 Python 脚本，返回输出和 traceback |
| `record_finding` | 归档漏洞：标题、等级、URL、影响、修复建议、请求包、响应包、分步过程 |
| `report_capability` | 登记一项能力的验证结论：found / clean / blocked / weak |
| `list_capabilities` | 重读能力快照，对话中途改过勾选时用 |
| `ask_choice` | 需要用户拍板时给 2–4 个可点选项 |
| `platform_overview` | 一次拿到资产、作业、漏洞、能力、连接器状态 |
| `list_assets` / `create_asset` | 查资产台账、登记目标 |
| `start_scan` / `list_scans` / `get_scan` / `cancel_scan` | 发起、查看、终止、取消批量作业 |
| `list_findings` / `update_finding_status` | 查漏洞、流转处理状态 |
| `list_connectors` / `test_connector` / `test_all_connectors` | 查连接器、单个检测、批量并发检测 |
| `list_dir` / `read_file` / `write_file` | 记忆目录只读、工作目录可写，两个目录之外一律拒绝 |
| `read_memory` / `search_memory` | 分页读用户记忆、按关键词或正则搜索 |

工具结果严格配对：一条消息里发 3 个 tool_call，平台就按原顺序回 3 条 tool 消息，被去重跳过或参数非法的也有明确回执。这样不会出现服务端整轮拒绝的 `tool call result does not follow tool call` 错误。

破坏性操作在工具层就拦掉了，不靠提示词自觉：格式化和删根目录、关机、改引导、改平台自身口令、写业务数据、上传可执行文件、压测、爆破、落地持久化后门、内网横向，全部直接拒绝。只有两类操作会停下来问你：读取凭据或私钥这类敏感信息、执行删除类不可逆命令。各自一个开关，默认都开着。

## 测试能力

64 项，7 组。同一类漏洞不拆成多张卡：SQL 注入的字符型、整型、报错、UNION、堆叠、时间盲注合并为一项，IDOR 与水平越权合并，任意文件读取与路径穿越合并，云配置与元数据合并，源码泄露与备份泄露合并，组件漏洞与 Nday 合并。勾一项覆盖该类全部常规手法。

| 分组 | 项数 | 内容 |
| --- | --- | --- |
| 注入攻击 | 16 | 反射型/存储型/DOM 型 XSS、SQL、NoSQL、ORM/HQL、SSTI、表达式注入、命令注入、反序列化、SSRF、XXE、LDAP、XPath、CRLF、GraphQL |
| 执行与文件 | 10 | RCE、动态代码执行、文件上传/读取/写入、LFI/RFI、压缩包穿越、源码与备份泄露、目录爆破、目录索引 |
| 认证与访问控制 | 15 | 未授权访问、IDOR、权限提升、批量赋值、弱口令、默认凭据、登录防爆破、密码重置、任意用户接管、任意用户注册、JWT 弱密钥、会话固定、OAuth/SSO、CSRF、开放重定向 |
| 业务逻辑 | 5 | 逻辑缺陷、支付与金额篡改、并发竞态、接口限流、数据批量导出 |
| 云与组件 | 7 | 云配置与元数据、对象存储权限、组件已知漏洞、中间件管理端、容器 API、Kubernetes API、CI/CD 配置泄露 |
| 客户端与传输 | 4 | 原型链污染、postMessage 校验、点击劫持、Web 缓存欺骗 |
| 信息泄露 | 7 | 敏感信息、接口文档、详细报错、个人数据、日志文件、版本库、调试端点 |

每项有 1–5 的权重，默认满格，数字越大越先测。权重只决定顺序，不影响测不测。每项还可以写一段「用户提示」，说明必须怎么测、哪些不能碰，这段会作为硬性要求注入每一轮。

页面上还有一个「自动渗透」开关，默认关闭。关着的时候清单之外一律不测，端口扫描、目录爆破、子域枚举这类只产清单不产结论的动作也不做。打开之后勾选项变成底线，模型会按实际暴露面主动找清单外的类型。

CORS 宽松、缺安全响应头、纯版本指纹、目录索引、Source Map 暴露这几类不产生实际危害的项，无论开关怎么设都不进漏洞清单，只作为加固建议附在报告末尾。

## 大模型接入

15 个连接器，Claude 和 Gemini 走各自原生协议，其余走 OpenAI 兼容协议。

| 连接器 | 默认 Base URL | 默认模型 |
| --- | --- | --- |
| NCC 大模型 | `https://ai.nccsec.cn/v1` | `cyber-model-1` |
| DeepSeek | `https://api.deepseek.com` | `deepseek-chat` |
| OpenAI 兼容 | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Anthropic Claude | `https://api.anthropic.com` | `claude-sonnet-4-5-20250929` |
| Google Gemini | `https://generativelanguage.googleapis.com` | `gemini-2.0-flash` |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus` |
| Moonshot Kimi | `https://api.moonshot.cn/v1` | `kimi-k2` |
| 智谱 GLM | `https://open.bigmodel.cn/api/paas/v4` | `glm-4.5` |
| 豆包 / 火山方舟 | `https://ark.cn-beijing.volces.com/api/v3` | 填自己的 `ep-…` |
| 腾讯混元 | `https://api.hunyuan.cloud.tencent.com/v1` | `hunyuan-turbos-latest` |
| 百度文心 | `https://qianfan.baidubce.com/v2` | `ernie-4.0-turbo-8k` |
| MiniMax | `https://api.minimax.chat/v1` | `MiniMax-M2` |
| 硅基流动 | `https://api.siliconflow.cn/v1` | `deepseek-ai/DeepSeek-V3` |
| Ollama 本地 | `http://127.0.0.1:11434/v1` | `qwen2.5:7b` |
| 自定义模型 | 自己填 | 自己填 |

「保存并检测」会真发一次最小补全（`max_tokens=16`），拿到实际回包才算接入成功。只看 `/models` 返回 200 不算数：密钥有效但账户余额为 0 时列表照样 200，这种情况会明确报「账户额度不足」。只有 `reasoning_content` 没有 `content` 也算出结果。

目录里没有的模型走「自定义模型」，填 Base URL 和模型名称就能用。这类内网网关大多免鉴权，Key 可以留空，检测时只认实际出没出结果。还可以填一个显示名称，比如「内网千问」，比一串模型 ID 好认。

密钥在服务端用 Fernet 加密，密钥文件是 `data/.secret`，首次启动生成，权限 0600。页面和接口都只能拿到脱敏后的 `sk-abc…7890`，看不到明文。改模型名时密钥留空表示不变，移除连接器才是真删。

## 配置

环境变量统一 `K7so_` 前缀，早期的 `MONO_` 前缀也认。都有默认值，不改也能跑。

| 变量 | 默认 | 作用 |
| --- | --- | --- |
| `K7so_DATA_DIR` | `./data` | 数据目录，数据库、报告、密钥、工具、记忆都在这里 |
| `K7so_ADMIN_USER` | `admin` | 初始账号名 |
| `K7so_ADMIN_PASSWORD` | 空 | 留空则首次启动随机生成口令 |
| `K7so_MAX_OUTPUT_TOKENS` | `16000` | 单次输出上限 |
| `K7so_CONTINUE_ROUNDS` | `6` | 输出被截断时最多续写几段 |
| `K7so_TURN_MAX_SECONDS` | `900` | 单轮时限，能力台账没清空时按段续期 |
| `K7so_LEDGER_STEPS_PER_ITEM` | `8` | 每项能力折算的步数额度 |
| `K7so_LEDGER_HARD_STEPS` | `1200` | 单轮步数硬上限 |
| `K7so_LEDGER_HARD_SECONDS` | `21600` | 台账续期兜底，6 小时 |
| `K7so_CONTEXT_CHAR_BUDGET` | `80000` | 整体上下文字数预算 |
| `K7so_HISTORY_CHAR_BUDGET` | `24000` | 历史对话字数预算 |
| `K7so_TOOL_RESULT_CHARS` | `5000` | 普通工具结果截断长度 |
| `K7so_TOOL_RESULT_LARGE` | `24000` | 命令、文件、请求类结果截断长度 |
| `K7so_CMD_OUTPUT_CHARS` | `18000` | 命令输出上限 |
| `K7so_CMD_TIMEOUT` | `300` | 命令默认超时，秒 |
| `K7so_CMD_TIMEOUT_MAX` | `900` | 命令可申请的超时上限 |
| `K7so_STEP_STALL_SECONDS` | `300` | 看门狗静默阈值 |
| `K7so_HTTP_BODY_CHARS` | `14000` | HTTP 响应体保留长度 |
| `K7so_HTTP_PACKET_CHARS` | `6000` | 归档报文保留长度 |
| `K7so_MEMORY_PRELOAD` | `12000` | 每轮预载记忆字数 |
| `K7so_MEMORY_CHUNK` | `16000` | 记忆翻页每次字数 |
| `K7so_MEMORY_MAX_FILE_BYTES` | `67108864` | 单个记忆文件上限，64MB |
| `K7so_SHELL` | 自动 | 覆盖 shell，例如 `pwsh -NoProfile -Command` |

界面上的「平台设置」还有几项：安全模式（批量作业排除 DoS 和爆破模板，对话里的 PUT/PATCH/DELETE 先确认一次）、HTTP 并发、启用 AI 研判、请求超时、User-Agent、记忆目录和工作目录。

## 目录结构

```text
mono/
├── api/            接口层，auth / chat / capabilities / assets / kits /
│                   findings / scans / connectors / reports / dashboard / settings
├── engine/         评估引擎
│   ├── agent.py        工具调用主循环、提示词、收尾自检、承上摘要
│   ├── capabilities.py 64 项能力定义与分组
│   ├── coverage.py     能力覆盖台账
│   ├── watchdog.py     步骤看门狗
│   ├── shell.py        命令与脚本执行
│   ├── scanner.py      批量作业流水线
│   ├── asset_registry.py 文件解析、DNS 收集、证书日志、模块对比
│   ├── kits.py         本地工具运行
│   └── workspace.py    记忆与工作目录、分页读取、文档解析
├── connectors/     连接器适配：llm / recon / platforms / tools
├── static/         index.html + style.css + app.js
├── db.py           SQLite 持久层、种子数据、审计
├── security.py     口令哈希、Fernet、会话签名
├── runtime.py      SSE 事件总线与取消标记
└── main.py         FastAPI 应用装配
data/               运行时数据，不进仓库
tests/              1062 项回归测试
run.py              启动入口
```

几个设计上的取舍：前端手写，不打包、不外链 CDN、不用图标字体，离线也能开；SQLite 单文件，备份就是复制一个文件；执行和 HTTP 连接解耦，每条事件带 seq，断了重连能补上漏掉的部分。

## 测试

```bash
python tests/run_all.py
```

1062 项，全部用临时数据目录，不会动 `data/` 里的真实数据。

| 文件 | 项数 | 重点 |
| --- | --- | --- |
| `test_agent_flow.py` | 435 | 工具循环、过程播报、敏感拦截与脱敏、记忆分页、插话打断、截断续写、多工具并发、漏洞实时卡片 |
| `test_api_smoke.py` | 205 | 登录与越权、各资源 CRUD 边界、SSE 全链路、断线续传、自定义模型 |
| `test_settings_effect.py` | 57 | 每个设置项是否真生效、权重排序、密钥脱敏、自动渗透开关 |
| `test_asset_kits.py` | 91 | 五种文件格式解析、DNS 名解压、模块对比、四类工具识别与运行 |
| `test_leak_and_outline.py` | 78 | 泄露门槛降档、收尾清单补报文、分步复现、断线续传 |
| `test_round_brief.py` | 73 | 承上摘要的内容与注入时机、重复段落去重 |
| `test_tools_smoke.py` | 61 | 各工具返回值、shell 与 python 执行、破坏性命令拦截、HTTP 报文 |
| `test_watchdog.py` | 29 | 模型卡死重启、命令静默判死、阈值 |
| `test_first_run.py` | 19 | 首次启动随机口令、旧默认口令失效、数据目录被 gitignore |
| `test_memory_worker.py` | 14 | 四万字记忆分页读全、预载缺口标注 |

## 使用边界

只对你拥有或已获书面授权的目标使用。压测、拒绝服务、密码爆破不在能力清单里，也会被工具层拒绝。

默认监听 `127.0.0.1`。要在局域网上给同事用，先设 `K7so_ADMIN_PASSWORD` 并把口令改成强的，`python run.py --host 0.0.0.0`。这是单用户模型，不要直接暴露到公网。

报告里的漏洞信息属于敏感数据，注意分发范围。

## 依赖与许可

运行时依赖四个包，都是宽松许可，可以商用和再分发：FastAPI（MIT）、Uvicorn（BSD-3-Clause）、HTTPX（BSD-3-Clause）、cryptography（Apache-2.0 / BSD-3-Clause）。本项目不含 GPL / AGPL 等传染性依赖，分发时保留各包自己的许可证和版权声明即可。

前端全部手写，没有内联或打包任何第三方库，不分发字体文件。

文中提到的 DeepSeek、OpenAI、Claude、Gemini、通义千问、Kimi、智谱、豆包、混元、文心、MiniMax、硅基流动、Ollama、FOFA、Hunter、Shodan、ZoomEye、Quake、Censys、VirusTotal、ThreatBook、补天、Nmap、Nuclei 等名称和接口地址，只用于说明可以接入哪些服务，商标归各自权利人所有。本项目与这些厂商没有隶属、代理或背书关系。

MIT，见 [LICENSE](LICENSE)。
