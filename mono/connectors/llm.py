"""大模型连接器：OpenAI 兼容系列 + Anthropic / Gemini 原生协议。"""
from __future__ import annotations

import json
from typing import Any, AsyncGenerator

import httpx

from .base import BaseConnector, ConnectorResult

# 检测失败时的归因关键词：网关各说各话，统一翻成用户能照着办的一句话
QUOTA_HINTS = (
    "insufficient_quota",
    "insufficient quota",
    "quota",
    "余额",
    "额度",
    "积分",
    "欠费",
    "充值",
    "credit",
    "billing",
    "arrears",
    "payment",
    "not enough",
    "exceeded your current",
)
AUTH_HINTS = ("invalid_api_key", "invalid api key", "unauthorized", "authentication", "api key", "鉴权", "密钥", "token 无效")
MODEL_HINTS = ("model_not_found", "does not exist", "not found", "no such model", "invalid model", "模型不存在", "模型未开通")
RATE_HINTS = ("rate_limit", "rate limit", "too many requests", "频率", "限流", "请求次数超限")


def probe_error_text(raw: str, status: int = 0, model: str = "") -> str:
    """把检测失败的原始返回翻成一句人话，并指出下一步该做什么。

    重点是把「额度/积分」和「密钥/模型名」区分开——这三种原因用户要做的事完全不同。
    """
    body = str(raw or "")
    low = body.lower()
    if any(hint in low for hint in QUOTA_HINTS):
        return "连接失败：账户额度不足（积分/余额已用完），接口能连上但无法出结果，请充值后再检测"
    if any(hint in low for hint in RATE_HINTS):
        return "连接失败：请求被限流（并发或频率超限），稍等一分钟再检测"
    if any(hint in low for hint in MODEL_HINTS):
        suffix = f"「{model}」" if model else "当前填写的模型"
        return f"连接失败：{suffix}在该账号下不可用（未开通或名字写错），请换成账号已开通的模型名"
    if any(hint in low for hint in AUTH_HINTS) or status in (401, 403):
        return "连接失败：密钥无效或没有权限（可能已过期、被禁用，或复制时带了空格）"
    if status:
        snippet = body[:180].replace("\n", " ")
        return f"连接失败：HTTP {status}，{snippet or '接口没有返回原因'}"
    return f"连接失败：{body[:180] or '接口没有返回可识别的内容'}"


def _probe_ok(model: str) -> str:
    return f"连接成功：已实际出结果（额度可用），当前模型 {model}"


class OpenAIChatConnector(BaseConnector):
    default_model = "gpt-4o-mini"
    # 内网网关 / 本地模型可以不带 Key：这类连接器不该因为「没填密钥」就判失败
    secret_optional = False

    @property
    def model(self) -> str:
        return str(self.config.get("model") or self.default_model)

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
        return headers

    def config_problem(self) -> ConnectorResult | None:
        """发请求前的配置预检：地址没填就别发了，报错也要说人话。"""
        if not self.base_url:
            return ConnectorResult(False, "还没填 Base URL：请先填写接口地址（例如 https://api.example.com/v1）再检测")
        return None

    async def test(self) -> ConnectorResult:
        """真发一次最小补全来判定，而不是只看 /models 列表。

        只看模型列表会漏掉最常见的一种失败：密钥有效、模型存在，但账户积分/余额已经用完。
        那种情况下 `/models` 照样返回 200 和一堆模型名，列表接口不校验额度，于是检测显示
        「连接成功」，用户一对话才发现一个字都出不来。这里改成发一次 max_tokens=16 的补全，
        只要没拿到 choices 就按失败处理，并把额度、密钥、模型名三种原因分开报。
        """
        if self.row.get("secret_enc") and not self.secret:
            return ConnectorResult(False, "密钥解密失败，请重新保存")
        broken = self.config_problem()
        if broken:
            return broken
        if not self.secret and not self.secret_optional:
            return ConnectorResult(False, "尚未配置密钥，请先在 API 中心填写")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 16,
            "stream": False,
        }
        resp, error = await self.http_post(
            "/chat/completions", headers=self.headers(), json=payload, timeout=30
        )
        if resp is None:
            return ConnectorResult(False, f"连不上 {self.base_url}：{error}")
        raw = resp.text or ""
        if resp.status_code >= 400:
            return ConnectorResult(False, probe_error_text(raw, resp.status_code, self.model))
        try:
            data = json.loads(raw)
        except ValueError:
            return ConnectorResult(False, f"接口返回的不是 JSON：{raw[:160]}")
        if not isinstance(data, dict):
            return ConnectorResult(False, "接口返回结构异常")
        # 不少网关把额度不足塞在 200 的响应体里
        if data.get("error"):
            return ConnectorResult(
                False, probe_error_text(json.dumps(data["error"], ensure_ascii=False), resp.status_code, self.model)
            )
        choices = data.get("choices") or []
        message = (choices[0] or {}).get("message") if choices else None
        if not isinstance(message, dict):
            return ConnectorResult(
                False,
                f"接口连通但没有任何输出，多半是额度用尽或模型未开通：{raw[:160]}",
            )
        # 推理型模型可能把 16 个 token 全用在 reasoning_content 上，content 为空也算成功
        sample = str(message.get("content") or message.get("reasoning_content") or "")[:40]
        return ConnectorResult(True, _probe_ok(self.model), {"sample": sample})

    async def chat(self, system: str, user: str, max_tokens: int = 900) -> ConnectorResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.25,
            "max_tokens": max_tokens,
            "stream": False,
        }
        resp, error = await self.http_post(
            "/chat/completions",
            headers=self.headers(),
            json=payload,
            timeout=90,
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return ConnectorResult(False, "模型返回结构异常")
        return ConnectorResult(True, "研判完成", {"content": content})

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1200,
        timeout: float = 120,
    ) -> ConnectorResult:
        """带工具调用的通用对话补全，供 AI 助手循环使用。"""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        resp, error = await self.http_post(
            "/chat/completions",
            headers=self.headers(),
            json=payload,
            timeout=timeout,
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if isinstance(data, dict) and data.get("error"):
            payload = data["error"]
            if isinstance(payload, dict):
                code = str(payload.get("code") or payload.get("type") or "")
                detail = str(payload.get("message") or "")
                return ConnectorResult(False, f"模型接口报错：{detail}（{code}）" if code else f"模型接口报错：{detail}")
            return ConnectorResult(False, f"模型接口报错：{payload}")
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError):
            return ConnectorResult(False, "模型返回结构异常")
        if not isinstance(message, dict):
            return ConnectorResult(False, "模型返回结构异常")
        return ConnectorResult(
            True,
            "完成",
            {"message": message, "finish_reason": str(choice.get("finish_reason") or "")},
        )

    async def stream_complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1200,
        timeout: float = 180,
    ) -> AsyncGenerator[tuple[str, Any], None]:
        """流式补全。逐段产出 ("text", 增量)，结束时产出 ("final", {...}) 或 ("error", 文案)。"""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        content_parts: list[str] = []
        calls: dict[int, dict[str, Any]] = {}
        finish_reason = ""
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                async with client.stream(
                    "POST", self.url("/chat/completions"), headers=self.headers(), json=payload
                ) as resp:
                    if resp.status_code >= 400:
                        body = (await resp.aread()).decode("utf-8", "ignore")
                        yield ("error", f"HTTP {resp.status_code}: {body[:240]}")
                        return
                    async for raw in resp.aiter_lines():
                        line = (raw or "").strip()
                        if not line or line.startswith(":"):
                            continue
                        if line.startswith("data:"):
                            line = line[5:].strip()
                        if line == "[DONE]":
                            break
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(chunk, dict):
                            continue
                        # 不少网关把失败塞在 200 的流里（如金额不足、模型不存在），原样报给用户
                        error_payload = chunk.get("error")
                        if error_payload:
                            if isinstance(error_payload, dict):
                                code = str(error_payload.get("code") or error_payload.get("type") or "")
                                detail = str(error_payload.get("message") or "")
                            else:
                                code, detail = "", str(error_payload)
                            label = f"{detail}（{code}）" if code and code not in detail else detail
                            yield ("error", f"模型接口报错：{label or '未返回原因'}")
                            return
                        choices = chunk.get("choices") or []
                        if not choices:
                            continue
                        choice = choices[0] or {}
                        if choice.get("finish_reason"):
                            finish_reason = str(choice["finish_reason"])
                        delta = choice.get("delta") or {}
                        piece = delta.get("content")
                        if isinstance(piece, str) and piece:
                            content_parts.append(piece)
                            yield ("text", piece)
                        for item in delta.get("tool_calls") or []:
                            if not isinstance(item, dict):
                                continue
                            index = int(item.get("index") or 0)
                            slot = calls.setdefault(
                                index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}}
                            )
                            if item.get("id"):
                                slot["id"] = str(item["id"])
                            function = item.get("function") or {}
                            name_piece = str(function.get("name") or "")
                            if name_piece:
                                current = str(slot["function"]["name"])
                                if not current:
                                    slot["function"]["name"] = name_piece
                                elif name_piece not in current:
                                    slot["function"]["name"] = current + name_piece
                            if function.get("arguments"):
                                slot["function"]["arguments"] += str(function["arguments"])
        except Exception as exc:  # 网络或解析异常交回调用方决定是否降级
            yield ("error", f"流式请求异常: {type(exc).__name__}: {exc}")
            return

        message: dict[str, Any] = {"role": "assistant", "content": "".join(content_parts)}
        if calls:
            message["tool_calls"] = [calls[key] for key in sorted(calls)]
            for slot in message["tool_calls"]:
                if not slot.get("id"):
                    slot["id"] = f"call_{abs(hash(slot['function'].get('name', ''))) % 10**8}"
                slot["function"]["arguments"] = slot["function"].get("arguments") or "{}"
        yield ("final", {"message": message, "finish_reason": finish_reason})


class DeepSeekConnector(OpenAIChatConnector):
    key = "deepseek"
    category = "ai"
    default_model = "deepseek-chat"


class GenericOpenAIConnector(OpenAIChatConnector):
    key = "openai"
    category = "ai"
    default_model = "gpt-4o-mini"


class QwenConnector(OpenAIChatConnector):
    key = "qwen"
    category = "ai"
    default_model = "qwen-plus"


class MoonshotConnector(OpenAIChatConnector):
    key = "moonshot"
    category = "ai"
    default_model = "kimi-k2"


class ZhipuConnector(OpenAIChatConnector):
    key = "zhipu"
    category = "ai"
    default_model = "glm-4.5"


class DoubaoConnector(OpenAIChatConnector):
    key = "doubao"
    category = "ai"
    default_model = ""


class HunyuanConnector(OpenAIChatConnector):
    key = "hunyuan"
    category = "ai"
    default_model = "hunyuan-turbos-latest"


class BaiduConnector(OpenAIChatConnector):
    key = "baidu"
    category = "ai"
    default_model = "ernie-4.0-turbo-8k"


class MiniMaxConnector(OpenAIChatConnector):
    key = "minimax"
    category = "ai"
    default_model = "MiniMax-M2"


class SiliconFlowConnector(OpenAIChatConnector):
    key = "siliconflow"
    category = "ai"
    default_model = "deepseek-ai/DeepSeek-V3"


class OllamaConnector(OpenAIChatConnector):
    key = "ollama"
    category = "ai"
    default_model = "qwen2.5:7b"

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
        return headers


class NccLLMConnector(OpenAIChatConnector):
    key = "ncc_llm"
    category = "ai"
    default_model = "cyber-model-1"


class CustomLLMConnector(OpenAIChatConnector):
    """自定义模型：目录里没有的网关，自己填 Base URL + 模型名接进来。

    「OpenAI 兼容大模型」那条预置了官方地址，用户改成内网地址容易被下一次目录回填覆盖；
    这里地址、模型名、显示名称全部由用户填，适合自建 vLLM / One-API / 公司统一代理。
    内网网关大多免鉴权，所以密钥在这里是可选项，不填也能检测能不能出结果。
    """

    key = "custom"
    category = "ai"
    default_model = ""
    secret_optional = True

    def config_problem(self) -> ConnectorResult | None:
        broken = super().config_problem()
        if broken:
            return broken
        if not self.model:
            return ConnectorResult(False, "还没填模型名称：请填写网关里的模型 ID（例如 qwen2.5-72b-instruct）再检测")
        return None


class AnthropicConnector(BaseConnector):
    """Anthropic Claude 原生 Messages API。"""

    key = "anthropic"
    category = "ai"
    default_model = "claude-sonnet-4-5-20250929"

    @property
    def model(self) -> str:
        return str(self.config.get("model") or self.default_model)

    def headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "x-api-key": self.secret,
            "anthropic-version": "2023-06-01",
        }

    async def test(self) -> ConnectorResult:
        """真发一次最小补全：只有真的出结果，才算额度可用。"""
        if self.row.get("secret_enc") and not self.secret:
            return ConnectorResult(False, "密钥解密失败，请重新保存")
        missing = self.require_secret()
        if missing:
            return missing
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 16,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "ping"}]}],
        }
        resp, error = await self.http_post("/v1/messages", headers=self.headers(), json=payload, timeout=30)
        if resp is None:
            return ConnectorResult(False, f"连不上 {self.base_url}：{error}")
        raw = resp.text or ""
        if resp.status_code >= 400:
            return ConnectorResult(False, probe_error_text(raw, resp.status_code, self.model))
        try:
            data = json.loads(raw)
        except ValueError:
            return ConnectorResult(False, f"接口返回的不是 JSON：{raw[:160]}")
        if not isinstance(data, dict):
            return ConnectorResult(False, "接口返回结构异常")
        if data.get("error"):
            return ConnectorResult(
                False, probe_error_text(json.dumps(data["error"], ensure_ascii=False), resp.status_code, self.model)
            )
        blocks = data.get("content")
        if not isinstance(blocks, list) or not blocks:
            return ConnectorResult(False, f"接口连通但没有任何输出，多半是额度用尽或模型未开通：{raw[:160]}")
        sample = ""
        for block in blocks:
            if isinstance(block, dict) and block.get("text"):
                sample = str(block["text"])[:40]
                break
        return ConnectorResult(True, _probe_ok(self.model), {"sample": sample})

    @staticmethod
    def _convert(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        converted: list[dict[str, Any]] = []
        for message in messages:
            role = message.get("role")
            content = message.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "user":
                converted.append(
                    {"role": "user", "content": [{"type": "text", "text": str(content)}]}
                )
                continue
            if role == "assistant":
                blocks: list[dict[str, Any]] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for index, call in enumerate(message.get("tool_calls") or []):
                    function = call.get("function") or {}
                    try:
                        args = json.loads(function.get("arguments") or "{}")
                    except (json.JSONDecodeError, TypeError, ValueError):
                        args = {}
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": call.get("id") or f"toolu_{index}",
                            "name": function.get("name") or "tool",
                            "input": args if isinstance(args, dict) else {},
                        }
                    )
                if blocks:
                    converted.append({"role": "assistant", "content": blocks})
                continue
            if role == "tool":
                block = {
                    "type": "tool_result",
                    "tool_use_id": message.get("tool_call_id") or "",
                    "content": str(content),
                }
                if (
                    converted
                    and converted[-1]["role"] == "user"
                    and any(
                        isinstance(item, dict) and item.get("type") == "tool_result"
                        for item in converted[-1]["content"]
                    )
                ):
                    converted[-1]["content"].append(block)
                else:
                    converted.append({"role": "user", "content": [block]})
        return "\n\n".join(system_parts), converted

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1200,
        timeout: float = 120,
    ) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        system, converted = self._convert(messages)
        if not converted:
            return ConnectorResult(False, "没有可发送的对话内容")
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": converted,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [
                {
                    "name": item["function"]["name"],
                    "description": item["function"].get("description", ""),
                    "input_schema": item["function"].get("parameters") or {"type": "object", "properties": {}},
                }
                for item in tools
            ]
        resp, error = await self.http_post(
            "/v1/messages", headers=self.headers(), json=payload, timeout=timeout
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        blocks = data.get("content")
        if not isinstance(blocks, list):
            return ConnectorResult(False, "Claude 返回结构异常")
        texts: list[str] = []
        calls: list[dict[str, Any]] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                texts.append(str(block.get("text") or ""))
            elif block.get("type") == "tool_use":
                calls.append(
                    {
                        "id": block.get("id") or f"toolu_{len(calls)}",
                        "type": "function",
                        "function": {
                            "name": block.get("name") or "",
                            "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False),
                        },
                    }
                )
        message: dict[str, Any] = {"role": "assistant", "content": "\n".join(texts).strip()}
        if calls:
            message["tool_calls"] = calls
        return ConnectorResult(True, "完成", {"message": message})


class GeminiConnector(BaseConnector):
    """Google Gemini 原生 generateContent API。"""

    key = "gemini"
    category = "ai"
    default_model = "gemini-2.0-flash"

    @property
    def model(self) -> str:
        return str(self.config.get("model") or self.default_model)

    def headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json", "x-goog-api-key": self.secret}

    async def test(self) -> ConnectorResult:
        """真发一次 generateContent：只有真的出候选答案，才算额度可用。"""
        if self.row.get("secret_enc") and not self.secret:
            return ConnectorResult(False, "密钥解密失败，请重新保存")
        missing = self.require_secret()
        if missing:
            return missing
        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
            "generationConfig": {"maxOutputTokens": 16},
        }
        resp, error = await self.http_post(
            f"/v1beta/models/{self.model}:generateContent", headers=self.headers(), json=payload, timeout=30
        )
        if resp is None:
            return ConnectorResult(False, f"连不上 {self.base_url}：{error}")
        raw = resp.text or ""
        if resp.status_code >= 400:
            return ConnectorResult(False, probe_error_text(raw, resp.status_code, self.model))
        try:
            data = json.loads(raw)
        except ValueError:
            return ConnectorResult(False, f"接口返回的不是 JSON：{raw[:160]}")
        if not isinstance(data, dict):
            return ConnectorResult(False, "接口返回结构异常")
        if data.get("error"):
            return ConnectorResult(
                False, probe_error_text(json.dumps(data["error"], ensure_ascii=False), resp.status_code, self.model)
            )
        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            blocked = str(data.get("promptFeedback") or "")[:120]
            return ConnectorResult(
                False, f"接口连通但没有任何输出，多半是额度用尽或模型未开通：{blocked or raw[:160]}"
            )
        sample = ""
        try:
            parts = ((candidates[0] or {}).get("content") or {}).get("parts") or []
            for part in parts:
                if isinstance(part, dict) and part.get("text"):
                    sample = str(part["text"])[:40]
                    break
        except (TypeError, IndexError):
            sample = ""
        return ConnectorResult(True, _probe_ok(self.model), {"sample": sample})

    @staticmethod
    def _convert(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        contents: list[dict[str, Any]] = []
        tool_names: dict[str, str] = {}
        for message in messages:
            role = message.get("role")
            content = message.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "user":
                contents.append({"role": "user", "parts": [{"text": str(content)}]})
                continue
            if role == "assistant":
                parts: list[dict[str, Any]] = []
                if content:
                    parts.append({"text": str(content)})
                for index, call in enumerate(message.get("tool_calls") or []):
                    function = call.get("function") or {}
                    name = function.get("name") or "tool"
                    call_id = call.get("id") or f"call_{index}"
                    tool_names[call_id] = name
                    try:
                        args = json.loads(function.get("arguments") or "{}")
                    except (json.JSONDecodeError, TypeError, ValueError):
                        args = {}
                    parts.append({"functionCall": {"name": name, "args": args if isinstance(args, dict) else {}}})
                if parts:
                    contents.append({"role": "model", "parts": parts})
                continue
            if role == "tool":
                name = tool_names.get(message.get("tool_call_id") or "", "tool")
                contents.append(
                    {
                        "role": "user",
                        "parts": [{"functionResponse": {"name": name, "response": {"result": str(content)}}}],
                    }
                )
        return "\n\n".join(system_parts), contents

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 1200,
        timeout: float = 120,
    ) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        system, contents = self._convert(messages)
        if not contents:
            return ConnectorResult(False, "没有可发送的对话内容")
        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if system:
            payload["system_instruction"] = {"parts": [{"text": system}]}
        if tools:
            payload["tools"] = [
                {"function_declarations": [item["function"] for item in tools]}
            ]
        resp, error = await self.http_post(
            f"/v1beta/models/{self.model}:generateContent",
            headers=self.headers(),
            json=payload,
            timeout=timeout,
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        candidates = data.get("candidates") or []
        if not candidates:
            feedback = data.get("promptFeedback") or {}
            return ConnectorResult(False, f"Gemini 未返回内容（{feedback.get('blockReason') or '空响应'}）")
        parts = ((candidates[0] or {}).get("content") or {}).get("parts") or []
        texts: list[str] = []
        calls: list[dict[str, Any]] = []
        for part in parts:
            if not isinstance(part, dict):
                continue
            if "text" in part:
                texts.append(str(part.get("text") or ""))
            call = part.get("functionCall")
            if isinstance(call, dict):
                calls.append(
                    {
                        "id": f"call_{len(calls)}",
                        "type": "function",
                        "function": {
                            "name": call.get("name") or "",
                            "arguments": json.dumps(call.get("args") or {}, ensure_ascii=False),
                        },
                    }
                )
        message: dict[str, Any] = {"role": "assistant", "content": "\n".join(texts).strip()}
        if calls:
            message["tool_calls"] = calls
        return ConnectorResult(True, "完成", {"message": message})
