"""Модуль подключения к MCP-серверу (Connector).

Реализует подключение к MCP-серверам через оба стандартных транспорта
(stdio и Streamable HTTP), выполнение инициализации по спецификации MCP,
получение списков инструментов и вызов инструментов с заданными параметрами.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from .models import ServerInfo, ToolInfo

logger = logging.getLogger(__name__)


@dataclass
class ConnectorConfig:
    """Конфигурация подключения к MCP-серверу."""
    transport: str = "stdio"  # "stdio" или "http"
    # stdio параметры
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # HTTP параметры
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0


class MCPConnector:
    """Подключение к MCP-серверу и взаимодействие через протокол."""

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.session: Optional[ClientSession] = None
        self.server_info = ServerInfo(transport=config.transport)
        self._tools: list[ToolInfo] = []

    @asynccontextmanager
    async def connect(self) -> AsyncGenerator[MCPConnector, None]:
        """Контекстный менеджер для подключения к серверу."""
        if self.config.transport == "stdio":
            async with self._connect_stdio() as connector:
                yield connector
        elif self.config.transport == "http":
            async with self._connect_http() as connector:
                yield connector
        else:
            raise ValueError(f"Неподдерживаемый транспорт: {self.config.transport}")

    @asynccontextmanager
    async def _connect_stdio(self) -> AsyncGenerator[MCPConnector, None]:
        """Подключение через stdio транспорт."""
        server_params = StdioServerParameters(
            command=self.config.command,
            args=self.config.args,
            env=self.config.env or None,
        )
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                self.session = session
                await self._initialize()
                yield self

    @asynccontextmanager
    async def _connect_http(self) -> AsyncGenerator[MCPConnector, None]:
        """Подключение через Streamable HTTP транспорт (MCP spec 2025-03+).

        Использует единый эндпоинт с двунаправленным обменом JSON-RPC
        поверх HTTP POST и опциональным SSE-стримом ответов.
        """
        async with streamablehttp_client(
            url=self.config.url,
            headers=self.config.headers or None,
            timeout=self.config.timeout,
        ) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                self.session = session
                await self._initialize()
                yield self

    async def _initialize(self) -> None:
        """Инициализация MCP-сессии: отправка initialize, получение capabilities."""
        result = await self.session.initialize()
        self.server_info.name = getattr(result, "server_info", {}).get("name", "unknown") if isinstance(getattr(result, "server_info", None), dict) else "unknown"
        self.server_info.version = getattr(result, "server_info", {}).get("version", "unknown") if isinstance(getattr(result, "server_info", None), dict) else "unknown"

        # Попробуем извлечь capabilities из результата
        if hasattr(result, "capabilities"):
            caps = result.capabilities
            if hasattr(caps, "model_dump"):
                self.server_info.capabilities = caps.model_dump()
            elif isinstance(caps, dict):
                self.server_info.capabilities = caps

        logger.info(f"Подключено к серверу: {self.server_info.name} v{self.server_info.version}")

    async def list_tools(self) -> list[ToolInfo]:
        """Получить список инструментов сервера."""
        if not self.session:
            raise RuntimeError("Нет активной сессии")

        result = await self.session.list_tools()
        tools = []
        for tool in result.tools:
            # Конвертируем annotations в dict если это объект
            ann = {}
            if hasattr(tool, "annotations") and tool.annotations:
                if hasattr(tool.annotations, "model_dump"):
                    ann = tool.annotations.model_dump()
                elif isinstance(tool.annotations, dict):
                    ann = tool.annotations
                else:
                    ann = {k: v for k, v in vars(tool.annotations).items() if not k.startswith("_")}

            info = ToolInfo(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.inputSchema if hasattr(tool, "inputSchema") else {},
                annotations=ann,
            )
            tools.append(info)

        self._tools = tools
        self.server_info.tools_count = len(tools)
        self.server_info.tools = tools
        return tools

    async def list_resources(self) -> list[dict]:
        """Получить список ресурсов сервера."""
        if not self.session:
            raise RuntimeError("Нет активной сессии")
        try:
            result = await self.session.list_resources()
            resources = []
            for r in result.resources:
                resources.append({
                    "uri": str(r.uri) if hasattr(r, "uri") else "",
                    "name": r.name if hasattr(r, "name") else "",
                    "description": r.description if hasattr(r, "description") else "",
                    "mimeType": r.mimeType if hasattr(r, "mimeType") else "",
                })
            self.server_info.resources_count = len(resources)
            return resources
        except Exception as e:
            logger.debug(f"list_resources не поддерживается: {e}")
            return []

    async def list_prompts(self) -> list[dict]:
        """Получить список промптов сервера."""
        if not self.session:
            raise RuntimeError("Нет активной сессии")
        try:
            result = await self.session.list_prompts()
            prompts = []
            for p in result.prompts:
                prompts.append({
                    "name": p.name if hasattr(p, "name") else "",
                    "description": p.description if hasattr(p, "description") else "",
                })
            self.server_info.prompts_count = len(prompts)
            return prompts
        except Exception as e:
            logger.debug(f"list_prompts не поддерживается: {e}")
            return []

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict:
        """Вызвать инструмент сервера с заданными параметрами."""
        if not self.session:
            raise RuntimeError("Нет активной сессии")

        try:
            result = await self.session.call_tool(name, arguments or {})
            # Извлекаем текстовое содержимое из результата
            content_parts = []
            is_error = getattr(result, "isError", False)
            for part in result.content:
                if hasattr(part, "text"):
                    content_parts.append(part.text)
                elif hasattr(part, "data"):
                    content_parts.append(str(part.data))
            return {
                "content": "\n".join(content_parts),
                "is_error": is_error,
                "raw": result,
            }
        except Exception as e:
            return {
                "content": str(e),
                "is_error": True,
                "raw": None,
                "exception": type(e).__name__,
            }

    def get_tools(self) -> list[ToolInfo]:
        """Получить кешированный список инструментов."""
        return self._tools
