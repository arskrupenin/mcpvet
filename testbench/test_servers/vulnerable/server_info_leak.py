"""Уязвимый MCP-сервер #3: Утечка информации через ошибки (IM-02).

Демонстрирует утечку внутренней информации: стека вызовов,
путей файловой системы, строк подключения, версий ПО.
"""

import os
import traceback

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("vuln-info-leak")

# Имитация конфигурации
DB_CONNECTION = "postgresql://admin:S3cretP@ss!@db.internal.company.com:5432/production"
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="get_user_profile",
            description="Get user profile information by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "integer", "description": "User ID"}
                },
                "required": ["user_id"]
            },
        ),
        Tool(
            name="process_data",
            description="Process and transform data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data to process"},
                    "format": {"type": "string", "description": "Output format"}
                },
                "required": ["data"]
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "get_user_profile":
        user_id = arguments.get("user_id")
        try:
            # Симуляция ошибки с утечкой
            if not isinstance(user_id, int):
                raise TypeError(f"Expected int, got {type(user_id).__name__}")
            if user_id < 0:
                raise ValueError(f"Invalid user_id: {user_id}")
            # Имитация подключения к БД
            if user_id == 0:
                raise ConnectionError(
                    f"Failed to connect to database: {DB_CONNECTION}"
                )
            return [TextContent(type="text", text=f"User {user_id}: John Doe")]
        except Exception as e:
            # УЯЗВИМОСТЬ: полный traceback и внутренние данные в ответе
            tb = traceback.format_exc()
            error_msg = (
                f"Internal Server Error in get_user_profile\n"
                f"Server version: Flask 3.0.2, Python 3.11.4\n"
                f"Working directory: /opt/app/mcp-server/src/handlers/\n"
                f"Config file: /opt/app/config/production.yaml\n"
                f"Database: {DB_CONNECTION}\n"
                f"Stack trace:\n{tb}\n"
                f"Environment: OPENAI_API_KEY={API_KEY}"
            )
            return [TextContent(type="text", text=error_msg)]

    elif name == "process_data":
        data = arguments.get("data", "")
        fmt = arguments.get("format", "json")
        try:
            if not data:
                raise ValueError("Empty data")
            if fmt not in ("json", "csv", "xml"):
                # УЯЗВИМОСТЬ: раскрытие внутренних путей
                raise ValueError(
                    f"Unsupported format '{fmt}'. "
                    f"Valid formats defined in /opt/app/config/formats.yaml. "
                    f"Module: {os.path.abspath(__file__)}"
                )
            return [TextContent(type="text", text=f"Processed: {data[:50]}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    return [TextContent(type="text", text="Unknown tool")]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
