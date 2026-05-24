"""Уязвимый MCP-сервер #4: Избыточные привилегии (T03, CF-02).

Демонстрирует нарушение принципа наименьших привилегий:
сервер для заметок предоставляет доступ к shell, файловой системе и т.д.
"""

import os
import subprocess

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("vuln-excessive-perms")

NOTES_DB = {}


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="create_note",
            description="Create a new note.",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Note title"},
                    "content": {"type": "string", "description": "Note content"},
                },
                "required": ["title", "content"]
            },
        ),
        Tool(
            name="list_notes",
            description="List all saved notes.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # УЯЗВИМОСТЬ: инструменты ниже не нужны для приложения заметок
        Tool(
            name="execute_command",
            description="Execute a system command for debugging purposes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to execute"}
                },
                "required": ["command"]
            },
        ),
        Tool(
            name="write_file",
            description="Write content to any file on the system.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "content": {"type": "string", "description": "File content"},
                },
                "required": ["path", "content"]
            },
        ),
        Tool(
            name="delete_file",
            description="Delete a file from the filesystem.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to delete"}
                },
                "required": ["path"]
            },
        ),
        Tool(
            name="read_env",
            description="Read environment variables for configuration.",
            inputSchema={
                "type": "object",
                "properties": {
                    "var_name": {"type": "string", "description": "Variable name"}
                },
                "required": ["var_name"]
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "create_note":
        title = arguments.get("title", "")
        content = arguments.get("content", "")
        NOTES_DB[title] = content
        return [TextContent(type="text", text=f"Note '{title}' created.")]

    elif name == "list_notes":
        if not NOTES_DB:
            return [TextContent(type="text", text="No notes yet.")]
        notes = "\n".join(f"- {t}: {c[:50]}" for t, c in NOTES_DB.items())
        return [TextContent(type="text", text=notes)]

    elif name == "execute_command":
        cmd = arguments.get("command", "")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return [TextContent(type="text", text=result.stdout or result.stderr)]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {e}")]

    elif name == "write_file":
        path = arguments.get("path", "")
        content = arguments.get("content", "")
        try:
            with open(path, "w") as f:
                f.write(content)
            return [TextContent(type="text", text=f"Written to {path}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {e}")]

    elif name == "delete_file":
        path = arguments.get("path", "")
        try:
            os.remove(path)
            return [TextContent(type="text", text=f"Deleted {path}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {e}")]

    elif name == "read_env":
        var = arguments.get("var_name", "")
        value = os.environ.get(var, "Not set")
        return [TextContent(type="text", text=f"{var}={value}")]

    return [TextContent(type="text", text="Unknown tool")]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
