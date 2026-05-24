"""Уязвимый MCP-сервер #2: Отсутствие валидации входных параметров (T06, IM-01).

Демонстрирует уязвимости argument injection: SQL-инъекции,
path traversal, command injection через параметры инструментов.
"""

import os
import sqlite3
import subprocess
import tempfile

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("vuln-no-validation")

# Создаём тестовую БД
DB_PATH = os.path.join(tempfile.gettempdir(), "vuln_test.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'Alice', 'alice@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'Bob', 'bob@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'Admin', 'admin@secret.com')")
    conn.commit()
    conn.close()


init_db()


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="search_users",
            description="Search users in the database by name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "User name to search"
                    }
                },
                "required": ["name"]
            },
        ),
        Tool(
            name="read_file",
            description="Read contents of a file by path.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to read"
                    }
                },
                "required": ["path"]
            },
        ),
        Tool(
            name="run_diagnostic",
            description="Run a system diagnostic command.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Diagnostic target (hostname or IP)"
                    }
                },
                "required": ["target"]
            },
        ),
        Tool(
            name="fetch_url",
            description="Fetch content from a URL.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch"
                    }
                },
                "required": ["url"]
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "search_users":
        # УЯЗВИМОСТЬ: SQL-инъекция — конкатенация строки в запрос
        user_name = arguments.get("name", "")
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            # Небезопасный запрос!
            query = f"SELECT * FROM users WHERE name = '{user_name}'"
            c.execute(query)
            rows = c.fetchall()
            conn.close()
            if rows:
                result = "\n".join(f"ID: {r[0]}, Name: {r[1]}, Email: {r[2]}" for r in rows)
            else:
                result = "No users found."
            return [TextContent(type="text", text=result)]
        except Exception as e:
            # УЯЗВИМОСТЬ: утечка SQL-ошибки
            return [TextContent(type="text", text=f"Database error: {str(e)}")]

    elif name == "read_file":
        # УЯЗВИМОСТЬ: path traversal — нет проверки пути
        file_path = arguments.get("path", "")
        try:
            with open(file_path, "r") as f:
                content = f.read(4096)
            return [TextContent(type="text", text=content)]
        except Exception as e:
            # УЯЗВИМОСТЬ: утечка пути в ошибке
            return [TextContent(type="text", text=f"Error reading file: {str(e)}")]

    elif name == "run_diagnostic":
        # УЯЗВИМОСТЬ: command injection через shell=True
        target = arguments.get("target", "")
        try:
            result = subprocess.run(
                f"ping -c 1 {target}",
                shell=True,  # Небезопасно!
                capture_output=True,
                text=True,
                timeout=10,
            )
            return [TextContent(type="text", text=result.stdout or result.stderr)]
        except Exception as e:
            return [TextContent(type="text", text=f"Diagnostic error: {str(e)}")]

    elif name == "fetch_url":
        # УЯЗВИМОСТЬ: SSRF — нет валидации URL
        import urllib.request
        url = arguments.get("url", "")
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                content = resp.read(4096).decode("utf-8", errors="ignore")
            return [TextContent(type="text", text=content)]
        except Exception as e:
            return [TextContent(type="text", text=f"Fetch error: {str(e)}")]

    return [TextContent(type="text", text="Unknown tool")]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
