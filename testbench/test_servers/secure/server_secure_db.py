"""Защищённый MCP-сервер #2: Database Query (эталон безопасной реализации).

Демонстрирует применение контрмер для сервера с доступом к БД:
- Параметризованные запросы (prepared statements)
- Allow-list для файловых путей
- Безопасная обработка ошибок без утечки информации
- Валидация всех входных параметров
- Корректные аннотации
- Журналирование
"""

import logging
import os
import re
import sqlite3
import tempfile

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secure-db")

server = Server("secure-db")

# Безопасная инициализация БД
DB_PATH = os.path.join(tempfile.gettempdir(), "secure_test.db")
ALLOWED_READ_DIR = os.path.join(tempfile.gettempdir(), "safe_files")
os.makedirs(ALLOWED_READ_DIR, exist_ok=True)

# Создаём тестовый файл
with open(os.path.join(ALLOWED_READ_DIR, "readme.txt"), "w") as f:
    f.write("This is a safe readme file.")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'Alice', 'alice@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'Bob', 'bob@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'Charlie', 'charlie@example.com')")
    conn.commit()
    conn.close()


init_db()

# Валидация
MAX_NAME_LENGTH = 100
NAME_PATTERN = re.compile(r"^[\w\s\-'.]{1,100}$")
FILENAME_PATTERN = re.compile(r"^[\w\-. ]{1,100}$")


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="search_users",
            description="Search users in the database by name. Returns matching user records (ID, name, email).",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "User name to search (max 100 characters, letters and basic punctuation only)",
                        "maxLength": 100,
                    }
                },
                "required": ["name"]
            },
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        ),
        Tool(
            name="read_document",
            description=(
                "Read a document from the safe documents directory. "
                "Only files in the designated safe directory can be read. "
                "Does not support paths with directory traversal."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Filename (without path, must be in the safe directory)",
                        "maxLength": 100,
                    }
                },
                "required": ["filename"]
            },
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    logger.info(f"Tool call: {name}")

    try:
        if name == "search_users":
            return await _search_users(arguments)
        elif name == "read_document":
            return await _read_document(arguments)
        else:
            return [TextContent(type="text", text="Unknown tool.")]
    except Exception:
        logger.exception(f"Error in tool {name}")
        # Безопасная ошибка — без деталей
        return [TextContent(type="text", text="An internal error occurred. Please try again later.")]


async def _search_users(arguments: dict):
    name = arguments.get("name", "")

    # Валидация входных данных
    if not name or not name.strip():
        return [TextContent(type="text", text="Name parameter is required.")]
    if len(name) > MAX_NAME_LENGTH:
        return [TextContent(type="text", text=f"Name too long (max {MAX_NAME_LENGTH} characters).")]
    if not NAME_PATTERN.match(name):
        return [TextContent(type="text", text="Name contains invalid characters.")]

    # БЕЗОПАСНО: параметризованный запрос
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, email FROM users WHERE name LIKE ?", (f"%{name}%",))
    rows = c.fetchall()
    conn.close()

    if rows:
        result = "\n".join(f"ID: {r[0]}, Name: {r[1]}, Email: {r[2]}" for r in rows)
    else:
        result = "No users found matching the search criteria."

    logger.info(f"search_users: found {len(rows)} results")
    return [TextContent(type="text", text=result)]


async def _read_document(arguments: dict):
    filename = arguments.get("filename", "")

    # Валидация имени файла
    if not filename or not filename.strip():
        return [TextContent(type="text", text="Filename is required.")]
    if not FILENAME_PATTERN.match(filename):
        return [TextContent(type="text", text="Invalid filename format.")]

    # БЕЗОПАСНО: защита от path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        logger.warning(f"Path traversal attempt: {filename}")
        return [TextContent(type="text", text="Invalid filename. Directory traversal is not allowed.")]

    # Построение безопасного пути
    safe_path = os.path.join(ALLOWED_READ_DIR, filename)
    resolved = os.path.realpath(safe_path)

    # Проверка что resolved path внутри разрешённой директории
    if not resolved.startswith(os.path.realpath(ALLOWED_READ_DIR)):
        logger.warning(f"Path escape attempt: {filename} -> {resolved}")
        return [TextContent(type="text", text="Access denied. File is outside the allowed directory.")]

    if not os.path.exists(resolved):
        return [TextContent(type="text", text="File not found.")]

    with open(resolved, "r") as f:
        content = f.read(4096)

    logger.info(f"read_document: {filename} ({len(content)} chars)")
    return [TextContent(type="text", text=content)]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
