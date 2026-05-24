"""Защищённый MCP-сервер #1: Notes (эталон безопасной реализации).

Демонстрирует применение контрмер:
- Чистые описания инструментов без скрытых инструкций
- Минимальные привилегии (только CRUD заметок)
- Валидация входных параметров
- Безопасная обработка ошибок
- Аннотации readOnlyHint/destructiveHint
- Журналирование вызовов
"""

import logging
import re
import uuid
from datetime import datetime

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Настройка журналирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secure-notes")

server = Server("secure-notes")

# Хранилище заметок
NOTES: dict[str, dict] = {}

# Ограничения
MAX_TITLE_LENGTH = 200
MAX_CONTENT_LENGTH = 10000
MAX_NOTES = 1000
ALLOWED_TITLE_PATTERN = re.compile(r"^[\w\s\-.,!?()'\"\u0400-\u04ff]{1,200}$")


def _validate_title(title: str) -> str | None:
    """Валидация заголовка. Возвращает ошибку или None."""
    if not title or not title.strip():
        return "Title cannot be empty"
    if len(title) > MAX_TITLE_LENGTH:
        return f"Title too long (max {MAX_TITLE_LENGTH} characters)"
    if not ALLOWED_TITLE_PATTERN.match(title):
        return "Title contains invalid characters"
    return None


def _validate_content(content: str) -> str | None:
    """Валидация содержимого."""
    if not content:
        return "Content cannot be empty"
    if len(content) > MAX_CONTENT_LENGTH:
        return f"Content too long (max {MAX_CONTENT_LENGTH} characters)"
    return None


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="create_note",
            description="Create a new text note with a title and content. Creates a note in the local notes storage.",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Note title (max 200 characters, alphanumeric and basic punctuation)",
                        "maxLength": 200,
                    },
                    "content": {
                        "type": "string",
                        "description": "Note text content (max 10000 characters)",
                        "maxLength": 10000,
                    },
                },
                "required": ["title", "content"]
            },
            annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
        ),
        Tool(
            name="list_notes",
            description="List all saved notes. Returns note IDs, titles, and creation dates.",
            inputSchema={"type": "object", "properties": {}},
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        ),
        Tool(
            name="get_note",
            description="Get the full content of a specific note by its ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "note_id": {
                        "type": "string",
                        "description": "Note ID (UUID format)",
                    }
                },
                "required": ["note_id"]
            },
            annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        ),
        Tool(
            name="delete_note",
            description="Permanently delete a note by its ID. This action cannot be undone.",
            inputSchema={
                "type": "object",
                "properties": {
                    "note_id": {
                        "type": "string",
                        "description": "Note ID (UUID format) to delete",
                    }
                },
                "required": ["note_id"]
            },
            annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    logger.info(f"Tool call: {name}, args: {_sanitize_log(arguments)}")

    try:
        if name == "create_note":
            return await _create_note(arguments)
        elif name == "list_notes":
            return await _list_notes()
        elif name == "get_note":
            return await _get_note(arguments)
        elif name == "delete_note":
            return await _delete_note(arguments)
        else:
            logger.warning(f"Unknown tool requested: {name}")
            return [TextContent(type="text", text="Unknown tool.")]
    except Exception:
        # Безопасная обработка: НЕ раскрываем детали
        logger.exception(f"Error in tool {name}")
        return [TextContent(type="text", text="An internal error occurred. Please try again.")]


def _sanitize_log(args: dict) -> dict:
    """Санитизация аргументов для журнала (обрезаем длинные значения)."""
    return {k: (v[:50] + "..." if isinstance(v, str) and len(v) > 50 else v) for k, v in args.items()}


async def _create_note(arguments: dict):
    title = arguments.get("title", "")
    content = arguments.get("content", "")

    # Валидация
    if err := _validate_title(title):
        return [TextContent(type="text", text=f"Invalid title: {err}")]
    if err := _validate_content(content):
        return [TextContent(type="text", text=f"Invalid content: {err}")]
    if len(NOTES) >= MAX_NOTES:
        return [TextContent(type="text", text=f"Notes limit reached ({MAX_NOTES}).")]

    note_id = str(uuid.uuid4())
    NOTES[note_id] = {
        "title": title.strip(),
        "content": content,
        "created_at": datetime.now().isoformat(),
    }
    logger.info(f"Note created: {note_id}")
    return [TextContent(type="text", text=f"Note created with ID: {note_id}")]


async def _list_notes():
    if not NOTES:
        return [TextContent(type="text", text="No notes saved.")]
    lines = []
    for nid, note in NOTES.items():
        lines.append(f"- [{nid}] {note['title']} ({note['created_at'][:10]})")
    return [TextContent(type="text", text="\n".join(lines))]


async def _get_note(arguments: dict):
    note_id = arguments.get("note_id", "")
    # Валидация UUID
    try:
        uuid.UUID(note_id)
    except (ValueError, AttributeError):
        return [TextContent(type="text", text="Invalid note ID format.")]

    note = NOTES.get(note_id)
    if not note:
        return [TextContent(type="text", text="Note not found.")]
    return [TextContent(type="text", text=f"Title: {note['title']}\n\n{note['content']}")]


async def _delete_note(arguments: dict):
    note_id = arguments.get("note_id", "")
    try:
        uuid.UUID(note_id)
    except (ValueError, AttributeError):
        return [TextContent(type="text", text="Invalid note ID format.")]

    if note_id not in NOTES:
        return [TextContent(type="text", text="Note not found.")]
    del NOTES[note_id]
    logger.info(f"Note deleted: {note_id}")
    return [TextContent(type="text", text=f"Note {note_id} deleted.")]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
