"""Уязвимый MCP-сервер #8: HTTP без TLS, без авторизации (TR-02, CF-03, IM-01).

Демонстрирует уязвимости HTTP-транспорта:
- Отсутствие TLS (TR-02): сервер слушает обычный HTTP, не HTTPS
- Отсутствие авторизации (CF-03): любой клиент может вызвать любой инструмент
- SQL-инъекция в параметрах (IM-01): прямая конкатенация имени в запрос

Запускается через FastMCP с SSE-транспортом на порту 8765.
"""

import sqlite3
import os
import tempfile
import urllib.request

from mcp.server.fastmcp import FastMCP


# API-ключ в исходниках для срабатывания TR-03 (white-box)
INTERNAL_API_KEY = "sk-prod-aB3xYz9Lm2QwErT5"


mcp = FastMCP("vuln-http-basic")


# Создаём БД с тестовыми данными
DB_PATH = os.path.join(tempfile.gettempdir(), "vuln_http_test.db")


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'Alice', 'alice@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'Admin', 'admin@secret.com')")
    conn.commit()
    conn.close()


_init_db()


@mcp.tool()
def search_users(name: str) -> str:
    """Search users in the database by name. Returns matching records."""
    # Уязвимо: прямая конкатенация имени в SQL
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%'"
    try:
        c.execute(query)
        rows = c.fetchall()
        conn.close()
        return "\n".join(f"ID: {r[0]}, Name: {r[1]}, Email: {r[2]}" for r in rows)
    except sqlite3.Error as e:
        return f"SQL error: {e}"


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch content from a URL and return first 200 bytes."""
    # Уязвимо к SSRF: нет фильтрации внутренних адресов
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            return resp.read(200).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Fetch error: {e}"


@mcp.tool()
def delete_user(user_id: int) -> str:
    """Delete a user by ID."""
    # Деструктивная операция без destructiveHint
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return f"User {user_id} deleted"


if __name__ == "__main__":
    # Запускаем как SSE-сервер (HTTP, без TLS)
    mcp.run(transport="sse")
