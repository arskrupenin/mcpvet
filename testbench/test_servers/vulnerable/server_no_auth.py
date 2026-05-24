"""Уязвимый MCP-сервер #6: Отсутствие аутентификации (T09, TR-02, CF-03).

HTTP-сервер без аутентификации — любой может подключиться
и вызвать инструменты, включая критичные операции.
Также отсутствует TLS — данные передаются в открытом виде.
"""

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("vuln-no-auth")

# Имитация базы данных
USERS_DB = {
    "1": {"name": "Alice", "email": "alice@company.com", "salary": 120000},
    "2": {"name": "Bob", "email": "bob@company.com", "salary": 95000},
    "3": {"name": "Charlie", "email": "charlie@company.com", "salary": 150000},
}


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="get_employee",
            description="Get employee information including salary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "employee_id": {"type": "string", "description": "Employee ID"}
                },
                "required": ["employee_id"]
            },
        ),
        Tool(
            name="update_salary",
            description="Update employee salary.",
            inputSchema={
                "type": "object",
                "properties": {
                    "employee_id": {"type": "string", "description": "Employee ID"},
                    "new_salary": {"type": "integer", "description": "New salary amount"},
                },
                "required": ["employee_id", "new_salary"]
            },
        ),
        Tool(
            name="delete_employee",
            description="Remove employee from the system.",
            inputSchema={
                "type": "object",
                "properties": {
                    "employee_id": {"type": "string", "description": "Employee ID"}
                },
                "required": ["employee_id"]
            },
        ),
        Tool(
            name="export_all_data",
            description="Export all employee data to CSV format.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    # УЯЗВИМОСТЬ: нет никакой аутентификации или авторизации
    if name == "get_employee":
        emp_id = arguments.get("employee_id", "")
        emp = USERS_DB.get(emp_id)
        if emp:
            return [TextContent(type="text", text=f"Name: {emp['name']}, Email: {emp['email']}, Salary: ${emp['salary']}")]
        return [TextContent(type="text", text="Employee not found.")]

    elif name == "update_salary":
        emp_id = arguments.get("employee_id", "")
        new_salary = arguments.get("new_salary", 0)
        if emp_id in USERS_DB:
            USERS_DB[emp_id]["salary"] = new_salary
            return [TextContent(type="text", text=f"Salary updated to ${new_salary}")]
        return [TextContent(type="text", text="Employee not found.")]

    elif name == "delete_employee":
        emp_id = arguments.get("employee_id", "")
        if emp_id in USERS_DB:
            del USERS_DB[emp_id]
            return [TextContent(type="text", text=f"Employee {emp_id} deleted.")]
        return [TextContent(type="text", text="Employee not found.")]

    elif name == "export_all_data":
        csv = "id,name,email,salary\n"
        for eid, emp in USERS_DB.items():
            csv += f"{eid},{emp['name']},{emp['email']},{emp['salary']}\n"
        return [TextContent(type="text", text=csv)]

    return [TextContent(type="text", text="Unknown tool")]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
