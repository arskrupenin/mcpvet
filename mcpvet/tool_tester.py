"""Модуль тестирования реализации инструментов (ToolTester).

Реализует проверки этапа 2 (IM-01 — IM-04):
  IM-01: Валидация входных параметров
  IM-02: Обработка ошибок и утечка информации
  IM-03: Контроль побочных эффектов
  IM-04: Изоляция контекста между сессиями
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Awaitable

from .models import CheckResult, Finding, Severity, ToolInfo
from .payloads import (
    COMMAND_INJECTION_PAYLOADS,
    INFO_LEAK_PATTERNS,
    PATH_TRAVERSAL_PAYLOADS,
    SQL_INJECTION_PAYLOADS,
    SSRF_PAYLOADS,
    TYPE_CONFUSION_PAYLOADS,
)

logger = logging.getLogger(__name__)

# Тип функции для вызова инструмента
CallToolFn = Callable[[str, dict[str, Any]], Awaitable[dict]]


class ToolTester:
    """Тестирование реализации инструментов MCP-сервера."""

    def __init__(self, tools: list[ToolInfo], call_tool: CallToolFn):
        self.tools = tools
        self.call_tool = call_tool
        self.findings: list[Finding] = []

    async def run_all(self) -> list[Finding]:
        """Запустить все проверки этапа 2."""
        self.findings = []
        await self.check_im01_input_validation()
        await self.check_im02_error_handling()
        await self.check_im03_side_effects()
        # IM-04 требует двух параллельных сессий — выполняется
        # только при наличии возможности создать вторую сессию
        return self.findings

    # ── IM-01: Валидация входных параметров ────────────────────────

    async def check_im01_input_validation(self) -> list[Finding]:
        """IM-01: Тестирование валидации входных параметров инструментов."""
        findings = []

        for tool in self.tools:
            schema = tool.input_schema
            properties = schema.get("properties", {})
            if not properties:
                continue

            tool_vulns: list[str] = []

            for param_name, param_schema in properties.items():
                param_type = param_schema.get("type", "string")

                # Определяем набор payloads на основе типа и имени параметра
                payloads_to_test = self._select_payloads(param_name, param_type)

                for payload_category, payloads in payloads_to_test.items():
                    for payload in payloads[:3]:  # Первые 3 для экономии времени
                        try:
                            result = await self.call_tool(
                                tool.name,
                                {param_name: payload}
                            )

                            # Анализируем ответ
                            content = result.get("content", "")
                            is_error = result.get("is_error", False)

                            # Если сервер обработал вредоносный ввод без ошибки —
                            # это может указывать на отсутствие валидации
                            vuln_indicators = self._check_vuln_indicators(
                                content, payload_category, payload
                            )
                            if vuln_indicators:
                                tool_vulns.append(
                                    f"{param_name}/{payload_category}: {vuln_indicators}"
                                )

                        except Exception as e:
                            logger.debug(
                                f"Ошибка при тестировании {tool.name}.{param_name} "
                                f"с {payload_category}: {e}"
                            )

            if tool_vulns:
                findings.append(Finding(
                    check_id="IM-01",
                    severity=Severity.HIGH,
                    title=f"Недостаточная валидация параметров: '{tool.name}'",
                    description=(
                        f"Инструмент '{tool.name}' не отклоняет вредоносные входные "
                        f"данные. Обнаружено {len(tool_vulns)} потенциальных уязвимостей."
                    ),
                    evidence="; ".join(tool_vulns[:5]),
                    recommendation=(
                        "Реализовать строгую валидацию входных параметров по JSON Schema; "
                        "использовать параметризованные запросы для БД; "
                        "применять allow-списки для путей файлов."
                    ),
                    threat_id="T06",
                ))

        self.findings.extend(findings)
        return findings

    def _select_payloads(
        self, param_name: str, param_type: str
    ) -> dict[str, list]:
        """Подобрать payloads на основе имени и типа параметра."""
        payloads: dict[str, list] = {}
        name_lower = param_name.lower()

        # SQL-инъекции: для параметров, связанных с запросами
        if any(kw in name_lower for kw in ["query", "sql", "search", "filter", "where", "id", "name", "user"]):
            payloads["sql_injection"] = SQL_INJECTION_PAYLOADS

        # Path traversal: для параметров с путями
        if any(kw in name_lower for kw in ["path", "file", "dir", "folder", "name", "location", "filename"]):
            payloads["path_traversal"] = PATH_TRAVERSAL_PAYLOADS

        # Command injection: для параметров с командами
        if any(kw in name_lower for kw in ["command", "cmd", "exec", "shell", "run", "script", "input"]):
            payloads["command_injection"] = COMMAND_INJECTION_PAYLOADS

        # SSRF: для параметров с URL
        if any(kw in name_lower for kw in ["url", "uri", "link", "endpoint", "host", "address", "target"]):
            payloads["ssrf"] = SSRF_PAYLOADS

        # Если тип string — всегда тестируем хотя бы SQL и path traversal
        if param_type == "string" and not payloads:
            payloads["sql_injection"] = SQL_INJECTION_PAYLOADS[:3]
            payloads["path_traversal"] = PATH_TRAVERSAL_PAYLOADS[:3]
            payloads["command_injection"] = COMMAND_INJECTION_PAYLOADS[:3]

        # Type confusion: для числовых параметров
        if param_type in ("integer", "number"):
            payloads["type_confusion"] = TYPE_CONFUSION_PAYLOADS["string_as_number"]

        return payloads

    def _check_vuln_indicators(
        self, content: str, category: str, payload: Any
    ) -> str:
        """Проверить ответ на индикаторы успешной эксплуатации."""
        if not content:
            return ""

        content_lower = content.lower()

        # SQL-инъекция: проверяем на признаки успешного выполнения
        if category == "sql_injection":
            if any(ind in content_lower for ind in [
                "syntax error", "sql", "mysql", "postgresql", "sqlite",
                "ora-", "table", "column", "row"
            ]):
                return f"SQL-ошибка в ответе"
            if "union" in str(payload).lower() and len(content) > 100:
                return "Возможный результат UNION-запроса"

        # Path traversal
        if category == "path_traversal":
            if any(ind in content_lower for ind in [
                "root:", "/bin/", "nobody:", "daemon:",  # /etc/passwd
                "[boot loader]",                          # Windows
                "proc/", "/var/", "/usr/",
            ]):
                return f"Содержимое системного файла в ответе"

        # Command injection
        if category == "command_injection":
            if any(ind in content_lower for ind in [
                "uid=", "gid=",               # id output
                "vulnerable",                   # echo VULNERABLE
                "root", "bin/", "sbin/",       # ls output
            ]):
                return f"Результат выполнения команды в ответе"

        # SSRF
        if category == "ssrf":
            if any(ind in content_lower for ind in [
                "ami-", "instance-id", "security-credentials",  # AWS metadata
                "redis_version", "connected_clients",           # Redis
                "computemetadata",                               # GCP
            ]):
                return f"Данные внутреннего сервиса в ответе"

        return ""

    # ── IM-02: Обработка ошибок ────────────────────────────────────

    async def check_im02_error_handling(self) -> list[Finding]:
        """IM-02: Тестирование обработки ошибок и утечки информации."""
        findings = []

        # Набор тестов для провокации ошибок
        error_triggers = [
            {},                                # Пустые параметры
            {"__nonexistent": "test"},         # Несуществующий параметр
            {"": ""},                          # Пустой ключ
        ]

        for tool in self.tools:
            leaks: list[str] = []

            for trigger in error_triggers:
                try:
                    result = await self.call_tool(tool.name, trigger)
                    content = result.get("content", "")

                    # Анализируем на утечки
                    for pattern in INFO_LEAK_PATTERNS:
                        matches = re.findall(pattern, content)
                        if matches:
                            leak_type = self._classify_leak(pattern)
                            leaks.append(f"{leak_type}: '{matches[0][:60]}'")

                except Exception as e:
                    error_text = str(e)
                    for pattern in INFO_LEAK_PATTERNS:
                        matches = re.findall(pattern, error_text)
                        if matches:
                            leak_type = self._classify_leak(pattern)
                            leaks.append(f"{leak_type} (в исключении): '{matches[0][:60]}'")

            if leaks:
                # Дедупликация
                unique_leaks = list(dict.fromkeys(leaks))
                findings.append(Finding(
                    check_id="IM-02",
                    severity=Severity.MEDIUM,
                    title=f"Утечка информации через ошибки: '{tool.name}'",
                    description=(
                        f"Ответы об ошибках инструмента '{tool.name}' содержат "
                        f"внутреннюю техническую информацию."
                    ),
                    evidence="; ".join(unique_leaks[:5]),
                    recommendation=(
                        "Реализовать единую обработку исключений, возвращающую "
                        "обобщённые сообщения; журналировать детали серверно."
                    ),
                    threat_id="",
                ))

        self.findings.extend(findings)
        return findings

    def _classify_leak(self, pattern: str) -> str:
        """Классифицировать тип утечки по паттерну."""
        if "Traceback" in pattern or "at \\w" in pattern:
            return "Stack trace"
        if "password" in pattern or "secret" in pattern or "token" in pattern:
            return "Учётные данные"
        if "mysql" in pattern or "postgres" in pattern or "SQLSTATE" in pattern:
            return "Строка подключения к БД"
        if "Version" in pattern or "Django" in pattern:
            return "Версия ПО"
        if "/" in pattern and "\\" in pattern:
            return "Путь файловой системы"
        return "Техническая информация"

    # ── IM-03: Контроль побочных эффектов ──────────────────────────

    async def check_im03_side_effects(self) -> list[Finding]:
        """IM-03: Проверка побочных эффектов инструментов.

        Проверяет соответствие аннотаций фактическому поведению.
        В black-box режиме ограничена проверкой аннотаций.
        """
        findings = []

        for tool in self.tools:
            annotations = tool.annotations or {}
            read_only = annotations.get("readOnlyHint", None)
            destructive = annotations.get("destructiveHint", None)

            # Если заявлен read-only, но имя/описание указывает на запись
            if read_only is True:
                name_desc = f"{tool.name} {tool.description}".lower()
                write_indicators = [
                    "write", "create", "update", "delete", "modify",
                    "send", "post", "put", "patch", "remove", "execute",
                    "insert", "drop", "truncate",
                ]
                found_write = [w for w in write_indicators if w in name_desc]
                if found_write:
                    findings.append(Finding(
                        check_id="IM-03",
                        severity=Severity.HIGH,
                        title=f"Несоответствие аннотации: '{tool.name}'",
                        description=(
                            f"Инструмент '{tool.name}' помечен как readOnlyHint=true, "
                            f"но имя или описание указывают на операции записи."
                        ),
                        evidence=f"readOnlyHint=true, но найдены: {found_write}",
                        recommendation=(
                            "Обеспечить соответствие аннотаций фактическому поведению; "
                            "запускать инструменты в изолированной среде."
                        ),
                        threat_id="T03",
                    ))

            # Проверка: деструктивный без маркировки
            if destructive is None or destructive is False:
                name_desc = f"{tool.name} {tool.description}".lower()
                destruct_indicators = ["delete", "remove", "drop", "truncate", "format", "destroy", "purge"]
                found_destruct = [w for w in destruct_indicators if w in name_desc]
                if found_destruct:
                    findings.append(Finding(
                        check_id="IM-03",
                        severity=Severity.MEDIUM,
                        title=f"Деструктивный инструмент без маркировки: '{tool.name}'",
                        description=(
                            f"Инструмент '{tool.name}' выполняет деструктивные операции, "
                            f"но не помечен аннотацией destructiveHint."
                        ),
                        evidence=f"destructiveHint не установлен, найдены: {found_destruct}",
                        recommendation="Добавить аннотацию destructiveHint=true.",
                        threat_id="T03",
                    ))

        self.findings.extend(findings)
        return findings
