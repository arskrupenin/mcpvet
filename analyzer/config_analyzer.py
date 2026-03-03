"""Модуль анализа конфигурации (ConfigAnalyzer).

Реализует проверки этапа 1 (CF-01 — CF-04):
  CF-01: Скрытые инструкции в описаниях инструментов
  CF-02: Избыточные разрешения
  CF-03: Аутентификация и авторизация
  CF-04: Механизм согласия пользователя (consent)
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Optional

from .models import CheckResult, Finding, Severity, ToolInfo
from .payloads import (
    EXCESSIVE_PERMISSION_INDICATORS,
    MISLEADING_DESCRIPTIONS,
    OBFUSCATION_PATTERNS,
    POISONING_KEYWORDS,
    POISONING_REGEX_PATTERNS,
)

logger = logging.getLogger(__name__)


class ConfigAnalyzer:
    """Анализ конфигурации и манифеста MCP-сервера."""

    def __init__(self, tools: list[ToolInfo], server_capabilities: dict | None = None):
        self.tools = tools
        self.capabilities = server_capabilities or {}
        self.findings: list[Finding] = []

    def run_all(self) -> list[Finding]:
        """Запустить все проверки этапа 1."""
        self.findings = []
        self.check_cf01_tool_poisoning()
        self.check_cf02_excessive_permissions()
        self.check_cf03_authentication()
        self.check_cf04_consent()
        return self.findings

    # ── CF-01: Скрытые инструкции в описаниях ──────────────────────

    def check_cf01_tool_poisoning(self) -> list[Finding]:
        """CF-01: Анализ описаний инструментов на наличие скрытых инструкций."""
        findings = []

        for tool in self.tools:
            desc = tool.description
            if not desc:
                continue

            issues: list[str] = []

            # 1) Поиск по ключевым словам
            for kw in POISONING_KEYWORDS:
                if kw.lower() in desc.lower():
                    issues.append(f"Ключевое слово: '{kw}'")

            # 2) Поиск по регулярным выражениям
            for pattern in POISONING_REGEX_PATTERNS:
                matches = re.findall(pattern, desc)
                if matches:
                    matched = matches[0] if isinstance(matches[0], str) else " ".join(matches[0])
                    issues.append(f"Паттерн: '{matched}'")

            # 3) Поиск обфускации
            for pattern in OBFUSCATION_PATTERNS:
                matches = re.findall(pattern, desc)
                if matches:
                    issues.append(f"Обфускация обнаружена: {len(matches)} вхождений")

            # 4) Эвристика: аномально длинное описание
            if len(desc) > 500:
                issues.append(f"Аномально длинное описание: {len(desc)} символов")

            # 5) Проверка на наличие base64 блоков
            b64_matches = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", desc)
            for b64 in b64_matches:
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                    if any(kw in decoded.lower() for kw in ["ignore", "call", "send", "execute"]):
                        issues.append(f"Base64-закодированная инструкция: '{decoded[:80]}'")
                except Exception:
                    pass

            # 6) Проверка на ссылки на другие серверы/инструменты
            cross_refs = re.findall(
                r"(?i)(?:call|use|invoke|refer\s+to)\s+[\w_-]+(?:\s+tool|\s+server|\s+from)",
                desc
            )
            if cross_refs:
                issues.append(f"Ссылки на другие инструменты/серверы: {cross_refs}")

            if issues:
                finding = Finding(
                    check_id="CF-01",
                    severity=Severity.CRITICAL,
                    title=f"Скрытые инструкции в описании инструмента '{tool.name}'",
                    description=(
                        f"Описание инструмента '{tool.name}' содержит элементы, "
                        f"характерные для атаки tool poisoning (T01)."
                    ),
                    evidence="; ".join(issues[:5]),
                    recommendation=(
                        "Удалить скрытые инструкции из описаний; ограничить описания "
                        "минимально необходимой информацией о назначении и параметрах."
                    ),
                    threat_id="T01",
                )
                findings.append(finding)

        self.findings.extend(findings)
        return findings

    # ── CF-02: Избыточные разрешения ───────────────────────────────

    def check_cf02_excessive_permissions(self) -> list[Finding]:
        """CF-02: Оценка запрашиваемых разрешений."""
        findings = []

        dangerous_tools = []
        write_tools = []
        read_tools = []

        for tool in self.tools:
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()
            combined = f"{name_lower} {desc_lower}"

            # Проверка на опасные операции
            for indicator in EXCESSIVE_PERMISSION_INDICATORS:
                if indicator in combined:
                    dangerous_tools.append((tool.name, indicator))
                    break

            # Классификация read/write
            annotations = tool.annotations or {}
            read_only = annotations.get("readOnlyHint", None)

            if read_only is True:
                read_tools.append(tool.name)
            elif any(w in combined for w in ["write", "create", "update", "delete", "modify", "send", "post"]):
                write_tools.append(tool.name)
            else:
                read_tools.append(tool.name)

        # Проверка на наличие опасных инструментов
        if dangerous_tools:
            evidence = "; ".join(f"'{t}' ({ind})" for t, ind in dangerous_tools[:5])
            findings.append(Finding(
                check_id="CF-02",
                severity=Severity.HIGH,
                title="Инструменты с избыточными привилегиями",
                description=(
                    f"Обнаружено {len(dangerous_tools)} инструмент(ов) с потенциально "
                    f"опасными операциями (выполнение команд, удаление данных)."
                ),
                evidence=evidence,
                recommendation=(
                    "Ограничить каждый инструмент минимально необходимым набором операций; "
                    "разделить инструменты чтения и записи; применить sandboxing."
                ),
                threat_id="T03",
            ))

        # Проверка: много инструментов записи без чтения
        total = len(self.tools)
        if total > 0 and len(write_tools) / total > 0.7:
            findings.append(Finding(
                check_id="CF-02",
                severity=Severity.MEDIUM,
                title="Преобладание инструментов записи",
                description=(
                    f"{len(write_tools)} из {total} инструментов выполняют операции записи. "
                    f"Принцип наименьших привилегий может быть нарушен."
                ),
                evidence=f"Запись: {write_tools[:5]}",
                recommendation="Разделить read-only и write инструменты на разные серверы.",
                threat_id="T03",
            ))

        self.findings.extend(findings)
        return findings

    # ── CF-03: Аутентификация и авторизация ────────────────────────

    def check_cf03_authentication(self) -> list[Finding]:
        """CF-03: Проверка наличия аутентификации и авторизации.

        Примечание: для stdio-серверов аутентификация не всегда релевантна,
        т.к. управление доступом обеспечивается хост-приложением.
        """
        findings = []

        # Проверяем capabilities на наличие security/auth
        has_auth = False
        caps = self.capabilities
        if caps:
            auth_indicators = ["auth", "security", "oauth", "token"]
            caps_str = str(caps).lower()
            has_auth = any(ind in caps_str for ind in auth_indicators)

        # Для HTTP-транспорта отсутствие аутентификации — критично
        # Это будет отдельно проверяться в TransportAnalyzer,
        # здесь мы проверяем на уровне capabilities

        # Проверяем, есть ли авторизация на уровне инструментов
        tools_with_access_control = 0
        for tool in self.tools:
            annotations = tool.annotations or {}
            if annotations.get("requiresAuth") or annotations.get("role"):
                tools_with_access_control += 1

        if len(self.tools) > 1 and tools_with_access_control == 0:
            findings.append(Finding(
                check_id="CF-03",
                severity=Severity.MEDIUM,
                title="Отсутствие авторизации на уровне инструментов",
                description=(
                    "Ни один из инструментов не содержит аннотаций контроля доступа. "
                    "Все инструменты доступны одинаково для любого клиента."
                ),
                evidence=f"Инструментов: {len(self.tools)}, с контролем доступа: {tools_with_access_control}",
                recommendation=(
                    "Реализовать авторизацию на уровне инструментов; "
                    "реализовать ролевую модель доступа."
                ),
                threat_id="T09",
            ))

        self.findings.extend(findings)
        return findings

    # ── CF-04: Механизм согласия пользователя ──────────────────────

    def check_cf04_consent(self) -> list[Finding]:
        """CF-04: Проверка механизма consent."""
        findings = []

        for tool in self.tools:
            desc = tool.description
            issues = []

            # 1) Пустое или слишком короткое описание
            if not desc or len(desc) < 10:
                issues.append("Описание отсутствует или слишком короткое для осознанного решения")

            # 2) Вводящие в заблуждение формулировки
            if desc:
                for misleading in MISLEADING_DESCRIPTIONS:
                    if misleading.lower() in desc.lower():
                        # Проверяем, есть ли при этом побочные эффекты
                        annotations = tool.annotations or {}
                        is_destructive = annotations.get("destructiveHint", False)
                        is_read_only = annotations.get("readOnlyHint", True)

                        if is_destructive or not is_read_only:
                            issues.append(
                                f"Описание содержит '{misleading}', но инструмент "
                                f"имеет побочные эффекты"
                            )

            # 3) Отсутствие информации о побочных эффектах для write-операций
            if desc:
                name_lower = tool.name.lower()
                has_write_indicator = any(
                    w in name_lower for w in ["write", "delete", "send", "create", "modify", "execute"]
                )
                has_sideeffect_info = any(
                    w in desc.lower() for w in [
                        "side effect", "побочн", "modifies", "deletes", "creates",
                        "sends", "writes", "destructive", "irreversible"
                    ]
                )
                if has_write_indicator and not has_sideeffect_info:
                    issues.append("Инструмент с операциями записи без указания побочных эффектов")

            if issues:
                findings.append(Finding(
                    check_id="CF-04",
                    severity=Severity.MEDIUM,
                    title=f"Недостаточная информация для consent: '{tool.name}'",
                    description=(
                        f"Описание инструмента '{tool.name}' не позволяет пользователю "
                        f"принять осознанное решение о допустимости вызова."
                    ),
                    evidence="; ".join(issues),
                    recommendation=(
                        "Обеспечить информативные описания с указанием побочных эффектов; "
                        "реализовать уведомления об изменениях инструментов."
                    ),
                    threat_id="T02",
                ))

        self.findings.extend(findings)
        return findings
