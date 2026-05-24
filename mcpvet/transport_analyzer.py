"""Модуль анализа транспорта (TransportAnalyzer).

Реализует проверки этапа 3 (TR-01 — TR-04):
  TR-01: Безопасность stdio
  TR-02: Безопасность Streamable HTTP
  TR-03: Хранение и передача учётных данных
  TR-04: Журналирование и аудит
"""

from __future__ import annotations

import logging
import os
import re
import ssl
import subprocess
from pathlib import Path
from typing import Optional

from .models import Finding, Severity
from .payloads import CREDENTIAL_PATTERNS

logger = logging.getLogger(__name__)


class TransportAnalyzer:
    """Анализ безопасности транспортного уровня MCP-сервера."""

    def __init__(
        self,
        transport: str,
        url: str = "",
        command: str = "",
        args: list[str] | None = None,
        server_dir: str = "",
    ):
        self.transport = transport
        self.url = url
        self.command = command
        self.args = args or []
        self.server_dir = server_dir
        self.findings: list[Finding] = []

    def run_all(self) -> list[Finding]:
        """Запустить все проверки этапа 3."""
        self.findings = []
        if self.transport == "stdio":
            self.check_tr01_stdio_security()
        elif self.transport == "http":
            self.check_tr02_http_security()
        if self.server_dir:
            self.check_tr03_credential_storage()
        self.check_tr04_logging()
        return self.findings

    # ── TR-01: Безопасность stdio ──────────────────────────────────

    def check_tr01_stdio_security(self) -> list[Finding]:
        """TR-01: Проверка безопасности stdio транспорта."""
        findings = []

        # 1) Проверка: запуск от root
        try:
            current_user = os.getenv("USER", os.getenv("USERNAME", "unknown"))
            if current_user == "root":
                findings.append(Finding(
                    check_id="TR-01",
                    severity=Severity.HIGH,
                    title="MCP-сервер может запускаться от root",
                    description=(
                        "Текущий пользователь — root. MCP-сервер, запущенный как "
                        "дочерний процесс, унаследует права суперпользователя."
                    ),
                    evidence=f"USER={current_user}",
                    recommendation=(
                        "Запускать MCP-сервер от имени непривилегированного пользователя; "
                        "применить контейнеризацию или sandbox."
                    ),
                    threat_id="T09",
                ))
        except Exception:
            pass

        # 2) Проверка: наличие изоляции (docker, firejail, sandbox)
        has_isolation = False
        if self.command:
            isolation_indicators = ["docker", "podman", "firejail", "sandbox", "bubblewrap", "nsjail"]
            if any(ind in self.command.lower() for ind in isolation_indicators):
                has_isolation = True

        if not has_isolation and self.command:
            findings.append(Finding(
                check_id="TR-01",
                severity=Severity.MEDIUM,
                title="Отсутствие изоляции процесса MCP-сервера",
                description=(
                    "Команда запуска MCP-сервера не содержит признаков "
                    "контейнеризации или sandbox-изоляции."
                ),
                evidence=f"Команда: {self.command} {' '.join(self.args[:3])}",
                recommendation=(
                    "Применить контейнеризацию (Docker) или sandbox (firejail, bubblewrap); "
                    "ограничить доступ к файловой системе."
                ),
                threat_id="T09",
            ))

        self.findings.extend(findings)
        return findings

    # ── TR-02: Безопасность HTTP ───────────────────────────────────

    def check_tr02_http_security(self) -> list[Finding]:
        """TR-02: Проверка безопасности HTTP/SSE транспорта."""
        findings = []

        if not self.url:
            return findings

        # 1) Проверка TLS
        if self.url.startswith("http://") and "localhost" not in self.url and "127.0.0.1" not in self.url:
            findings.append(Finding(
                check_id="TR-02",
                severity=Severity.CRITICAL,
                title="Отсутствие TLS",
                description=(
                    "MCP-сервер доступен по незашифрованному HTTP. "
                    "Данные передаются в открытом виде."
                ),
                evidence=f"URL: {self.url}",
                recommendation="Обеспечить TLS 1.2+ с валидными сертификатами.",
                threat_id="T10",
            ))

        # 2) Проверка версии TLS (если HTTPS)
        if self.url.startswith("https://"):
            try:
                hostname = self.url.split("//")[1].split("/")[0].split(":")[0]
                port = 443
                if ":" in self.url.split("//")[1].split("/")[0]:
                    port = int(self.url.split("//")[1].split("/")[0].split(":")[1])

                context = ssl.create_default_context()
                with context.wrap_socket(
                    __import__("socket").create_connection((hostname, port), timeout=5),
                    server_hostname=hostname
                ) as sock:
                    version = sock.version()
                    if version and version in ("TLSv1", "TLSv1.1"):
                        findings.append(Finding(
                            check_id="TR-02",
                            severity=Severity.HIGH,
                            title="Устаревшая версия TLS",
                            description=f"Сервер использует устаревший {version}.",
                            evidence=f"TLS версия: {version}",
                            recommendation="Обновить до TLS 1.2+.",
                            threat_id="T10",
                        ))
            except Exception as e:
                logger.debug(f"Не удалось проверить TLS: {e}")

        # 3) Проверка аутентификации (попытка подключения без токена)
        # Это проверяется при фактическом подключении через Connector

        # 4) Проверка на localhost без аутентификации
        if ("localhost" in self.url or "127.0.0.1" in self.url) and self.url.startswith("http://"):
            findings.append(Finding(
                check_id="TR-02",
                severity=Severity.LOW,
                title="HTTP на localhost без TLS",
                description="Сервер на localhost без TLS. Допустимо для разработки.",
                evidence=f"URL: {self.url}",
                recommendation="Для production — обеспечить TLS даже на localhost.",
                threat_id="T10",
                result="info",
            ))

        self.findings.extend(findings)
        return findings

    # ── TR-03: Хранение учётных данных ─────────────────────────────

    def check_tr03_credential_storage(self) -> list[Finding]:
        """TR-03: Проверка хранения и передачи учётных данных."""
        findings = []

        if not self.server_dir or not os.path.isdir(self.server_dir):
            return findings

        # Файлы для проверки
        check_extensions = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env"}
        sensitive_files: list[tuple[str, str, str]] = []

        for root, dirs, files in os.walk(self.server_dir):
            # Пропускаем node_modules, .git, __pycache__
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "__pycache__", "venv", ".venv"}]

            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in check_extensions and filename != ".env":
                    continue

                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read(50000)  # Ограничиваем размер

                    for pattern in CREDENTIAL_PATTERNS:
                        matches = re.findall(pattern, content)
                        if matches:
                            rel_path = os.path.relpath(filepath, self.server_dir)
                            for match in matches[:2]:
                                # Маскируем найденные секреты
                                masked = match[:10] + "..." if len(match) > 10 else match
                                sensitive_files.append((rel_path, pattern, masked))

                except Exception as e:
                    logger.debug(f"Не удалось прочитать {filepath}: {e}")

        if sensitive_files:
            evidence_parts = [f"{f}: {m}" for f, _, m in sensitive_files[:5]]
            findings.append(Finding(
                check_id="TR-03",
                severity=Severity.CRITICAL,
                title="Учётные данные в исходном коде или конфигурации",
                description=(
                    f"Обнаружено {len(sensitive_files)} вхождений учётных данных "
                    f"в файлах проекта MCP-сервера."
                ),
                evidence="; ".join(evidence_parts),
                recommendation=(
                    "Использовать хранилища секретов (Vault, AWS Secrets Manager); "
                    "передавать секреты через переменные окружения; "
                    "добавить .env в .gitignore."
                ),
                threat_id="T04",
            ))

        # Проверка наличия .env файла
        env_file = os.path.join(self.server_dir, ".env")
        if os.path.exists(env_file):
            # Проверяем, есть ли .gitignore с .env
            gitignore = os.path.join(self.server_dir, ".gitignore")
            env_in_gitignore = False
            if os.path.exists(gitignore):
                with open(gitignore) as f:
                    env_in_gitignore = ".env" in f.read()

            if not env_in_gitignore:
                findings.append(Finding(
                    check_id="TR-03",
                    severity=Severity.HIGH,
                    title="Файл .env не защищён от коммита",
                    description=".env существует, но не указан в .gitignore.",
                    evidence=f"Файл: {env_file}",
                    recommendation="Добавить .env в .gitignore.",
                    threat_id="T10",
                ))

        self.findings.extend(findings)
        return findings

    # ── TR-04: Журналирование и аудит ──────────────────────────────

    def check_tr04_logging(self) -> list[Finding]:
        """TR-04: Проверка наличия журналирования."""
        findings = []

        if not self.server_dir or not os.path.isdir(self.server_dir):
            # Без доступа к коду проверяем только наличие логов
            findings.append(Finding(
                check_id="TR-04",
                severity=Severity.LOW,
                title="Невозможно проверить журналирование (нет доступа к коду)",
                description="Проверка журналирования требует доступа к исходному коду.",
                evidence="server_dir не указан",
                recommendation="Предоставить путь к исходному коду для полной проверки.",
                threat_id="T11",
                result="skipped",
            ))
            return findings

        # Проверяем исходный код на наличие логирования
        has_logging = False
        logging_indicators = [
            "logging", "logger", "log.", "console.log", "winston",
            "pino", "bunyan", "structlog", "loguru",
        ]

        for root, dirs, files in os.walk(self.server_dir):
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "__pycache__", "venv"}]
            for filename in files:
                if not filename.endswith((".py", ".js", ".ts")):
                    continue
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, errors="ignore") as f:
                        content = f.read(50000)
                    if any(ind in content for ind in logging_indicators):
                        has_logging = True
                        break
                except Exception:
                    pass
            if has_logging:
                break

        if not has_logging:
            findings.append(Finding(
                check_id="TR-04",
                severity=Severity.MEDIUM,
                title="Отсутствие журналирования",
                description=(
                    "В исходном коде MCP-сервера не обнаружены механизмы "
                    "журналирования вызовов инструментов."
                ),
                evidence="Не обнаружены импорты logging/logger в исходных файлах.",
                recommendation=(
                    "Реализовать структурированное журналирование всех вызовов "
                    "инструментов с указанием сессии, времени, параметров и результата."
                ),
                threat_id="T11",
            ))

        self.findings.extend(findings)
        return findings
