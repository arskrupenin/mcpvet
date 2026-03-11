"""Модуль обнаружения rug pull (RugPullDetector).

Реализует проверку LM-03: обнаружение изменения описаний или поведения
инструментов MCP-сервера после первоначального одобрения пользователем.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Finding, Severity, ToolInfo

logger = logging.getLogger(__name__)


class RugPullDetector:
    """Обнаружение rug pull через сравнение хешей описаний инструментов."""

    HASH_STORE_DIR = ".mcp_scan_hashes"

    def __init__(self, server_name: str, tools: list[ToolInfo], store_dir: str = ""):
        self.server_name = server_name
        self.tools = tools
        self.store_dir = store_dir or os.path.join(
            os.path.expanduser("~"), self.HASH_STORE_DIR
        )
        self.findings: list[Finding] = []

    def run_all(self) -> list[Finding]:
        """Запустить проверку LM-03."""
        self.findings = []
        self.check_lm03_rug_pull()
        return self.findings

    def _compute_tool_hash(self, tool: ToolInfo) -> str:
        """Вычислить SHA-256 хеш описания инструмента."""
        data = json.dumps({
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _compute_all_hashes(self) -> dict[str, str]:
        """Вычислить хеши всех инструментов."""
        return {tool.name: self._compute_tool_hash(tool) for tool in self.tools}

    def _get_hash_file(self) -> str:
        """Путь к файлу хешей для данного сервера."""
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in self.server_name)
        return os.path.join(self.store_dir, f"{safe_name}.json")

    def _load_previous_hashes(self) -> dict | None:
        """Загрузить ранее сохранённые хеши."""
        hash_file = self._get_hash_file()
        if not os.path.exists(hash_file):
            return None
        try:
            with open(hash_file) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Ошибка чтения хешей: {e}")
            return None

    def _save_hashes(self, hashes: dict[str, str]) -> None:
        """Сохранить текущие хеши."""
        os.makedirs(self.store_dir, exist_ok=True)
        hash_file = self._get_hash_file()
        data = {
            "server": self.server_name,
            "timestamp": datetime.now().isoformat(),
            "tool_hashes": hashes,
            "tool_descriptions": {t.name: t.description for t in self.tools},
        }
        with open(hash_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Хеши сохранены: {hash_file}")

    def check_lm03_rug_pull(self) -> list[Finding]:
        """LM-03: Обнаружение rug pull через сравнение хешей."""
        findings = []
        current_hashes = self._compute_all_hashes()
        previous_data = self._load_previous_hashes()

        if previous_data is None:
            # Первый запуск — сохраняем baseline
            self._save_hashes(current_hashes)
            findings.append(Finding(
                check_id="LM-03",
                severity=Severity.INFO,
                title="Baseline хешей инструментов сохранён",
                description=(
                    f"Первый анализ сервера '{self.server_name}'. "
                    f"Хеши {len(current_hashes)} инструментов сохранены для "
                    f"последующего сравнения."
                ),
                evidence=f"Инструментов: {len(current_hashes)}",
                recommendation="При следующем запуске будет выполнено сравнение.",
                threat_id="T02",
                result="info",
            ))
        else:
            # Сравниваем с предыдущими
            prev_hashes = previous_data.get("tool_hashes", {})
            prev_descriptions = previous_data.get("tool_descriptions", {})
            prev_timestamp = previous_data.get("timestamp", "unknown")

            changes: list[str] = []
            added: list[str] = []
            removed: list[str] = []

            # Изменённые инструменты
            for name, current_hash in current_hashes.items():
                if name in prev_hashes:
                    if current_hash != prev_hashes[name]:
                        old_desc = prev_descriptions.get(name, "N/A")
                        new_desc = next(
                            (t.description for t in self.tools if t.name == name), "N/A"
                        )
                        changes.append(
                            f"'{name}': описание изменено "
                            f"(было: '{old_desc[:50]}...', стало: '{new_desc[:50]}...')"
                        )
                else:
                    added.append(name)

            # Удалённые инструменты
            for name in prev_hashes:
                if name not in current_hashes:
                    removed.append(name)

            if changes or added or removed:
                evidence_parts = []
                if changes:
                    evidence_parts.append(f"Изменены: {'; '.join(changes[:3])}")
                if added:
                    evidence_parts.append(f"Добавлены: {', '.join(added[:3])}")
                if removed:
                    evidence_parts.append(f"Удалены: {', '.join(removed[:3])}")

                findings.append(Finding(
                    check_id="LM-03",
                    severity=Severity.CRITICAL,
                    title="Обнаружено изменение инструментов (rug pull)",
                    description=(
                        f"Описания инструментов сервера '{self.server_name}' изменились "
                        f"с момента предыдущего анализа ({prev_timestamp}). "
                        f"Изменены: {len(changes)}, добавлены: {len(added)}, "
                        f"удалены: {len(removed)}."
                    ),
                    evidence="; ".join(evidence_parts),
                    recommendation=(
                        "Проверить изменения вручную; требовать повторного одобрения "
                        "пользователя; реализовать журналирование изменений."
                    ),
                    threat_id="T02",
                ))
            else:
                findings.append(Finding(
                    check_id="LM-03",
                    severity=Severity.INFO,
                    title="Инструменты не изменились",
                    description=(
                        f"Хеши всех {len(current_hashes)} инструментов совпадают "
                        f"с предыдущим анализом ({prev_timestamp})."
                    ),
                    evidence="Все хеши совпадают",
                    recommendation="",
                    threat_id="T02",
                    result="secure",
                ))

            # Обновляем хеши
            self._save_hashes(current_hashes)

        self.findings.extend(findings)
        return findings
