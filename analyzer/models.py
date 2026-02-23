"""Модели данных для результатов анализа."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Уровень риска обнаруженной уязвимости."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckResult(str, Enum):
    """Результат проверки."""
    VULNERABLE = "vulnerable"
    SECURE = "secure"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"
    INFO = "info"


class Finding(BaseModel):
    """Обнаруженная уязвимость."""
    check_id: str = Field(description="Идентификатор проверки (CF-01, IM-01, ...)")
    severity: Severity
    title: str
    description: str
    evidence: str = Field(default="", description="Доказательство обнаружения")
    recommendation: str = Field(default="")
    threat_id: str = Field(default="", description="Идентификатор угрозы (T01-T12)")
    result: CheckResult = CheckResult.VULNERABLE


class ToolInfo(BaseModel):
    """Информация об инструменте MCP-сервера."""
    name: str
    description: str = ""
    input_schema: dict = Field(default_factory=dict)
    annotations: dict = Field(default_factory=dict)


class ServerInfo(BaseModel):
    """Информация о проанализированном сервере."""
    name: str = "unknown"
    version: str = "unknown"
    transport: str = "stdio"
    tools_count: int = 0
    resources_count: int = 0
    prompts_count: int = 0
    capabilities: dict = Field(default_factory=dict)
    tools: list[ToolInfo] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Итоговый отчёт сканирования."""
    server: ServerInfo
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    findings: list[Finding] = Field(default_factory=list)
    checks_run: list[str] = Field(default_factory=list)
    checks_skipped: list[str] = Field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.result == CheckResult.VULNERABLE:
                counts[f.severity.value] += 1
        counts["total"] = sum(counts.values())
        return counts
