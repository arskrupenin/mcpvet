"""SARIF v2.1.0 exporter for mcpvet.

Преобразует ScanReport в формат SARIF (Static Analysis Results Interchange Format,
OASIS Standard v2.1.0, март 2020) для нативной интеграции с GitHub Code Scanning,
GitLab Ultimate, Azure DevOps Advanced Security и SARIF Viewer extensions.

Спецификация: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from .models import ScanReport, Severity, CheckResult


# Маппинг severity → SARIF level (4 уровня по стандарту: error, warning, note, none)
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "none",
}


# Каталог правил методики (rule definitions). Соответствует методике гл.2.
# Формат кортежа: (rule_id, краткое описание, threat_ids через запятую, режим)
_RULE_CATALOG: list[tuple[str, str, str, str]] = [
    ("CF-01", "Скрытые инструкции в описаниях инструментов (tool poisoning)", "T01",        "auto"),
    ("CF-02", "Избыточные привилегии инструментов",                            "T03",        "auto"),
    ("CF-03", "Отсутствие per-tool аутентификации и авторизации",              "T09",        "auto"),
    ("CF-04", "Недостаточная информация о побочных эффектах (consent)",        "T01,T02",    "auto"),
    ("IM-01", "Уязвимости валидации входных параметров (SQLi/path/cmd/SSRF)",  "T06",        "auto"),
    ("IM-02", "Утечка информации через ошибки",                                "T10",        "auto"),
    ("IM-03", "Отсутствие маркировки деструктивных операций",                  "T03",        "auto"),
    ("IM-04", "Изоляция контекста между сессиями",                             "T07",        "manual"),
    ("TR-01", "Отсутствие изоляции stdio-процесса",                            "T09",        "auto"),
    ("TR-02", "Уязвимости HTTP/TLS-транспорта",                                "T09,T10",    "auto"),
    ("TR-03", "Учётные данные в исходном коде",                                "T04,T10",    "auto"),
    ("TR-04", "Отсутствие аудит-журналирования",                               "T11",        "auto"),
    ("DM-01", "Косвенный prompt injection",                                    "T05",        "manual"),
    ("DM-02", "Tool poisoning в динамике",                                     "T01,T07",    "manual"),
    ("DM-03", "Rug pull — изменение описаний между прогонами",                 "T02",        "auto"),
    ("DM-04", "Cross-server shadowing",                                        "T07",        "manual"),
    ("DM-05", "Цепочка поставок MCP-серверов",                                 "T08",        "manual"),
    ("DM-06", "Безопасность механизма Sampling",                               "T01,T05",    "manual"),
]


def _build_rules() -> list[dict[str, Any]]:
    """Построить tool.driver.rules[] с описанием всех 18 проверок методики."""
    rules: list[dict[str, Any]] = []
    for rule_id, short_desc, threats, mode in _RULE_CATALOG:
        threat_tags = [t.strip() for t in threats.split(",") if t.strip()]
        rules.append({
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": short_desc},
            "fullDescription":  {"text": short_desc},
            "defaultConfiguration": {
                "enabled": mode == "auto",
            },
            "properties": {
                "tags": ["security", "mcp", mode] + threat_tags,
                "category": rule_id.split("-", 1)[0],  # CF / IM / TR / LM
                "automation": mode,
            },
        })
    return rules


def to_sarif(report: ScanReport) -> dict[str, Any]:
    """Преобразовать ScanReport в SARIF v2.1.0 dict (без записи на диск)."""
    server_name = report.server.name or "unknown"
    fq_name = f"mcp-server://{server_name}"

    # Преобразование findings → SARIF results
    results: list[dict[str, Any]] = []
    for f in report.findings:
        if f.result != CheckResult.VULNERABLE:
            continue
        result: dict[str, Any] = {
            "ruleId": f.check_id,
            "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.title},
            "locations": [{
                "logicalLocations": [{
                    "name": server_name,
                    "kind": "module",
                    "fullyQualifiedName": fq_name,
                }],
            }],
            "properties": {
                "severity":       f.severity.value,
                "threat_id":      f.threat_id or "",
                "evidence":       (f.evidence or "")[:1000],
                "recommendation": f.recommendation or "",
            },
        }
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcpvet",
                    "version": "0.2.0",
                    "informationUri": "https://github.com/arskrupen/mcpvet",
                    "rules": _build_rules(),
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": report.scan_timestamp,
                "endTimeUtc":   report.scan_timestamp,
            }],
            "properties": {
                "server": {
                    "name":         report.server.name,
                    "version":      report.server.version,
                    "transport":    report.server.transport,
                    "tools_count":  report.server.tools_count,
                },
                "checks_run":     report.checks_run,
                "checks_skipped": report.checks_skipped,
            },
            "results": results,
        }]
    }


def write_sarif(report: ScanReport, path: str) -> None:
    """Сохранить ScanReport в SARIF-файл по указанному пути."""
    data = to_sarif(report)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
