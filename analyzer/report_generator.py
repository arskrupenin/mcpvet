"""Генератор отчётов (ReportGenerator).

Формирует итоговый отчёт в форматах JSON и Markdown
с перечнем обнаруженных уязвимостей и рекомендациями.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .models import CheckResult, Finding, ScanReport, Severity


# Цвета для уровней риска
SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "[!!!]",
    Severity.HIGH: "[!!]",
    Severity.MEDIUM: "[!]",
    Severity.LOW: "[i]",
    Severity.INFO: "[-]",
}


class ReportGenerator:
    """Генерация отчётов по результатам анализа."""

    def __init__(self, report: ScanReport):
        self.report = report
        self.console = Console()

    def to_json(self, filepath: str = "") -> str:
        """Сформировать JSON-отчёт."""
        data = {
            "server": self.report.server.model_dump(),
            "scan_timestamp": self.report.scan_timestamp,
            "findings": [f.model_dump() for f in self.report.findings],
            "checks_run": self.report.checks_run,
            "checks_skipped": self.report.checks_skipped,
            "summary": self.report.summary,
        }
        json_str = json.dumps(data, indent=2, ensure_ascii=False)

        if filepath:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str

    def to_markdown(self, filepath: str = "") -> str:
        """Сформировать Markdown-отчёт."""
        lines = []
        s = self.report.server
        summary = self.report.summary

        lines.append(f"# Отчёт анализа защищённости MCP-сервера")
        lines.append("")
        lines.append(f"**Сервер:** {s.name} v{s.version}")
        lines.append(f"**Транспорт:** {s.transport}")
        lines.append(f"**Инструментов:** {s.tools_count}")
        lines.append(f"**Дата анализа:** {self.report.scan_timestamp}")
        lines.append("")

        # Сводка
        lines.append("## Сводка результатов")
        lines.append("")
        lines.append(f"| Уровень | Количество |")
        lines.append(f"|---------|------------|")
        lines.append(f"| Критический | {summary.get('critical', 0)} |")
        lines.append(f"| Высокий | {summary.get('high', 0)} |")
        lines.append(f"| Средний | {summary.get('medium', 0)} |")
        lines.append(f"| Низкий | {summary.get('low', 0)} |")
        lines.append(f"| Информационный | {summary.get('info', 0)} |")
        lines.append(f"| **Итого** | **{summary.get('total', 0)}** |")
        lines.append("")

        # Уязвимости
        vuln_findings = [
            f for f in self.report.findings
            if f.result in (CheckResult.VULNERABLE, CheckResult.PARTIAL)
        ]

        if vuln_findings:
            lines.append("## Обнаруженные уязвимости")
            lines.append("")

            for i, f in enumerate(vuln_findings, 1):
                severity_ru = {
                    "critical": "КРИТИЧЕСКИЙ",
                    "high": "ВЫСОКИЙ",
                    "medium": "СРЕДНИЙ",
                    "low": "НИЗКИЙ",
                    "info": "ИНФОРМ.",
                }.get(f.severity.value, f.severity.value.upper())

                lines.append(f"### {i}. [{f.check_id}] {f.title}")
                lines.append("")
                lines.append(f"**Уровень риска:** {severity_ru}")
                if f.threat_id:
                    lines.append(f"**Угроза:** {f.threat_id}")
                lines.append("")
                lines.append(f"**Описание:** {f.description}")
                lines.append("")
                if f.evidence:
                    lines.append(f"**Доказательство:** `{f.evidence}`")
                    lines.append("")
                if f.recommendation:
                    lines.append(f"**Рекомендация:** {f.recommendation}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        # Пройденные проверки
        if self.report.checks_run:
            lines.append("## Выполненные проверки")
            lines.append("")
            for check_id in self.report.checks_run:
                status = "УЯЗВИМ" if any(
                    f.check_id == check_id and f.result == CheckResult.VULNERABLE
                    for f in self.report.findings
                ) else "БЕЗОПАСЕН"
                marker = "X" if status == "УЯЗВИМ" else "V"
                lines.append(f"- [{marker}] {check_id}: {status}")
            lines.append("")

        # Пропущенные проверки
        if self.report.checks_skipped:
            lines.append("## Пропущенные проверки")
            lines.append("")
            for check_id in self.report.checks_skipped:
                lines.append(f"- {check_id}")
            lines.append("")

        md_content = "\n".join(lines)

        if filepath:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(md_content)

        return md_content

    def print_console(self) -> None:
        """Вывести отчёт в консоль с форматированием."""
        s = self.report.server
        summary = self.report.summary

        # Заголовок
        self.console.print()
        self.console.print(
            Panel(
                f"[bold]mcpvet[/bold]\n"
                f"Сервер: {s.name} v{s.version} ({s.transport})\n"
                f"Инструментов: {s.tools_count}\n"
                f"Дата: {self.report.scan_timestamp}",
                title="Отчёт анализа",
                border_style="blue",
            )
        )

        # Сводка
        summary_table = Table(title="Сводка результатов")
        summary_table.add_column("Уровень", style="bold")
        summary_table.add_column("Кол-во", justify="right")

        for sev_name, color in [
            ("critical", "red bold"),
            ("high", "red"),
            ("medium", "yellow"),
            ("low", "blue"),
            ("info", "dim"),
        ]:
            count = summary.get(sev_name, 0)
            if count > 0:
                summary_table.add_row(
                    Text(sev_name.upper(), style=color),
                    Text(str(count), style=color),
                )

        summary_table.add_row(
            Text("ИТОГО", style="bold"),
            Text(str(summary.get("total", 0)), style="bold"),
        )
        self.console.print(summary_table)

        # Уязвимости
        vuln_findings = [
            f for f in self.report.findings
            if f.result in (CheckResult.VULNERABLE, CheckResult.PARTIAL)
        ]

        if vuln_findings:
            self.console.print()
            findings_table = Table(title="Обнаруженные уязвимости")
            findings_table.add_column("#", justify="right", width=3)
            findings_table.add_column("ID", width=6)
            findings_table.add_column("Уровень", width=10)
            findings_table.add_column("Описание", max_width=60)
            findings_table.add_column("Угроза", width=5)

            for i, f in enumerate(vuln_findings, 1):
                color = SEVERITY_COLORS.get(f.severity, "")
                findings_table.add_row(
                    str(i),
                    f.check_id,
                    Text(f.severity.value.upper(), style=color),
                    f.title,
                    f.threat_id or "-",
                )

            self.console.print(findings_table)
        else:
            self.console.print("\n[green bold]Уязвимостей не обнаружено.[/green bold]\n")
