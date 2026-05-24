"""CLI-интерфейс MCP Security Analyzer.

Точка входа для запуска анализа из командной строки.
Использование:
    python -m mcpvet --stdio "python server.py"
    python -m mcpvet --http "http://localhost:8080/mcp"
    python -m mcpvet --stdio "python server.py" --server-dir ./server_code --output report
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shlex
import sys
from datetime import datetime

from rich.console import Console

from .config_analyzer import ConfigAnalyzer
from .connector import ConnectorConfig, MCPConnector
from .models import CheckResult, ScanReport, ServerInfo
from .report_generator import ReportGenerator
from .rug_pull_detector import RugPullDetector
from .tool_tester import ToolTester
from .transport_analyzer import TransportAnalyzer

console = Console()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mcpvet",
        description="mcpvet — MCP server security analyzer",
    )

    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument(
        "--stdio",
        metavar="COMMAND",
        help='Команда запуска MCP-сервера через stdio (напр. "python server.py")',
    )
    transport.add_argument(
        "--http",
        metavar="URL",
        help="URL MCP-сервера (Streamable HTTP транспорт)",
    )

    parser.add_argument(
        "--server-dir",
        metavar="PATH",
        default="",
        help="Путь к исходному коду сервера (для white-box проверок TR-03, TR-04)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PREFIX",
        default="",
        help="Префикс выходных файлов (по умолчанию: scan_<server>_<date>)",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default="./reports",
        help="Директория для отчётов (по умолчанию: ./reports)",
    )
    parser.add_argument(
        "--checks",
        metavar="IDS",
        default="",
        help="Запустить только указанные проверки (через запятую, напр. CF-01,IM-01)",
    )
    parser.add_argument(
        "--skip-checks",
        metavar="IDS",
        default="",
        help="Пропустить указанные проверки",
    )
    parser.add_argument(
        "--hash-dir",
        metavar="DIR",
        default="",
        help="Директория для хранения хешей (rug pull detector)",
    )
    parser.add_argument(
        "--clean-hashes",
        action="store_true",
        help="Очистить хранилище хешей перед прогоном (rug pull baseline reset)",
    )
    parser.add_argument(
        "--env",
        metavar="KEY=VALUE",
        action="append",
        default=[],
        help="Дополнительная переменная окружения для субпроцесса MCP-сервера "
             "(можно указывать несколько раз: --env K1=v1 --env K2=v2)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Подробный вывод",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Вывести только JSON (без консольного отчёта)",
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Дополнительно сохранить отчёт в формате SARIF v2.1.0 "
             "(OASIS Standard, для интеграции с GitHub Code Scanning и др.)",
    )

    return parser.parse_args(argv)


async def run_scan(args: argparse.Namespace) -> ScanReport:
    """Выполнить полное сканирование MCP-сервера."""

    # Очистка хранилища хешей (rug pull baseline reset) — если запрошена
    if getattr(args, "clean_hashes", False):
        import shutil
        hash_dir = args.hash_dir or os.path.join(
            os.path.expanduser("~"), ".mcpvet", "hashes"
        )
        if os.path.isdir(hash_dir):
            shutil.rmtree(hash_dir, ignore_errors=True)
            console.print(f"[dim]Хранилище хешей очищено: {hash_dir}[/dim]")

    # Настройка подключения
    if args.stdio:
        parts = shlex.split(args.stdio)
        env_dict: dict[str, str] = {}
        for kv in getattr(args, "env", []) or []:
            if "=" in kv:
                k, v = kv.split("=", 1)
                env_dict[k] = v
            else:
                console.print(f"[yellow]Игнорирую --env без '=': {kv}[/yellow]")
        config = ConnectorConfig(
            transport="stdio",
            command=parts[0],
            args=parts[1:] if len(parts) > 1 else [],
            env=env_dict,
        )
    else:
        config = ConnectorConfig(
            transport="http",
            url=args.http,
        )

    # Определяем, какие проверки запускать
    all_checks = [
        "CF-01", "CF-02", "CF-03", "CF-04",
        "IM-01", "IM-02", "IM-03",
        "TR-01", "TR-02", "TR-03", "TR-04",
        "DM-03",
    ]

    if args.checks:
        checks_to_run = set(args.checks.upper().split(","))
    else:
        checks_to_run = set(all_checks)

    if args.skip_checks:
        skip = set(args.skip_checks.upper().split(","))
        checks_to_run -= skip

    connector = MCPConnector(config)

    async with connector.connect() as conn:
        # Получаем информацию о сервере
        tools = await conn.list_tools()
        await conn.list_resources()
        await conn.list_prompts()

        server_info = conn.server_info
        console.print(f"\n[bold green]Подключено:[/bold green] {server_info.name} "
                      f"({server_info.tools_count} инструментов)\n")

        report = ScanReport(server=server_info)
        checks_run = []
        checks_skipped = []

        # ── Этап 1: Анализ конфигурации ──
        cf_checks = {"CF-01", "CF-02", "CF-03", "CF-04"}
        if cf_checks & checks_to_run:
            console.print("[bold]Этап 1:[/bold] Анализ конфигурации...")
            analyzer = ConfigAnalyzer(tools, server_info.capabilities)
            findings = analyzer.run_all()
            report.findings.extend(findings)
            checks_run.extend(sorted(cf_checks & checks_to_run))
            console.print(f"  Обнаружено: {len([f for f in findings if f.result == CheckResult.VULNERABLE])} уязвимостей")
        else:
            checks_skipped.extend(sorted(cf_checks))

        # ── Этап 2: Тестирование реализации ──
        im_checks = {"IM-01", "IM-02", "IM-03"}
        if im_checks & checks_to_run:
            console.print("[bold]Этап 2:[/bold] Тестирование реализации инструментов...")
            tester = ToolTester(tools, conn.call_tool)
            findings = await tester.run_all()
            report.findings.extend(findings)
            checks_run.extend(sorted(im_checks & checks_to_run))
            console.print(f"  Обнаружено: {len([f for f in findings if f.result == CheckResult.VULNERABLE])} уязвимостей")
        else:
            checks_skipped.extend(sorted(im_checks))

        # ── Этап 3: Анализ транспорта ──
        tr_checks = {"TR-01", "TR-02", "TR-03", "TR-04"}
        if tr_checks & checks_to_run:
            console.print("[bold]Этап 3:[/bold] Анализ транспорта...")
            transport = TransportAnalyzer(
                transport=config.transport,
                url=config.url,
                command=config.command,
                args=config.args,
                server_dir=args.server_dir,
            )
            findings = transport.run_all()
            report.findings.extend(findings)
            checks_run.extend(sorted(tr_checks & checks_to_run))
            console.print(f"  Обнаружено: {len([f for f in findings if f.result == CheckResult.VULNERABLE])} уязвимостей")
        else:
            checks_skipped.extend(sorted(tr_checks))

        # ── Этап 4 (частично): Rug Pull Detector ──
        if "DM-03" in checks_to_run:
            console.print("[bold]Этап 4:[/bold] Проверка rug pull (DM-03)...")
            detector = RugPullDetector(
                server_name=server_info.name,
                tools=tools,
                store_dir=args.hash_dir,
            )
            findings = detector.run_all()
            report.findings.extend(findings)
            checks_run.append("DM-03")
            console.print(f"  Обнаружено: {len([f for f in findings if f.result == CheckResult.VULNERABLE])} уязвимостей")
        else:
            checks_skipped.append("DM-03")

        # Проверки, требующие LLM (не автоматизированы)
        manual_checks = ["DM-01", "DM-02", "DM-04", "DM-05", "DM-06", "IM-04"]
        checks_skipped.extend(manual_checks)

        report.checks_run = checks_run
        report.checks_skipped = checks_skipped

    return report


def main(argv: list[str] | None = None) -> None:
    """Главная точка входа CLI."""
    args = parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    try:
        report = asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red bold]Ошибка:[/red bold] {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Генерация отчётов
    gen = ReportGenerator(report)

    # Определяем имена файлов
    prefix = args.output or f"scan_{report.server.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, f"{prefix}.json")
    md_path = os.path.join(output_dir, f"{prefix}.md")
    sarif_path = os.path.join(output_dir, f"{prefix}.sarif") if args.sarif else None

    gen.to_json(json_path)
    gen.to_markdown(md_path)
    if sarif_path:
        gen.to_sarif(sarif_path)

    if not args.json_only:
        gen.print_console()
        console.print(f"\n[dim]Отчёты сохранены:[/dim]")
        console.print(f"  JSON: {json_path}")
        console.print(f"  Markdown: {md_path}")
        if sarif_path:
            console.print(f"  SARIF: {sarif_path}")
    else:
        print(gen.to_json())


if __name__ == "__main__":
    main()
