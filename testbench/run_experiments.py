"""Скрипт запуска экспериментов для раздела 3 ВКР.

Запускает MCP Security Analyzer против каждого тестового сервера
(7 уязвимых + 2 защищённых) и собирает результаты.
"""

import asyncio
import json
import os
import sys

# Добавляем текущую директорию в path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcpvet.cli import run_scan
from mcpvet.report_generator import ReportGenerator

# Конфигурация экспериментов
EXPERIMENTS = [
    # Уязвимые серверы
    {
        "id": "EXP-01",
        "name": "Tool Poisoning (T01)",
        "server_file": "test_servers/vulnerable/server_tool_poisoning.py",
        "expected_checks": ["CF-01"],
        "expected_vulns": True,
    },
    {
        "id": "EXP-02",
        "name": "Argument Injection (T06)",
        "server_file": "test_servers/vulnerable/server_no_validation.py",
        "expected_checks": ["IM-01", "IM-02"],
        "expected_vulns": True,
    },
    {
        "id": "EXP-03",
        "name": "Information Leak (IM-02)",
        "server_file": "test_servers/vulnerable/server_info_leak.py",
        "expected_checks": ["IM-02"],
        "expected_vulns": True,
    },
    {
        "id": "EXP-04",
        "name": "Excessive Permissions (T03)",
        "server_file": "test_servers/vulnerable/server_excessive_perms.py",
        "expected_checks": ["CF-02"],
        "expected_vulns": True,
    },
    {
        "id": "EXP-05",
        "name": "Rug Pull (T02)",
        "server_file": "test_servers/vulnerable/server_rug_pull.py",
        "expected_checks": ["DM-03"],
        "expected_vulns": False,  # Первый запуск — baseline
    },
    {
        "id": "EXP-05b",
        "name": "Rug Pull Active (T02)",
        "server_file": "test_servers/vulnerable/server_rug_pull.py",
        "env": {"RUG_PULL_ACTIVE": "1"},
        "expected_checks": ["DM-03", "CF-01"],
        "expected_vulns": True,
    },
    {
        "id": "EXP-06",
        "name": "No Auth (T09)",
        "server_file": "test_servers/vulnerable/server_no_auth.py",
        "expected_checks": ["CF-03", "CF-04"],
        "expected_vulns": True,
    },
    {
        "id": "EXP-07",
        "name": "Cross-Server Shadowing (T07)",
        "server_file": "test_servers/vulnerable/server_cross_shadow.py",
        "expected_checks": ["CF-01"],
        "expected_vulns": True,
    },
    # Защищённые серверы
    {
        "id": "EXP-08",
        "name": "Secure Notes (контроль)",
        "server_file": "test_servers/secure/server_secure_notes.py",
        "expected_checks": ["CF-01", "CF-02", "IM-01"],
        "expected_vulns": False,
    },
    {
        "id": "EXP-09",
        "name": "Secure DB (контроль)",
        "server_file": "test_servers/secure/server_secure_db.py",
        "expected_checks": ["CF-01", "IM-01"],
        "expected_vulns": False,
    },
]


class ExperimentArgs:
    """Имитация argparse.Namespace для run_scan."""
    def __init__(self, server_file, server_dir="", env=None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.stdio = f"{sys.executable} {os.path.join(base_dir, server_file)}"
        self.http = None
        self.server_dir = server_dir or os.path.join(base_dir, os.path.dirname(server_file))
        self.output = ""
        self.output_dir = os.path.join(base_dir, "reports")
        self.checks = ""
        self.skip_checks = ""
        self.hash_dir = os.path.join(base_dir, ".hash_store_v6")
        self.verbose = False
        self.json_only = True
        self.env = env or {}


async def run_experiment(exp: dict) -> dict:
    """Запустить один эксперимент."""
    print(f"\n{'='*60}")
    print(f"  {exp['id']}: {exp['name']}")
    print(f"{'='*60}")

    args = ExperimentArgs(
        server_file=exp["server_file"],
        env=exp.get("env"),
    )

    # Устанавливаем переменные окружения
    old_env = {}
    for k, v in (exp.get("env") or {}).items():
        old_env[k] = os.environ.get(k)
        os.environ[k] = v

    try:
        report = await run_scan(args)
        gen = ReportGenerator(report)

        # Сохраняем отчёты
        prefix = f"{exp['id']}_{exp['name'].replace(' ', '_').replace('(', '').replace(')', '')}"
        json_path = os.path.join(args.output_dir, f"{prefix}.json")
        md_path = os.path.join(args.output_dir, f"{prefix}.md")
        gen.to_json(json_path)
        gen.to_markdown(md_path)

        # Формируем результат
        summary = report.summary
        vuln_count = summary.get("total", 0)
        detected = vuln_count > 0

        result = {
            "id": exp["id"],
            "name": exp["name"],
            "server": report.server.name,
            "tools_count": report.server.tools_count,
            "findings_count": vuln_count,
            "by_severity": {k: v for k, v in summary.items() if k != "total"},
            "detected": detected,
            "expected_vulns": exp["expected_vulns"],
            "correct": detected == exp["expected_vulns"],
            "checks_run": report.checks_run,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "evidence": f.evidence[:100],
                }
                for f in report.findings
                if f.result.value == "vulnerable"
            ],
        }

        status = "OK" if result["correct"] else "MISMATCH"
        print(f"  Результат: {vuln_count} уязвимостей [{status}]")
        for f in result["findings"]:
            print(f"    [{f['severity'].upper()}] {f['check_id']}: {f['title']}")

        return result

    except Exception as e:
        print(f"  ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return {
            "id": exp["id"],
            "name": exp["name"],
            "error": str(e),
            "detected": False,
            "expected_vulns": exp["expected_vulns"],
            "correct": False,
        }
    finally:
        # Восстанавливаем env
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


async def main():
    print("=" * 60)
    print("  MCP Security Analyzer — Эксперименты для ВКР")
    print("=" * 60)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(base_dir, "reports"), exist_ok=True)

    results = []
    for exp in EXPERIMENTS:
        result = await run_experiment(exp)
        results.append(result)

    # Итоговая таблица
    print("\n" + "=" * 60)
    print("  ИТОГОВАЯ ТАБЛИЦА РЕЗУЛЬТАТОВ")
    print("=" * 60)
    print(f"{'ID':<8} {'Сервер':<35} {'Уязв.':<6} {'Ожид.':<6} {'Верно':<6}")
    print("-" * 61)

    correct = 0
    total = 0
    for r in results:
        if "error" in r:
            print(f"{r['id']:<8} {r['name']:<35} {'ERR':<6} {str(r['expected_vulns']):<6} {'N/A':<6}")
        else:
            total += 1
            if r["correct"]:
                correct += 1
            print(
                f"{r['id']:<8} {r['name']:<35} {r['findings_count']:<6} "
                f"{str(r['expected_vulns']):<6} {'DA' if r['correct'] else 'NET':<6}"
            )

    print("-" * 61)
    if total > 0:
        print(f"Точность: {correct}/{total} ({correct/total*100:.0f}%)")

    # Сохраняем сводный отчёт
    summary_path = os.path.join(base_dir, "reports", "experiment_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nСводный отчёт: {summary_path}")


if __name__ == "__main__":
    asyncio.run(main())
