"""Запуск EXP-10: HTTP-сервер для апробации TR-02 и CF-03 на HTTP-транспорте.

Запускает уязвимый HTTP-сервер (test_servers/vulnerable/server_http_basic.py)
в фоновом процессе, прогоняет анализатор через --http, сохраняет JSON-отчёт
в reports/EXP-10_HTTP_Basic.json и обновляет experiment_summary.json.
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Добавляем текущую директорию в path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcpvet.cli import run_scan
from mcpvet.report_generator import ReportGenerator


class Exp10Args:
    """Имитация argparse.Namespace для run_scan через HTTP."""
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.stdio = None
        self.http = "http://127.0.0.1:8000/sse"
        self.server_dir = os.path.join(base_dir, "test_servers/vulnerable")
        self.output = ""
        self.output_dir = os.path.join(base_dir, "reports")
        self.checks = ""
        self.skip_checks = ""
        self.hash_dir = os.path.join(base_dir, ".hash_store_v6")
        self.verbose = False
        self.json_only = True
        self.env = {}


async def run_exp10():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    server_script = os.path.join(base_dir, "test_servers/vulnerable/server_http_basic.py")

    # 1. Запускаем HTTP-сервер в фоне
    print("[EXP-10] Запускаю HTTP-сервер...")
    server_proc = subprocess.Popen(
        [sys.executable, server_script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # 2. Ждём пока сервер начнёт слушать
    print("[EXP-10] Жду готовности сервера (3 сек)...")
    await asyncio.sleep(3)

    if server_proc.poll() is not None:
        # Сервер упал
        stderr = server_proc.stderr.read().decode()
        raise RuntimeError(f"HTTP-сервер не запустился: {stderr[:500]}")

    try:
        # 3. Запускаем анализатор
        print("[EXP-10] Запускаю анализатор через --http...")
        args = Exp10Args()
        report = await run_scan(args)
        gen = ReportGenerator(report)

        # 4. Сохраняем отчёты
        prefix = "EXP-10_HTTP_Basic"
        json_path = os.path.join(args.output_dir, f"{prefix}.json")
        md_path = os.path.join(args.output_dir, f"{prefix}.md")
        gen.to_json(json_path)
        gen.to_markdown(md_path)

        # 5. Формируем результат для experiment_summary.json
        summary = report.summary
        vuln_count = summary.get("total", 0)
        detected = vuln_count > 0

        result = {
            "id": "EXP-10",
            "name": "HTTP Basic (TR-02, CF-03)",
            "server": report.server.name,
            "tools_count": report.server.tools_count,
            "findings_count": vuln_count,
            "by_severity": {k: v for k, v in summary.items() if k != "total"},
            "detected": detected,
            "expected_vulns": True,
            "correct": detected,
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

        print(f"\n[EXP-10] Сервер: {result['server']}")
        print(f"[EXP-10] Инструментов: {result['tools_count']}")
        print(f"[EXP-10] Всего находок: {result['findings_count']}")
        print(f"[EXP-10] Распределение: {result['by_severity']}")
        print(f"[EXP-10] Находки:")
        for f in result["findings"]:
            print(f"  [{f['severity'].upper()}] {f['check_id']}: {f['title']}")

        # Дополняем experiment_summary.json
        summary_path = os.path.join(args.output_dir, "experiment_summary.json")
        if os.path.exists(summary_path):
            with open(summary_path) as f:
                all_results = json.load(f)
        else:
            all_results = []
        # Удалим EXP-10 если он там уже есть, добавим заново
        all_results = [r for r in all_results if r.get("id") != "EXP-10"]
        all_results.append(result)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        print(f"\n[EXP-10] experiment_summary.json обновлён")

        return result

    finally:
        # 6. Останавливаем HTTP-сервер
        print("[EXP-10] Останавливаю HTTP-сервер...")
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()


if __name__ == "__main__":
    asyncio.run(run_exp10())
