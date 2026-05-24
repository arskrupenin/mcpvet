# Testbench

Тестовый стенд для воспроизводимой проверки методики из ВКР «Методика анализа уязвимостей и защиты MCP-серверов в мультиагентных системах», МИФИ, 2026.

Стенд содержит 10 MCP-серверов и сценарии прогона методики на них.

## Структура

```
testbench/
├── test_servers/
│   ├── vulnerable/             # 7 уязвимых stdio + 1 HTTP
│   │   ├── server_tool_poisoning.py    EXP-01 (CF-01, T01)
│   │   ├── server_no_validation.py     EXP-02 (IM-01/IM-02, T06)
│   │   ├── server_info_leak.py         EXP-03 (IM-02)
│   │   ├── server_excessive_perms.py   EXP-04 (CF-02, T03)
│   │   ├── server_rug_pull.py          EXP-05 + EXP-05b (DM-03, T02)
│   │   ├── server_no_auth.py           EXP-06 (CF-03/CF-04, T09)
│   │   ├── server_cross_shadow.py      EXP-07 (CF-01, T07)
│   │   └── server_http_basic.py        EXP-10 (HTTP без TLS)
│   └── secure/                 # 2 контрольных защищённых
│       ├── server_secure_notes.py      EXP-08
│       └── server_secure_db.py         EXP-09
├── run_experiments.py          # оркестратор для stdio-экспериментов
├── run_exp10_http.py           # отдельный сценарий для HTTP EXP-10
└── reports/                    # отчёты предыдущих прогонов (JSON + Markdown)
```

## Запуск

```bash
# Из корня репозитория
pip install -e .

# Сброс baseline для rug pull (DM-03)
rm -rf ~/.mcpvet/hashes ~/.mcp_scan_hashes

# Все 9 stdio-экспериментов
cd testbench
python run_experiments.py

# Отдельно HTTP (EXP-10)
python run_exp10_http.py

# Отчёты появятся в testbench/reports/
```

## Соответствие ВКР

- 10 серверов = 7 уязвимых stdio + 1 уязвимый HTTP + 2 контрольных
- 11 экспериментов = EXP-01..07, EXP-05b, EXP-08, EXP-09, EXP-10
- Метрики на полной разметке: TP = 77, FP = 5, FN = 0
- Precision = 0.939, Recall = 1.000, F1 = 0.969

## Лицензия

MIT (тот же, что и у основного пакета mcpvet).
