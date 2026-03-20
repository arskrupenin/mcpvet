# mcpvet

A comprehensive security analysis tool for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. Performs both static configuration analysis and dynamic runtime testing to identify vulnerabilities in MCP server implementations.

## Features

- **18 security checks** across 4 categories
- Supports **stdio** and **HTTP/SSE** transports
- Detects **tool poisoning**, **rug pull attacks**, injection vulnerabilities, information leaks
- Generates reports in **JSON**, **Markdown**, and formatted **console output**
- Extensible check architecture

## Installation

```bash
pip install mcpvet
```

Or from source:

```bash
pip install -e .
```

## Quick Start

```bash
# Scan a stdio-based MCP server
mcpvet --stdio "python my_server.py"

# Scan an HTTP/SSE MCP server
mcpvet --http "http://localhost:8080/mcp"

# Include source code analysis (white-box checks)
mcpvet --stdio "python server.py" --server-dir ./server_code

# Run specific checks only
mcpvet --stdio "python server.py" --checks CF-01,IM-01,LM-03

# Export JSON report
mcpvet --stdio "python server.py" --output report --json-only
```

## Security Checks

### Configuration Analysis (CF)

| ID    | Check                          | Threat |
|-------|--------------------------------|--------|
| CF-01 | Hidden instructions in tool descriptions (tool poisoning) | T01 |
| CF-02 | Excessive permissions           | T03 |
| CF-03 | Authentication & authorization  | T09 |
| CF-04 | User consent mechanism          | T02 |

### Implementation Testing (IM)

| ID    | Check                          | Threat |
|-------|--------------------------------|--------|
| IM-01 | Input parameter validation (SQLi, path traversal, command injection, SSRF) | T06 |
| IM-02 | Error handling & information leakage | — |
| IM-03 | Side effect control             | T03 |

### Transport Security (TR)

| ID    | Check                          | Threat |
|-------|--------------------------------|--------|
| TR-01 | stdio process isolation         | T09 |
| TR-02 | HTTP/TLS security               | T10 |
| TR-03 | Credential storage              | T04 |
| TR-04 | Logging & audit trail           | T11 |

### LLM Interaction (LM)

| ID    | Check                          | Threat |
|-------|--------------------------------|--------|
| LM-03 | Rug pull detection (description hash comparison) | T02 |

## How It Works

1. **Connect** to the target MCP server via stdio or HTTP/SSE
2. **Enumerate** available tools, resources, and prompts
3. **Analyze configuration** — scan tool descriptions for poisoning patterns, check permissions
4. **Test implementation** — send injection payloads, trigger error conditions
5. **Check transport** — verify TLS, credential storage, logging
6. **Detect rug pull** — compare tool description hashes against previous baseline
7. **Generate report** with findings, severity levels, and remediation advice

## CLI Options

```
usage: mcpvet [-h] (--stdio COMMAND | --http URL)
              [--server-dir PATH] [--output PREFIX] [--output-dir DIR]
              [--checks IDS] [--skip-checks IDS] [--hash-dir DIR]
              [--verbose] [--json-only]

Options:
  --stdio COMMAND    MCP server command (stdio transport)
  --http URL         MCP server URL (HTTP/SSE transport)
  --server-dir PATH  Server source code path (for TR-03, TR-04 white-box checks)
  --output PREFIX    Output file prefix
  --output-dir DIR   Report output directory (default: ./reports)
  --checks IDS       Run only specified checks (comma-separated)
  --skip-checks IDS  Skip specified checks
  --hash-dir DIR     Directory for rug pull hash storage
  --verbose, -v      Verbose output
  --json-only        Output JSON only (no console report)
```

## Threat Model

The tool addresses 12 threat categories (T01–T12) specific to MCP server security:

- **T01** — Tool Poisoning (hidden instructions in descriptions)
- **T02** — Rug Pull (post-approval description changes)
- **T03** — Excessive Permissions (principle of least privilege violations)
- **T04** — Credential Leakage
- **T06** — Argument Injection (SQL, path traversal, command, SSRF)
- **T07** — Cross-Server Shadowing
- **T09** — Missing Authentication
- **T10** — Transport Security
- **T11** — Insufficient Logging

## Requirements

- Python 3.11+
- MCP SDK (`mcp>=1.0.0`)
- Pydantic, Rich, httpx

## License

MIT
