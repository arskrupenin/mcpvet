#!/bin/bash
# Example: scan a local MCP server

# Basic scan
mcpvet --stdio "python my_server.py"

# Scan with source code analysis
mcpvet --stdio "python my_server.py" \
    --server-dir ./my_server_code \
    --output my_scan_report \
    --verbose

# Scan HTTP server, skip transport checks
mcpvet --http "https://mcp.example.com/api" \
    --skip-checks TR-01,TR-03,TR-04

# Run only poisoning and rug pull checks
mcpvet --stdio "python server.py" \
    --checks CF-01,LM-03 \
    --hash-dir ./hashes
