# mcp-sqlserver

Read-only SQL Server MCP server for Claude Desktop (and any MCP-compatible client).

## Tools exposed

| Tool | Description |
|------|-------------|
| `query` | Run a SELECT query |
| `list_tables` | List all user tables with row-count estimate and size |
| `describe_table` | Show columns, types, nullability, PK for a table |
| `list_schemas` | List user-defined schemas |

## Security protections

| Attack | Example | Status |
|--------|---------|--------|
| Direct writes | `DROP`, `DELETE`, `UPDATE`, `INSERT` | ✅ Blocked |
| Multiple statements | `SELECT 1; DROP TABLE t` | ✅ Blocked |
| System procedures | `xp_cmdshell`, `EXEC sp_help` | ✅ Blocked |
| DoS | `WAITFOR DELAY '0:0:5'` | ✅ Blocked |
| Whitespace bypass | tabs and newlines between keywords | ✅ Blocked |
| Comment bypass | `/* */` and `--` before keywords | ✅ Blocked |
| Valid queries | `SELECT`, `SELECT TOP`, `COUNT`, `WHERE` | ✅ Allowed |

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MSSQL_SERVER` | ✅ | — | Server hostname or IP |
| `MSSQL_DATABASE` | ✅ | — | Database name |
| `MSSQL_USER` | ✅ | — | SQL login username |
| `MSSQL_PASSWORD` | ✅ | — | SQL login password |
| `MSSQL_PORT` | | `1433` | TCP port |
| `MSSQL_ENCRYPT` | | `true` | Enable TLS (`true`/`false`) |
| `MSSQL_TRUST_SERVER_CERTIFICATE` | | `false` | Trust self-signed certs |

## Build

```bash
npm install
npm run build
```

## Claude Desktop configuration

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sqlserver": {
      "command": "node",
      "args": ["C:/Users/gabri/OneDrive/Documentos/mcp-sqlserver/dist/index.js"],
      "env": {
        "MSSQL_SERVER": "localhost",
        "MSSQL_DATABASE": "MyDatabase",
        "MSSQL_USER": "sa",
        "MSSQL_PASSWORD": "YourPassword",
        "MSSQL_TRUST_SERVER_CERTIFICATE": "true"
      }
    }
  }
}
```
