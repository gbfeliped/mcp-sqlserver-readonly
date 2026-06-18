import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import sql from "mssql";
import { validateQuery, SqlGuardError } from "./guard.js";

// ---------------------------------------------------------------------------
// Connection config from environment variables
// ---------------------------------------------------------------------------

function getConfig(): sql.config {
  const server = process.env.MSSQL_SERVER;
  const database = process.env.MSSQL_DATABASE;
  const user = process.env.MSSQL_USER;
  const password = process.env.MSSQL_PASSWORD;
  const port = process.env.MSSQL_PORT ? parseInt(process.env.MSSQL_PORT, 10) : 1433;
  const trustServerCertificate =
    process.env.MSSQL_TRUST_SERVER_CERTIFICATE === "true";
  const encrypt = process.env.MSSQL_ENCRYPT !== "false"; // default true

  if (!server || !database || !user || !password) {
    throw new Error(
      "Missing required environment variables: MSSQL_SERVER, MSSQL_DATABASE, MSSQL_USER, MSSQL_PASSWORD"
    );
  }

  return {
    server,
    database,
    user,
    password,
    port,
    options: {
      encrypt,
      trustServerCertificate,
    },
    pool: {
      max: 10,
      min: 0,
      idleTimeoutMillis: 30000,
    },
    // Cap connection handshake and query execution to limit DoS surface
    connectionTimeout: 15000,
    requestTimeout: 10000,
  };
}

// ---------------------------------------------------------------------------
// Lazy connection pool
// ---------------------------------------------------------------------------

let pool: sql.ConnectionPool | null = null;

async function getPool(): Promise<sql.ConnectionPool> {
  if (!pool) {
    pool = await sql.connect(getConfig());
    pool.on("error", (err) =>
      process.stderr.write(`Pool error: ${err}\n`)
    );
  }
  return pool;
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "mcp-sqlserver",
  version: "1.0.0",
});

// ---- Tool: query ------------------------------------------------------------

server.registerTool(
  "query",
  {
    description:
      "Execute a read-only SELECT query against SQL Server. " +
      "Only SELECT (and CTEs starting with WITH) are permitted. " +
      "Write operations, system procedures, DoS constructs, and multiple " +
      "statements are all blocked.",
    inputSchema: { sql: z.string().describe("The SELECT query to execute") },
  },
  async ({ sql: userSql }) => {
    try {
      validateQuery(userSql);
    } catch (err) {
      if (err instanceof SqlGuardError) {
        return {
          content: [{ type: "text", text: `Error: ${err.message}` }],
          isError: true,
        };
      }
      throw err;
    }

    try {
      const db = await getPool();
      const request = db.request();
      const result = await request.query(userSql);

      if (!result.recordset || result.recordset.length === 0) {
        return {
          content: [{ type: "text", text: "Query returned no rows." }],
        };
      }

      const text = JSON.stringify(result.recordset, null, 2);
      return { content: [{ type: "text", text }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `SQL Server error: ${message}` }],
        isError: true,
      };
    }
  }
);

// ---- Tool: list_tables ------------------------------------------------------

server.registerTool(
  "list_tables",
  {
    description:
      "List all user tables in the connected SQL Server database, " +
      "including schema name, table name, row count estimate, and size in KB.",
    inputSchema: {},
  },
  async () => {
    const listSql = `
      SELECT
        s.name                                        AS schema_name,
        t.name                                        AS table_name,
        SUM(p.rows)                                   AS row_count_estimate,
        CAST(SUM(a.total_pages) * 8.0 AS DECIMAL(18, 2)) AS size_kb
      FROM sys.tables           t
      JOIN sys.schemas          s ON t.schema_id  = s.schema_id
      JOIN sys.indexes          i ON t.object_id  = i.object_id AND i.index_id IN (0, 1)
      JOIN sys.partitions       p ON i.object_id  = p.object_id AND i.index_id = p.index_id
      JOIN sys.allocation_units a ON p.partition_id = a.container_id
      GROUP BY s.name, t.name
      ORDER BY s.name, t.name
    `;

    try {
      const db = await getPool();
      const result = await db.request().query(listSql);
      if (!result.recordset || result.recordset.length === 0) {
        return { content: [{ type: "text", text: "No user tables found." }] };
      }
      return {
        content: [{ type: "text", text: JSON.stringify(result.recordset, null, 2) }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `SQL Server error: ${message}` }],
        isError: true,
      };
    }
  }
);

// ---- Tool: describe_table ---------------------------------------------------

server.registerTool(
  "describe_table",
  {
    description:
      "Describe the columns of a SQL Server table: name, data type, nullability, " +
      "max length, default value, and whether it is part of the primary key.",
    inputSchema: {
      schema: z.string().default("dbo").describe("Schema name (default: dbo)"),
      table: z.string().describe("Table name"),
    },
  },
  async ({ schema, table }) => {
    // Sanitise identifiers — only allow safe chars
    const identRe = /^[A-Za-z_][A-Za-z0-9_$#]*$/;
    if (!identRe.test(schema)) {
      return {
        content: [{ type: "text", text: "Error: invalid schema name" }],
        isError: true,
      };
    }
    if (!identRe.test(table)) {
      return {
        content: [{ type: "text", text: "Error: invalid table name" }],
        isError: true,
      };
    }

    const describeSql = `
      SELECT
        c.COLUMN_NAME,
        c.DATA_TYPE,
        c.CHARACTER_MAXIMUM_LENGTH,
        c.NUMERIC_PRECISION,
        c.NUMERIC_SCALE,
        c.IS_NULLABLE,
        c.COLUMN_DEFAULT,
        CASE WHEN kcu.COLUMN_NAME IS NOT NULL THEN 'YES' ELSE 'NO' END AS IS_PRIMARY_KEY
      FROM INFORMATION_SCHEMA.COLUMNS c
      LEFT JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
        ON  tc.TABLE_SCHEMA = c.TABLE_SCHEMA
        AND tc.TABLE_NAME   = c.TABLE_NAME
        AND tc.CONSTRAINT_TYPE = 'PRIMARY KEY'
      LEFT JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
        ON  kcu.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
        AND kcu.TABLE_SCHEMA    = c.TABLE_SCHEMA
        AND kcu.TABLE_NAME      = c.TABLE_NAME
        AND kcu.COLUMN_NAME     = c.COLUMN_NAME
      WHERE c.TABLE_SCHEMA = @schema
        AND c.TABLE_NAME   = @table
      ORDER BY c.ORDINAL_POSITION
    `;

    try {
      const db = await getPool();
      const result = await db.request()
        .input("schema", sql.NVarChar, schema)
        .input("table", sql.NVarChar, table)
        .query(describeSql);
      if (!result.recordset || result.recordset.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: `Table [${schema}].[${table}] not found or has no columns.`,
            },
          ],
        };
      }
      return {
        content: [{ type: "text", text: JSON.stringify(result.recordset, null, 2) }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `SQL Server error: ${message}` }],
        isError: true,
      };
    }
  }
);

// ---- Tool: list_schemas -----------------------------------------------------

server.registerTool(
  "list_schemas",
  {
    description: "List all schemas in the connected SQL Server database.",
    inputSchema: {},
  },
  async () => {
    const schemaSql = `
      SELECT name AS schema_name, principal_id
      FROM sys.schemas
      WHERE name NOT IN (
        'sys','INFORMATION_SCHEMA','db_owner','db_accessadmin',
        'db_securityadmin','db_ddladmin','db_backupoperator',
        'db_datareader','db_datawriter','db_denydatareader','db_denydatawriter'
      )
      ORDER BY name
    `;

    try {
      const db = await getPool();
      const result = await db.request().query(schemaSql);
      return {
        content: [{ type: "text", text: JSON.stringify(result.recordset, null, 2) }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: `SQL Server error: ${message}` }],
        isError: true,
      };
    }
  }
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr so it doesn't pollute the MCP stdio stream
  process.stderr.write("mcp-sqlserver running on stdio\n");
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
