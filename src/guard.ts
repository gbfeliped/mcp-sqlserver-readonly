/**
 * Read-only SQL guard for SQL Server.
 *
 * Pipeline:
 *  1. Strip string literals → replace content with spaces (keeps token positions)
 *  2. Strip comments (block and line)
 *  3. Normalise whitespace
 *  4. Run all rejection checks on the scrubbed text
 *  5. Pass the original, untouched query to the driver
 */

// ---------------------------------------------------------------------------
// Rejection lists
// ---------------------------------------------------------------------------

/** Write / DDL keywords — matched with word boundaries */
const WRITE_KEYWORDS = [
  "INSERT",
  "UPDATE",
  "DELETE",
  "DROP",
  "CREATE",
  "ALTER",
  "TRUNCATE",
  "MERGE",
  "REPLACE",
  "EXEC",
  "EXECUTE",
];

/** Dangerous built-in procs/functions — matched with word boundaries */
const DANGEROUS_PROCS = [
  // Remote access
  "XP_CMDSHELL",
  "XP_REGREAD",
  "XP_REGWRITE",
  "XP_REGENUMVALUES",
  "XP_REGDELETEVALUE",
  "XP_REGDELETEKEY",
  "XP_DIRTREE",
  "XP_FILEEXIST",
  "XP_FIXEDDRIVES",
  "XP_SUBDIRS",
  "XP_ENUMGROUPS",
  "XP_LOGININFO",
  "XP_MSVER",
  // Config / admin
  "SP_CONFIGURE",
  "SP_EXECUTESQL",
  "SP_HELP",
  "SP_HELPDB",
  "SP_WHO",
  "SP_WHO2",
  "SP_ADDLOGIN",
  "SP_ADDSRVROLEMEMBER",
  "SP_DROPSERVER",
  "SP_PASSWORD",
  // OLE Automation
  "SP_OACREATE",
  "SP_OAMETHOD",
  "SP_OAGETPROPERTY",
  "SP_OASETPROPERTY",
  "SP_OASTOP",
  "SP_OAGETERRORINFO",
  // External data access
  "OPENROWSET",
  "OPENDATASOURCE",
  "OPENQUERY",
  "OPENXML",
  // Log / trace functions
  "FN_DBLOG",
  "FN_DUMP_DBLOG",
  "FN_XE_FILE_TARGET_READ_FILE",
  // Bulk / file write
  "BULK INSERT",
  "SP_MAKEWEBTASK",
];

/** DoS constructs */
const DOS_PATTERNS = [
  /WAITFOR\s+DELAY/i,
  /WAITFOR\s+TIME/i,
  /SLEEP\s*\(/i,
  // Recursive CTE without recursion guard: OPTION (MAXRECURSION 0)
  /OPTION\s*\(\s*MAXRECURSION\s+0\s*\)/i,
];

/**
 * Four-part linked-server references: [server].[db].[schema].[table]
 * or server.db.schema.table — detect by looking for two or more dot-separated
 * identifiers at the start of a FROM/JOIN target context.
 * A simpler heuristic: any token containing TWO or more dots (a.b.c or a.b.c.d).
 */
const LINKED_SERVER_PATTERN =
  /(?:\[?[A-Za-z0-9_$#]+\]?\s*\.\s*){2,}\[?[A-Za-z0-9_$#]+\]?/;

// ---------------------------------------------------------------------------
// Step 1 – scrub string literal content
// ---------------------------------------------------------------------------

/**
 * Replace the *content* of every single-quoted string literal with spaces of
 * equal length, preserving token boundaries.  The surrounding quotes are kept
 * so that subsequent comment-stripping does not accidentally treat apostrophes
 * inside values as SQL comment markers.
 */
function scrubStringLiterals(sql: string): string {
  let result = "";
  let i = 0;
  while (i < sql.length) {
    if (sql[i] === "'") {
      result += "'";
      i++;
      while (i < sql.length) {
        if (sql[i] === "'" && sql[i + 1] === "'") {
          // Escaped quote inside literal — replace both with spaces
          result += "  ";
          i += 2;
        } else if (sql[i] === "'") {
          result += "'";
          i++;
          break;
        } else {
          result += " "; // replace content char with space
          i++;
        }
      }
    } else {
      result += sql[i++];
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Step 2 – strip comments
// ---------------------------------------------------------------------------

/**
 * Remove block comments (including nested) and line comments.
 * String literals have already been scrubbed so we will not mis-identify
 * comment sequences inside string values.
 */
function stripComments(sql: string): string {
  let result = "";
  let i = 0;
  while (i < sql.length) {
    if (sql[i] === "/" && sql[i + 1] === "*") {
      let depth = 1;
      i += 2;
      while (i < sql.length && depth > 0) {
        if (sql[i] === "/" && sql[i + 1] === "*") { depth++; i += 2; }
        else if (sql[i] === "*" && sql[i + 1] === "/") { depth--; i += 2; }
        else i++;
      }
      result += " ";
    } else if (sql[i] === "-" && sql[i + 1] === "-") {
      while (i < sql.length && sql[i] !== "\n") i++;
      result += " ";
    } else {
      result += sql[i++];
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Step 3 – normalise whitespace
// ---------------------------------------------------------------------------

function normalise(sql: string): string {
  return sql.replace(/[\t\r\n]+/g, " ").replace(/  +/g, " ").trim();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export class SqlGuardError extends Error {
  constructor(reason: string) {
    super(`Query blocked: ${reason}`);
    this.name = "SqlGuardError";
  }
}

/**
 * Validate a SQL query.  Throws SqlGuardError if the query is not allowed.
 * Returns the original (untouched) query string to pass to the driver.
 */
export function validateQuery(sql: string): string {
  if (!sql || !sql.trim()) {
    throw new SqlGuardError("empty query");
  }

  // Build scrubbed version for all checks
  const scrubbed = stripComments(scrubStringLiterals(sql));
  const normalised = normalise(scrubbed).toUpperCase();

  // 1. Any semicolon at all — we do not allow multiple statements
  //    (legitimate read-only queries never need a trailing semicolon either)
  if (/;/.test(scrubbed)) {
    throw new SqlGuardError("semicolons are not allowed (multiple statements)");
  }

  // 2. DoS patterns
  for (const pattern of DOS_PATTERNS) {
    if (pattern.test(normalised)) {
      throw new SqlGuardError(`DoS construct detected: ${pattern.source}`);
    }
  }

  // 3. Linked-server four-part references
  if (LINKED_SERVER_PATTERN.test(normalised)) {
    throw new SqlGuardError(
      "linked-server or multi-part identifier references are not allowed"
    );
  }

  // 4. Dangerous procs / functions  (word-boundary matched)
  for (const proc of DANGEROUS_PROCS) {
    const escaped = proc.replace(/\s+/g, "\\s+");
    const re = new RegExp(`(?<![A-Za-z0-9_])${escaped}(?![A-Za-z0-9_])`, "i");
    if (re.test(normalised)) {
      throw new SqlGuardError(`system procedure/function not allowed: ${proc}`);
    }
  }

  // 5. Write / DDL keywords  (word-boundary matched)
  for (const kw of WRITE_KEYWORDS) {
    const re = new RegExp(`(?<![A-Za-z0-9_])${kw}(?![A-Za-z0-9_])`, "i");
    if (re.test(normalised)) {
      throw new SqlGuardError(`write/DDL keyword not allowed: ${kw}`);
    }
  }

  // 6. Catch any SP_ / XP_ prefix calls not already in DANGEROUS_PROCS
  //    Lookbehind includes _ so identifiers like DISPLAY_SP_NAME are not false-positives
  if (/(?<![A-Za-z0-9_])(SP_|XP_)[A-Za-z0-9_]+/i.test(normalised)) {
    throw new SqlGuardError(
      "calls to SP_* or XP_* stored procedures are not allowed"
    );
  }

  // 7. Must start with SELECT or WITH (CTE)
  if (!/^(WITH\b|SELECT\b)/i.test(normalised)) {
    throw new SqlGuardError(
      "only SELECT queries are allowed (must start with SELECT or WITH)"
    );
  }

  return sql;
}
