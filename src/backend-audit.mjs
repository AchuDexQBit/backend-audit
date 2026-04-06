#!/usr/bin/env node

/**
 * Node.js Backend Security & Structure Audit Tool
 *
 * Usage: node backend-audit.mjs
 *
 * Checks:
 * 1. Folder structure compliance (controllers, services, endpoints, routes, index.js)
 * 2. Middleware registration
 * 3. Route registration in app/index.js
 * 4. Utils files existence (db.js, status.js, versionMap.js)
 * 5. SQL injection vulnerabilities
 * 6. Missing transaction wrapping on write endpoints
 * 7. Hardcoded secrets/credentials
 * 8. Missing auth middleware on protected routes
 * 9. console.log / debugger statements
 * 10. Missing input validation
 */

import fs from "fs";
import path from "path";

// ─── Configuration ────────────────────────────────────────────────────────────

const CONFIG = {
  projectRoot: process.cwd(),
  outputFile: "backend-audit-report.html",
  excludeDirs: ["node_modules", ".next", "build", "dist", "out", ".git"],
  excludeFiles: ["backend-audit.mjs", "backend-audit-report.html"],
  fileExtensions: [".js", ".mjs", ".ts"],

  // Paths relative to projectRoot
  appRoutesDir: "src/routes/app",
  middlewareDir: "src/routes/middleware",
  utilsDir: "src/utils",

  // Required utils files
  requiredUtils: ["db.js", "status.js", "versionMap.js"],

  // Required middleware directories
  requiredMiddleware: ["logger", "versionChecker", "tokenValidation"],

  // Required files inside each module
  moduleRequiredFiles: ["index.js"],
  moduleRequiredSuffixes: ["_controllers.js", "_services.js", "_routes.js"],
  moduleRequiredDirs: ["_endpoints"],

  // Public routes that don't need auth (relative to appRoutesDir)
  publicModules: ["authentication"],
};

// ─── Results ──────────────────────────────────────────────────────────────────

const results = {
  critical: [],
  high: [],
  medium: [],
  low: [],
  info: [],
  summary: {
    filesScanned: 0,
    modulesScanned: 0,
    issuesFound: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
  },
};

// ─── Security Pattern Definitions ─────────────────────────────────────────────
//
// IMPORTANT: All patterns are stored as { source, flags } objects rather than
// regex literals. A fresh RegExp is constructed each time it is used via
// makeRegex(). This prevents the well-known JavaScript /g flag statefulness
// bug where a regex object retains lastIndex between .test() / .exec() calls
// across different strings, causing false-negative matches.

const SECURITY_PATTERNS = {
  hardcodedSecrets: [
    {
      source: "api[_-]?key\\s*[:=]\\s*['\"][^'\"]{10,}['\"]",
      flags: "gi",
      name: "API Key",
    },
    {
      source: "password\\s*[:=]\\s*['\"][^'\"]+['\"]",
      flags: "gi",
      name: "Password",
    },
    {
      source: "secret\\s*[:=]\\s*['\"][^'\"]{10,}['\"]",
      flags: "gi",
      name: "Secret",
    },
    {
      source: "token\\s*[:=]\\s*['\"][^'\"]{20,}['\"]",
      flags: "gi",
      name: "Token",
    },
    {
      source: "private[_-]?key\\s*[:=]\\s*['\"][^'\"]+['\"]",
      flags: "gi",
      name: "Private Key",
    },
    {
      source: "mongodb(\\+srv)?:\\/\\/[^:]+:[^@]+@",
      flags: "gi",
      name: "MongoDB Connection String",
    },
    {
      source: "postgres:\\/\\/[^:]+:[^@]+@",
      flags: "gi",
      name: "PostgreSQL Connection String",
    },
    {
      source: "mysql:\\/\\/[^:]+:[^@]+@",
      flags: "gi",
      name: "MySQL Connection String",
    },
    {
      source: "Bearer\\s+[A-Za-z0-9\\-._~+\\/]+=*",
      flags: "gi",
      name: "Bearer Token",
    },
    { source: "sk-[a-zA-Z0-9]{32,}", flags: "gi", name: "OpenAI API Key" },
  ],
  sqlInjection: [
    {
      source:
        "(?:db|pool|connection|conn)\\s*\\.\\s*(?:execute|query)\\s*\\(\\s*['\"`][^'\"`]*\\+",
      flags: "gi",
      name: "SQL String Concatenation in db call",
    },
    {
      source:
        "(?:db|pool|connection|conn)\\s*\\.\\s*(?:execute|query)\\s*\\(\\s*`[^`]*\\$\\{",
      flags: "gi",
      name: "Template Literal in SQL query",
    },
    {
      source: "(?:query|sql)\\s*[+]=\\s*['\"`]",
      flags: "gi",
      name: "SQL String Being Built via Concatenation",
    },
    {
      source: "execSync\\s*\\(\\s*['\"`][^'\"`]*\\$\\{",
      flags: "gi",
      name: "Command Injection Risk",
    },
  ],
  insecurePatterns: [
    {
      source: "console\\.log\\s*\\(",
      flags: "gi",
      name: "console.log Statement",
    },
    {
      source: "console\\.error\\s*\\(",
      flags: "gi",
      name: "console.error Statement",
    },
    { source: "debugger\\s*;?", flags: "gi", name: "Debugger Statement" },
    {
      source: "localStorage\\.setItem.*(?:token|password|secret)",
      flags: "gi",
      name: "Sensitive Data in LocalStorage",
    },
  ],
  inputValidation: {
    // Presence of any recognised validation library or guard
    validationPresence: {
      source:
        "(?:joi|zod|yup|express-validator|validator|req\\.body\\s*&&|if\\s*\\(\\s*!req\\.body|validateBody|validate\\()",
      flags: "gi",
    },
    reqDataUsage: {
      body: { source: "req\\.body", flags: "gi" },
      params: { source: "req\\.params", flags: "gi" },
      query: { source: "req\\.query", flags: "gi" },
    },
  },
  transactions: {
    // Matches any write SQL keyword at the start of a statement
    writePattern: {
      source:
        "(?:INSERT|UPDATE|DELETE|insert|update|delete)\\s+(?:INTO|FROM|)\\s*\\w+",
      flags: "g",
    },
    // Matches any recognised transaction-begin call
    transactionPattern: {
      source:
        "(?:beginTransaction|START TRANSACTION|db\\.beginTransaction|connection\\.beginTransaction|await\\s+\\w+\\.beginTransaction)",
      flags: "gi",
    },
  },
};

/** Build a fresh RegExp from a pattern definition — never reuse a /g instance. */
function makeRegex({ source, flags }) {
  return new RegExp(source, flags);
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function addFinding(
  severity,
  category,
  file,
  line,
  issue,
  recommendation,
  code = "",
) {
  results[severity].push({
    category,
    file: path.relative(CONFIG.projectRoot, String(file)),
    line,
    issue,
    recommendation,
    code: String(code).trim().substring(0, 120),
  });
  results.summary[`${severity}Count`]++;
  if (severity !== "info") results.summary.issuesFound++;
}

function getAllFiles(dir, fileList = []) {
  if (!fs.existsSync(dir)) return fileList;
  const files = fs.readdirSync(dir);
  files.forEach((file) => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      if (!CONFIG.excludeDirs.includes(file)) getAllFiles(filePath, fileList);
    } else {
      const fileName = path.basename(filePath);
      if (CONFIG.excludeFiles.includes(fileName)) return;
      const ext = path.extname(file);
      if (CONFIG.fileExtensions.includes(ext)) fileList.push(filePath);
    }
  });
  return fileList;
}

function readFile(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

// ─── Structure Checks ─────────────────────────────────────────────────────────

function checkUtilsFiles() {
  const utilsDir = path.join(CONFIG.projectRoot, CONFIG.utilsDir);

  if (!fs.existsSync(utilsDir)) {
    addFinding(
      "high",
      "Project Structure",
      CONFIG.utilsDir,
      0,
      "Utils directory not found",
      `Create the directory at ${CONFIG.utilsDir} with db.js, status.js, and versionMap.js`,
    );
    return;
  }

  CONFIG.requiredUtils.forEach((file) => {
    const filePath = path.join(utilsDir, file);
    if (!fs.existsSync(filePath)) {
      addFinding(
        "high",
        "Project Structure",
        path.join(CONFIG.utilsDir, file),
        0,
        `Missing required utils file: ${file}`,
        `Create ${file} in ${CONFIG.utilsDir}. This file is required by the project template.`,
      );
    } else {
      addFinding(
        "info",
        "Project Structure",
        path.join(CONFIG.utilsDir, file),
        0,
        `✅ Utils file exists: ${file}`,
        "",
      );
    }
  });
}

function checkMiddleware() {
  const middlewareDir = path.join(CONFIG.projectRoot, CONFIG.middlewareDir);

  if (!fs.existsSync(middlewareDir)) {
    addFinding(
      "high",
      "Middleware Structure",
      CONFIG.middlewareDir,
      0,
      "Middleware directory not found",
      `Create the middleware directory at ${CONFIG.middlewareDir}`,
    );
    return;
  }

  CONFIG.requiredMiddleware.forEach((mw) => {
    const mwPath = path.join(middlewareDir, mw);
    if (!fs.existsSync(mwPath)) {
      addFinding(
        "high",
        "Middleware Structure",
        path.join(CONFIG.middlewareDir, mw),
        0,
        `Missing required middleware: ${mw}`,
        `Create the ${mw} middleware directory with an index.js inside ${CONFIG.middlewareDir}`,
      );
    } else {
      const indexPath = path.join(mwPath, "index.js");
      if (!fs.existsSync(indexPath)) {
        addFinding(
          "medium",
          "Middleware Structure",
          path.join(CONFIG.middlewareDir, mw),
          0,
          `Middleware directory '${mw}' is missing index.js`,
          `Create index.js inside ${path.join(CONFIG.middlewareDir, mw)}`,
        );
      } else {
        addFinding(
          "info",
          "Middleware Structure",
          path.join(CONFIG.middlewareDir, mw, "index.js"),
          0,
          `✅ Middleware exists: ${mw}`,
          "",
        );
      }
    }
  });

  const middlewareIndexPath = path.join(middlewareDir, "index.js");
  if (fs.existsSync(middlewareIndexPath)) {
    const content = readFile(middlewareIndexPath);
    if (content) {
      CONFIG.requiredMiddleware.forEach((mw) => {
        if (!content.includes(mw)) {
          addFinding(
            "medium",
            "Middleware Registration",
            middlewareIndexPath,
            0,
            `Middleware '${mw}' is not exported from middleware/index.js`,
            `Import and export '${mw}' in ${CONFIG.middlewareDir}/index.js`,
          );
        }
      });
    }
  } else {
    addFinding(
      "high",
      "Middleware Structure",
      middlewareIndexPath,
      0,
      "Missing middleware/index.js — middleware barrel file not found",
      `Create index.js in ${CONFIG.middlewareDir} that imports and exports all middleware`,
    );
  }
}

function checkModuleStructure() {
  const appDir = path.join(CONFIG.projectRoot, CONFIG.appRoutesDir);

  if (!fs.existsSync(appDir)) {
    addFinding(
      "high",
      "Project Structure",
      CONFIG.appRoutesDir,
      0,
      "App routes directory not found",
      `Create the directory at ${CONFIG.appRoutesDir}`,
    );
    return;
  }

  const appIndexPath = path.join(appDir, "index.js");
  if (!fs.existsSync(appIndexPath)) {
    addFinding(
      "high",
      "Project Structure",
      appIndexPath,
      0,
      "Missing app routes index.js",
      `Create index.js in ${CONFIG.appRoutesDir} to register all modules and middleware`,
    );
  }

  const entries = fs.readdirSync(appDir);
  const modules = entries.filter((entry) => {
    const entryPath = path.join(appDir, entry);
    return fs.statSync(entryPath).isDirectory();
  });

  results.summary.modulesScanned = modules.length;

  modules.forEach((moduleName) => {
    const moduleDir = path.join(appDir, moduleName);
    checkSingleModule(moduleName, moduleDir, appIndexPath);
  });
}

function checkSingleModule(moduleName, moduleDir, appIndexPath) {
  const indexPath = path.join(moduleDir, "index.js");
  if (!fs.existsSync(indexPath)) {
    addFinding(
      "high",
      "Module Structure",
      moduleDir,
      0,
      `Module '${moduleName}' is missing index.js`,
      `Create index.js in ${path.relative(CONFIG.projectRoot, moduleDir)} that wires controllers, services and routes together`,
    );
  }

  CONFIG.moduleRequiredSuffixes.forEach((suffix) => {
    const expectedFile = `${moduleName}${suffix}`;
    const filePath = path.join(moduleDir, expectedFile);
    if (!fs.existsSync(filePath)) {
      addFinding(
        "medium",
        "Module Structure",
        moduleDir,
        0,
        `Module '${moduleName}' is missing ${expectedFile}`,
        `Create ${expectedFile} in ${path.relative(CONFIG.projectRoot, moduleDir)} following the Controller → Service → Endpoint pattern`,
      );
    }
  });

  const endpointsDir = path.join(moduleDir, `${moduleName}_endpoints`);
  if (!fs.existsSync(endpointsDir)) {
    addFinding(
      "medium",
      "Module Structure",
      moduleDir,
      0,
      `Module '${moduleName}' is missing '${moduleName}_endpoints' directory`,
      `Create the endpoints directory at ${path.relative(CONFIG.projectRoot, endpointsDir)}`,
    );
  } else {
    const endpointsIndex = path.join(endpointsDir, "index.js");
    if (!fs.existsSync(endpointsIndex)) {
      addFinding(
        "medium",
        "Module Structure",
        endpointsDir,
        0,
        `Module '${moduleName}' endpoints directory is missing index.js`,
        `Create index.js in ${path.relative(CONFIG.projectRoot, endpointsDir)} that exports all endpoint functions`,
      );
    }
  }

  if (appIndexPath && fs.existsSync(appIndexPath)) {
    const appIndexContent = readFile(appIndexPath);
    if (appIndexContent && !appIndexContent.includes(moduleName)) {
      addFinding(
        "high",
        "Route Registration",
        appIndexPath,
        0,
        `Module '${moduleName}' is not registered in app/index.js`,
        `Import and register the '${moduleName}' module in ${CONFIG.appRoutesDir}/index.js using router.use('/${moduleName}/', ${moduleName})`,
      );
    }
  }
}

// ─── Code Safety Checks ───────────────────────────────────────────────────────

function checkHardcodedSecrets(file, content) {
  const lines = content.split("\n");
  SECURITY_PATTERNS.hardcodedSecrets.forEach((patternDef) => {
    // Build a fresh non-global regex for per-line testing
    const regex = makeRegex({
      source: patternDef.source,
      flags: patternDef.flags.replace("g", ""),
    });
    lines.forEach((line, index) => {
      if (regex.test(line)) {
        if (
          line.trim().startsWith("//") ||
          line.trim().startsWith("*") ||
          line.includes("example") ||
          line.includes("your-") ||
          line.includes("process.env")
        )
          return;
        addFinding(
          "critical",
          "Hardcoded Secrets",
          file,
          index + 1,
          `Potential ${patternDef.name} hardcoded in source code`,
          `Move this to environment variables and access via process.env. Never commit secrets to version control.`,
          line,
        );
      }
    });
  });
}

function checkSqlInjection(file, content) {
  const lines = content.split("\n");
  SECURITY_PATTERNS.sqlInjection.forEach((patternDef) => {
    // Build a fresh non-global regex for per-line testing
    const regex = makeRegex({
      source: patternDef.source,
      flags: patternDef.flags.replace("g", ""),
    });
    lines.forEach((line, index) => {
      if (regex.test(line)) {
        addFinding(
          "high",
          "SQL Injection",
          file,
          index + 1,
          `Potential SQL Injection: ${patternDef.name}`,
          `Use parameterized queries. Example: db.execute('SELECT * FROM table WHERE id = ?', [id]) — never concatenate user input into SQL strings.`,
          line,
        );
      }
    });
  });
}

function checkInsecurePatterns(file, content) {
  const lines = content.split("\n");
  SECURITY_PATTERNS.insecurePatterns.forEach((patternDef) => {
    // Build a fresh non-global regex for per-line testing
    const regex = makeRegex({
      source: patternDef.source,
      flags: patternDef.flags.replace("g", ""),
    });
    lines.forEach((line, index) => {
      if (regex.test(line)) {
        const severity =
          patternDef.name.includes("console") ||
          patternDef.name.includes("Debugger")
            ? "low"
            : "medium";
        const recommendation = patternDef.name.includes("console.log")
          ? "Remove console.log in production. Use a proper logger (e.g. Winston) with log levels."
          : patternDef.name.includes("console.error")
            ? "Replace console.error with a proper logger. Avoid leaking stack traces in production."
            : patternDef.name.includes("Debugger")
              ? "Remove debugger statements before committing."
              : "Never store sensitive data in browser storage.";
        addFinding(
          severity,
          "Insecure Pattern",
          file,
          index + 1,
          patternDef.name,
          recommendation,
          line,
        );
      }
    });
  });
}

function checkInputValidation(file, content) {
  if (!file.includes("_endpoints")) return;

  // Each test gets a fresh regex — no shared state
  const hasValidation = makeRegex(
    SECURITY_PATTERNS.inputValidation.validationPresence,
  ).test(content);
  const hasReqBody = makeRegex(
    SECURITY_PATTERNS.inputValidation.reqDataUsage.body,
  ).test(content);
  const hasReqParams = makeRegex(
    SECURITY_PATTERNS.inputValidation.reqDataUsage.params,
  ).test(content);
  const hasReqQuery = makeRegex(
    SECURITY_PATTERNS.inputValidation.reqDataUsage.query,
  ).test(content);

  if ((hasReqBody || hasReqParams || hasReqQuery) && !hasValidation) {
    addFinding(
      "medium",
      "Missing Input Validation",
      file,
      0,
      "Endpoint uses request data but has no input validation",
      `Add input validation using Joi, Zod, or express-validator before processing req.body/params/query. Example: const schema = Joi.object({ id: Joi.number().required() }); const { error } = schema.validate(req.body);`,
    );
  }
}

function checkTransactions(file, content) {
  if (!file.includes("_endpoints")) return;

  // Build fresh RegExp instances for every file — eliminates lastIndex statefulness
  const isWriteEndpoint = makeRegex(
    SECURITY_PATTERNS.transactions.writePattern,
  ).test(content);
  const hasTransaction = makeRegex(
    SECURITY_PATTERNS.transactions.transactionPattern,
  ).test(content);

  if (isWriteEndpoint && !hasTransaction) {
    addFinding(
      "high",
      "Missing Transaction",
      file,
      0,
      "Write operation (INSERT/UPDATE/DELETE) found without transaction wrapping",
      `Wrap all write operations in a transaction. Example:\n  await connection.beginTransaction();\n  try { ...queries... await connection.commit(); } catch(e) { await connection.rollback(); throw e; }`,
    );
  }
}

function checkAuthMiddleware() {
  const appIndexPath = path.join(
    CONFIG.projectRoot,
    CONFIG.appRoutesDir,
    "index.js",
  );
  if (!fs.existsSync(appIndexPath)) return;

  const content = readFile(appIndexPath);
  if (!content) return;

  const lines = content.split("\n");

  const hasTokenValidator = /tokenValidat/gi.test(content);
  if (!hasTokenValidator) {
    addFinding(
      "high",
      "Missing Auth Middleware",
      appIndexPath,
      0,
      "tokenValidator middleware is not applied in app/index.js",
      `Add router.use(middleware.tokenValidator) after your public routes (e.g. authentication) to protect all subsequent routes.`,
    );
    return;
  }

  let tokenValidatorLine = -1;
  lines.forEach((line, index) => {
    if (/tokenValidat/gi.test(line)) tokenValidatorLine = index;
  });

  if (tokenValidatorLine > -1) {
    lines.forEach((line, index) => {
      if (index >= tokenValidatorLine) return;
      const routerUseMatch = line.match(/router\.use\s*\(\s*['"`]\/(\w+)/);
      if (routerUseMatch) {
        const routeName = routerUseMatch[1];
        if (!CONFIG.publicModules.includes(routeName)) {
          addFinding(
            "high",
            "Missing Auth Middleware",
            appIndexPath,
            index + 1,
            `Route '/${routeName}' is registered before tokenValidator — it is unprotected`,
            `Move router.use('/${routeName}', ...) to after router.use(middleware.tokenValidator) in app/index.js`,
            line,
          );
        }
      }
    });
  }
}

// ─── Report Generation ────────────────────────────────────────────────────────

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function generateSeveritySection(severity, title) {
  if (results[severity].length === 0) return "";
  const findings = results[severity]
    .map(
      (f) => `
    <div class="finding">
      <div class="finding-header">
        <div class="finding-title">${escapeHtml(f.issue)}</div>
        <div class="finding-category">${escapeHtml(f.category)}</div>
      </div>
      <div class="finding-location">${escapeHtml(f.file)}${f.line ? `:${f.line}` : ""}</div>
      <div class="finding-recommendation"><strong>Recommendation:</strong> ${escapeHtml(f.recommendation)}</div>
      ${f.code ? `<div class="finding-code">${escapeHtml(f.code)}</div>` : ""}
    </div>`,
    )
    .join("");

  return `
    <div class="severity-section">
      <div class="severity-header ${severity}-header">${title} <span class="badge">${results[severity].length}</span></div>
      ${findings}
    </div>`;
}

function generateReport() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const formattedDate = `${pad(now.getDate())}/${pad(now.getMonth() + 1)}/${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Backend Audit Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 20px; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.4); overflow: hidden; }
    .header { background: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%); color: white; padding: 40px; text-align: center; }
    .header h1 { font-size: 2.2em; margin-bottom: 10px; font-weight: 700; }
    .header p { opacity: 0.85; font-size: 1.05em; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 20px; padding: 40px; background: #f8f9fa; }
    .summary-card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.08); text-align: center; }
    .summary-card .number { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
    .summary-card .label { color: #666; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }
    .critical .number { color: #dc3545; }
    .high .number { color: #fd7e14; }
    .medium .number { color: #ffc107; }
    .low .number { color: #17a2b8; }
    .findings { padding: 40px; }
    .severity-section { margin-bottom: 40px; }
    .severity-header { display: flex; align-items: center; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; font-size: 1.2em; font-weight: 600; color: white; }
    .critical-header { background: #dc3545; }
    .high-header { background: #fd7e14; }
    .medium-header { background: #e6a817; color: #fff; }
    .low-header { background: #17a2b8; }
    .finding { background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin-bottom: 15px; transition: box-shadow 0.2s; }
    .finding:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; gap: 10px; }
    .finding-title { font-weight: 600; font-size: 1.05em; color: #222; }
    .finding-category { background: #e9ecef; padding: 3px 10px; border-radius: 20px; font-size: 0.82em; color: #495057; white-space: nowrap; }
    .finding-location { color: #888; font-size: 0.88em; margin-bottom: 10px; font-family: monospace; }
    .finding-recommendation { background: #f8f9fa; padding: 12px; border-radius: 6px; border-left: 4px solid #0f3460; margin-top: 10px; font-size: 0.95em; white-space: pre-wrap; }
    .finding-code { background: #272822; color: #f8f8f2; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 0.88em; margin-top: 10px; overflow-x: auto; }
    .footer { background: #f8f9fa; padding: 30px; text-align: center; color: #666; border-top: 1px solid #e0e0e0; font-size: 0.95em; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; margin-left: 10px; background: rgba(255,255,255,0.25); }
    .stats { display: flex; justify-content: center; gap: 30px; flex-wrap: wrap; margin-top: 10px; }
    .stat { font-size: 0.95em; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Backend Audit Report</h1>
      <p>Generated on ${formattedDate}</p>
      <p>Project: ${path.basename(CONFIG.projectRoot)}</p>
    </div>
    <div class="summary">
      <div class="summary-card critical"><div class="number">${results.summary.criticalCount}</div><div class="label">Critical</div></div>
      <div class="summary-card high"><div class="number">${results.summary.highCount}</div><div class="label">High</div></div>
      <div class="summary-card medium"><div class="number">${results.summary.mediumCount}</div><div class="label">Medium</div></div>
      <div class="summary-card low"><div class="number">${results.summary.lowCount}</div><div class="label">Low</div></div>
    </div>
    <div class="findings">
      ${generateSeveritySection("critical", "Critical Issues")}
      ${generateSeveritySection("high", "High Severity Issues")}
      ${generateSeveritySection("medium", "Medium Severity Issues")}
      ${generateSeveritySection("low", "Low Severity Issues")}
      ${
        results.critical.length === 0 &&
        results.high.length === 0 &&
        results.medium.length === 0 &&
        results.low.length === 0
          ? '<div style="text-align:center;padding:60px;color:#28a745;font-size:1.3em;font-weight:600;">✅ No issues found — looking good!</div>'
          : ""
      }
    </div>
    <div class="footer">
      <div class="stats">
        <span class="stat"><strong>Files Scanned:</strong> ${results.summary.filesScanned}</span>
        <span class="stat"><strong>Modules Scanned:</strong> ${results.summary.modulesScanned}</span>
        <span class="stat"><strong>Total Issues:</strong> ${results.summary.issuesFound}</span>
      </div>
      <p style="margin-top:12px;">Generated by backend-audit.mjs — review each finding and implement recommended fixes.</p>
    </div>
  </div>
</body>
</html>`;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function runAudit() {
  console.log("\nStarting backend audit...\n");
  const startTime = Date.now();

  console.log("Checking utils files...");
  checkUtilsFiles();

  console.log("Checking middleware structure...");
  checkMiddleware();

  console.log("Checking module structure...");
  checkModuleStructure();

  console.log("Checking auth middleware...");
  checkAuthMiddleware();

  console.log("Scanning source files...");
  const files = getAllFiles(path.join(CONFIG.projectRoot, "src"));
  results.summary.filesScanned = files.length;
  console.log(`   Found ${files.length} files to analyse\n`);

  files.forEach((file) => {
    const content = readFile(file);
    if (!content) return;

    checkHardcodedSecrets(file, content);
    checkSqlInjection(file, content);
    checkInsecurePatterns(file, content);
    checkInputValidation(file, content);
    checkTransactions(file, content);
  });

  console.log("Generating report...");
  const html = generateReport();
  const outputPath = path.join(CONFIG.projectRoot, CONFIG.outputFile);
  fs.writeFileSync(outputPath, html);

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log("\nBackend audit complete!\n");
  console.log("═══════════════════════════════════════");
  console.log(`  Files Scanned:   ${results.summary.filesScanned}`);
  console.log(`  Modules Scanned: ${results.summary.modulesScanned}`);
  console.log(`  Critical:        ${results.summary.criticalCount}`);
  console.log(`  High:            ${results.summary.highCount}`);
  console.log(`  Medium:          ${results.summary.mediumCount}`);
  console.log(`  Low:             ${results.summary.lowCount}`);
  console.log(`  Duration:        ${duration}s`);
  console.log("═══════════════════════════════════════");
  console.log(`\nReport saved to: ${CONFIG.outputFile}\n`);

  if (
    results.summary.criticalCount > 0 ||
    results.summary.highCount > 0 ||
    results.summary.mediumCount > 0
  ) {
    console.error("❌ Issues found — fix before merging.");
    process.exit(1);
  }

  console.log("✅ All checks passed.");
}

export { runAudit };
