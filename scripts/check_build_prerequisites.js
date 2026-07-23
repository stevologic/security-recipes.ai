#!/usr/bin/env node

"use strict";

const { spawnSync } = require("node:child_process");

const python = "python";
const check = spawnSync(
  python,
  [
    "-c",
    [
      "import sys",
      "assert sys.version_info >= (3, 10), 'Python 3.10 or newer is required'",
      "import fastmcp, httpx, markdown, tomli",
    ].join("; "),
  ],
  { encoding: "utf8" },
);

if (check.error && check.error.code === "ENOENT") {
  console.error(
    "Site build prerequisite missing: Python 3.10+ must be available as `python`.",
  );
  process.exit(1);
}

if (check.status !== 0) {
  const detail = (check.stderr || check.stdout || "").trim();
  console.error(
    "Site build prerequisite failed. Install Python 3.10+ and run " +
      "`python -m pip install -r requirements-mcp-server.txt`.",
  );
  if (detail) console.error(detail);
  process.exit(check.status || 1);
}

console.log("Site build prerequisites passed: Python 3.10+ CVE renderer is available.");
