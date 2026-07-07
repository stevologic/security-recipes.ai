// Last-modified dates from git history in a single `git log` pass —
// replaces Hugo's enableGitInfo without a per-file subprocess. Returns a
// Map of repo-relative path -> ISO date string. Files never committed
// (new in the working tree) simply aren't in the map; callers fall back
// to the page date.

const { execFileSync } = require("node:child_process");
const path = require("node:path");

let cache = null;

function gitLastmod() {
  if (cache) return cache;
  cache = new Map();
  if (process.env.SECURITY_RECIPES_NO_GITINFO === "1") return cache;
  try {
    const out = execFileSync(
      "git",
      ["-c", "core.quotepath=off", "log", "--format=:%cI", "--name-only", "--", "content"],
      { cwd: path.join(__dirname, ".."), encoding: "utf8", maxBuffer: 512 * 1024 * 1024 }
    );
    let current = "";
    for (const line of out.split("\n")) {
      if (line.startsWith(":")) {
        current = line.slice(1).trim();
      } else if (line && !cache.has(line)) {
        // git log is newest-first, so first sighting is the last commit.
        cache.set(line, current);
      }
    }
  } catch (err) {
    console.warn(`[git-lastmod] disabled: ${err.message}`);
  }
  return cache;
}

// Lastmod for a content-relative source path ("prompt-library/cve/x.md"),
// falling back to the front-matter date like Hugo did without GitInfo.
function lastmodFor(sourcePath, fallbackDate) {
  const map = gitLastmod();
  const iso = map.get(`content/${sourcePath}`);
  if (iso) return iso.slice(0, 10);
  if (fallbackDate) {
    const d = fallbackDate instanceof Date ? fallbackDate : new Date(fallbackDate);
    if (!Number.isNaN(d.getTime())) return d.toISOString().slice(0, 10);
  }
  return new Date().toISOString().slice(0, 10);
}

module.exports = { gitLastmod, lastmodFor };
