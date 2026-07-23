const assert = require("node:assert/strict");
const test = require("node:test");

const {
  AI_CRAWLER_USER_AGENTS,
  ROBOTS_DISALLOW_RULES,
  renderRobotsTxt,
} = require("../eleventy.config").robotsPolicy;

function userAgentGroups(robots) {
  const groups = new Map();
  for (const block of robots.split(/\n\s*\n/)) {
    const lines = block
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));
    if (!lines[0]?.startsWith("User-agent: ")) continue;
    groups.set(lines[0].slice("User-agent: ".length), lines.slice(1));
  }
  return groups;
}

test("named AI crawlers retain every shared site exclusion", () => {
  const robots = renderRobotsTxt();
  const groups = userAgentGroups(robots);
  const expectedRules = [
    "Allow: /",
    ...ROBOTS_DISALLOW_RULES,
  ];

  assert.deepEqual(groups.get("*"), expectedRules);
  for (const userAgent of AI_CRAWLER_USER_AGENTS) {
    assert.deepEqual(groups.get(userAgent), expectedRules, userAgent);
  }
  assert.doesNotMatch(robots, /Disallow: \/traffic\//);
  assert.doesNotMatch(robots, /^Disallow:\s*$/m);
});
