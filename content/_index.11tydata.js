'use strict';

const { homepageMetrics } = require('../lib/homepage-metrics');

module.exports = {
  // The expiring latest view is served through SSI by the existing MCP
  // runtime. Do not bake dated CVE cards into immutable homepage HTML.
  homepageMetrics: homepageMetrics(),
};
