'use strict';

const { latestCves } = require('../lib/cve-latest');
const { homepageMetrics } = require('../lib/homepage-metrics');

module.exports = {
  latestCves: latestCves(10),
  homepageMetrics: homepageMetrics(),
};
