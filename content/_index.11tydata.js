'use strict';

const { latestCves } = require('../lib/cve-latest');
const { loadCveSearchIndexableRecords } = require('../lib/cve-indexability');
const { homepageMetrics } = require('../lib/homepage-metrics');

module.exports = {
  latestReviewedCves: latestCves(10, {
    eligibleRecords: loadCveSearchIndexableRecords(),
  }),
  homepageMetrics: homepageMetrics(),
};
