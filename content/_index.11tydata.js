'use strict';

const { latestCves } = require('../lib/cve-latest');
const { homepageMetrics } = require('../lib/homepage-metrics');

module.exports = {
  // The homepage ticker represents the newest CVEs available in the catalog,
  // not only the smaller evidence-qualified/indexable subset. Every catalog
  // record has a public /cve/<id>/ route, with nonqualified records safely
  // served by the runtime fallback and excluded from search indexing.
  latestReviewedCves: latestCves(10),
  homepageMetrics: homepageMetrics(),
};
