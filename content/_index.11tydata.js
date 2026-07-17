'use strict';

const { latestCves } = require('../lib/cve-latest');

module.exports = {
  latestCves: latestCves(10),
};
