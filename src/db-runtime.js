'use strict';

const config = require('./config');
const { createAsyncDatabase } = require('./db-async');

// One process-wide async connection. Consumers await getDatabase() at their
// async boundary; this avoids opening a new D1 REST client per request.
let databasePromise;

function getDatabase() {
  if (!databasePromise) databasePromise = createAsyncDatabase();
  return databasePromise;
}

function resetDatabaseForTests() {
  databasePromise = undefined;
}

module.exports = { getDatabase, resetDatabaseForTests, backend: config.database.backend };
