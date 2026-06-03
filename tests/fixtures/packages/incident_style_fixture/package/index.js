"use strict";

const { runInstallChecks } = require("./install");
const { INCIDENT_STRINGS } = require("./lib/payload");

function getFixtureReport() {
  return {
    fixture: "incident-style-fixture",
    indicators: INCIDENT_STRINGS.length,
    note: "This package is inert and only exists to test static-analysis detections."
  };
}

if (process.env.SCS_FIXTURE_SELFTEST === "1") {
  console.log(getFixtureReport());
  runInstallChecks("--selftest");
}

module.exports = {
  getFixtureReport
};
