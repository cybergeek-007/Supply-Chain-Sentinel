"use strict";

const INCIDENT_STRINGS = [
  "eval(",
  "Function(",
  "child_process",
  "spawn(",
  "execSync(",
  "fetch(",
  "axios.post(",
  "process.env.NPM_TOKEN",
  "process.env.GITHUB_TOKEN",
  ".ssh/id_rsa",
  ".npmrc",
  "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "launchctl load",
  "crontab -l",
  "dns.resolve",
  "https://collector.example.invalid/api/upload",
  "ZXZhbChhdG9iKCIiKSk="
];

module.exports = {
  INCIDENT_STRINGS
};
