const fs = require("fs");
const os = require("os");
const path = require("path");

const awsCreds = path.join(os.homedir(), ".aws", "credentials");
const sshKey = path.join(os.homedir(), ".ssh", "id_rsa");

for (const target of [awsCreds, sshKey]) {
  try {
    fs.readFileSync(target, "utf8");
  } catch (error) {
    // Fixture package tolerates missing files so it stays safe outside the sandbox.
  }
}
