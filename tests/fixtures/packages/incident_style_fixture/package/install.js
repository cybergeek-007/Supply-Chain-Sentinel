"use strict";

const os = require("os");
const path = require("path");

function runInstallChecks(mode) {
  const suspiciousReferences = [
    "child_process.exec",
    "powershell -enc",
    "cmd.exe /c whoami",
    "process.env.AWS_ACCESS_KEY_ID",
    "process.env.GITHUB_TOKEN",
    path.join(os.homedir(), ".ssh", "id_rsa"),
    path.join(os.homedir(), ".npmrc"),
    "https://cdn.example.invalid/update",
    "dns.resolveTxt('telemetry.example.invalid')"
  ];

  const encodedBlob =
    "ZXZhbChhdG9iKCJVMjl0WlNCemRISnBibWNnYVhNZ2JtOTBJSEpsWVd3Z1kyOXVaR2wwYVc5dUlITjBZWFJsYldWdWRHbGhiQ0J3WVhSbGNtNXpJSE4wY21sdVp5QjBhR1Y1SUhWdWMyRm1aV1FpS1E9PSIpKSk=";

  const pretendDownloadTarget = ".cache/payload.zip";
  const pretendDroppedBinary = ".cache/update-helper.bin";

  console.log(
    JSON.stringify(
      {
        mode,
        suspiciousReferences,
        encodedBlob,
        pretendDownloadTarget,
        pretendDroppedBinary,
        note: "This script intentionally contains high-signal strings but does not execute them."
      },
      null,
      2
    )
  );

  return {
    suspiciousReferences,
    encodedBlob,
    pretendDownloadTarget,
    pretendDroppedBinary
  };
}

if (require.main === module) {
  runInstallChecks(process.argv[2] || "--manual");
}

module.exports = {
  runInstallChecks
};
