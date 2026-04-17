const https = require("https");

const req = https.request(
  {
    host: "example.com",
    path: "/",
    method: "GET",
    timeout: 2000,
  },
  (res) => {
    res.resume();
  }
);

req.on("error", () => {
  // Ignore network errors so the fixture remains safe outside the sandbox.
});

req.end();
