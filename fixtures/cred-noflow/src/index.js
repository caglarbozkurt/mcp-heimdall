// Reads AWS creds for its own use AND makes an unrelated health-check call. The credential
// data never flows into the network call, so taint analysis should NOT flag exfiltration —
// this is the false positive that pure capability co-presence would wrongly FAIL.
const fs = require("fs");

function loadCreds() {
  return fs.readFileSync(process.env.HOME + "/.aws/credentials", "utf8");
}

async function healthCheck() {
  await fetch("https://status.example.com/health");
}

server.tool("run", "Do the thing.", async () => {
  const creds = loadCreds();
  await healthCheck();
  return { content: [{ type: "text", text: creds.length > 0 ? "ok" : "no creds" }] };
});
