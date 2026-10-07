// AGP-039: the UI in a real headless Chrome (rootless, over the DevTools protocol), as a human uses it:
// set the password with the setup code, make the approval key IN THE BROWSER, save its backup, enrol it,
// approve a waiting xbt402 call by signing in the page, sign a policy change, and check the pages on a
// phone-sized screen. Screenshots and HTML snapshots go to OUT.
//   node browser_test.mjs BASE SETUP_CODE OUT
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [BASE, CODE, OUT] = process.argv.slice(2);
mkdirSync(OUT, { recursive: true });
const CHROME = process.env.CHROME || "google-chrome";
const profile = mkdtempSync(join(tmpdir(), "xbtui-chrome-"));
const chrome = spawn(CHROME, ["--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--no-sandbox",
  "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
function check(name, ok, detail) { results.push({ name, ok: !!ok, detail }); console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : " " + (detail || "")}`); }

let port;
for (let i = 0; i < 100 && !port; i++) {
  await sleep(100);
  const f = join(profile, "DevToolsActivePort");
  if (existsSync(f)) port = readFileSync(f, "utf8").split("\n")[0];
}
if (!port) { console.log("FAIL chrome did not start"); process.exit(1); }
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let seq = 0; const pending = new Map(); const events = [];
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } else events.push(d);
});
function cdp(method, params = {}) {
  const id = ++seq;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((r) => pending.set(id, (d) => r(d.result || { error: d.error })));
}
async function ev(expr) {
  const r = await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`${expr}: ${JSON.stringify(r.exceptionDetails)}`);
  return r.result && r.result.value;
}
async function loaded() {
  for (let i = 0; i < 200; i++) {
    await sleep(50);
    try { if ((await ev("document.readyState")) === "complete" && (await ev("!!document.body"))) return; } catch (e) { /* navigating */ }
  }
}
async function go(path) { await cdp("Page.navigate", { url: BASE + path }); await sleep(100); await loaded(); }
async function submitAndWait(expr) {
  const before = await ev("performance.timeOrigin");
  await ev(expr);
  for (let i = 0; i < 400; i++) {
    await sleep(50);
    try { if ((await ev("performance.timeOrigin")) !== before && (await ev("document.readyState")) === "complete") return; } catch (e) { /* navigating */ }
  }
}
async function shot(name, width) {
  await cdp("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
  await sleep(150);
  const h = await ev("Math.min(document.documentElement.scrollHeight, 4000)");
  await cdp("Emulation.setDeviceMetricsOverride", { width, height: h, deviceScaleFactor: 1, mobile: width < 600 });
  const png = await cdp("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(OUT, `${name}.png`), Buffer.from(png.data, "base64"));
  writeFileSync(join(OUT, `${name}.html`), await ev("document.documentElement.outerHTML"));
  await cdp("Emulation.setDeviceMetricsOverride", { width: 1100, height: 900, deviceScaleFactor: 1, mobile: false });
}
const flash = () => ev("(document.querySelector('.flash')||{}).textContent||''");
const set = (sel, v) => ev(`(function(){var e=document.querySelector(${JSON.stringify(sel)});e.value=${JSON.stringify(v)};return true})()`);

await cdp("Page.enable"); await cdp("Runtime.enable");
const consoleErrors = [];
await cdp("Log.enable");
try {
  // 1. first run
  await go("/");
  check("first run asks for the setup code", (await ev("document.body.innerText")).includes("Setup code"));
  await shot("01-first-run", 1100);
  await set("[name=code]", CODE); await set("[name=password]", "browser box password"); await set("[name=password2]", "browser box password");
  await submitAndWait("document.querySelector('form').submit()");
  check("password set, on the setup page", (await ev("location.pathname")).endsWith("/setup"), await ev("location.href"));
  // 2. the approval key, made in the browser
  await ev("document.getElementById('keygen-new').click()");
  const backup = await ev("document.getElementById('keygen-backup').textContent");
  check("a 64-hex backup is shown", /^[0-9a-f]{64}$/.test(backup), backup);
  await set("#keygen-confirm", backup.slice(-8));
  await set("#keygen-pin", "246810"); await set("#keygen-pin2", "246810");
  await ev("document.getElementById('keygen-save').click()");
  await sleep(100);
  const weakMsg = await ev("document.getElementById('keygen-msg').textContent");
  check("a weak passphrase is refused", /at least 12 characters|only digits|repeated pattern/.test(weakMsg), weakMsg);
  const hint = await ev("document.getElementById('keygen-strength').textContent");
  check("a strength hint is shown", /12 characters|only digits|Strength:/.test(hint), hint);
  const PASS = "wallet-pass-41";
  await set("#keygen-pin", PASS); await set("#keygen-pin2", PASS);
  await ev("document.getElementById('keygen-save').click()");
  for (let i = 0; i < 400 && !(await ev("document.getElementById('keygen-msg').textContent")).includes("Saved"); i++) await sleep(50);
  const stored = await ev("localStorage.getItem('xbt-wallet-human-key-v1')");
  check("the key is stored encrypted in the browser, not in the clear", stored && !stored.includes(backup), stored);
  const pub = JSON.parse(stored).pub;
  check("a new wrap uses 210000 PBKDF2 iterations", JSON.parse(stored).iter === 210000, stored);
  await shot("02-setup-key", 1100);
  await submitAndWait("document.getElementById('enroll-form').submit()");
  check("the public key is enrolled", (await flash()).includes("Approval key enrolled"), await flash());
  check("the page knows this browser holds the enrolled key", (await ev("document.getElementById('browser-key').textContent")).includes("holds the enrolled"));
  // 3. plant an AGP-039 (60k) wrap of the same seed, then approve: unlocks, migrates, unlocks again later
  const planted = await ev(`(function(){
    var seed = XbtWallet.unhex(${JSON.stringify(backup)});
    var w = XbtWallet.wrap(seed, ${JSON.stringify(PASS)}, XbtWallet.LEGACY_ITER);
    XbtWallet.saveKey(w);
    return JSON.parse(localStorage.getItem(XbtWallet.STORE)).iter;
  })()`);
  check("a 60k wrap was planted for migration", planted === 60000, String(planted));
  await go("/approvals");
  await shot("03-approvals", 1100);
  await shot("03-approvals-phone", 390);
  const wrongPin = async () => {
    await set("form[data-sign=approve] input.pin", "000000000000");
    await ev("document.querySelector('form[data-sign=approve] button[type=submit]').click()");
    for (let i = 0; i < 200; i++) { await sleep(50); const m = await ev("document.querySelector('form[data-sign=approve] .sign-msg').textContent"); if (m && m !== "signing…") return m; }
  };
  check("a wrong passphrase is refused in the browser", (await wrongPin()) === "wrong passphrase");
  await set("form[data-sign=approve] input.pin", PASS);
  await submitAndWait("document.querySelector('form[data-sign=approve] button[type=submit]').click()");
  check("approved in the UI", (await flash()).startsWith("Approved."), await flash());
  const after = await ev("JSON.parse(localStorage.getItem('xbt-wallet-human-key-v1')).iter");
  check("the 60k wrap migrated to 210000 on unlock", after === 210000, String(after));
  // 4. a policy change, signed in the page
  await go("/policy?template=starter");
  await shot("04-policy", 1100);
  await set("[name=f_allowlist]", "http://127.0.0.1:33210");
  await set("[name=f_per_counterparty_cap_sats]", "9400"); // the test provider's channels hold at most 10,000
  await submitAndWait("document.querySelector('form.policy').submit()");
  check("the review shows the text to sign", await ev("!!document.querySelector('pre.signed-text')"));
  await shot("05-policy-review", 1100);
  await set("form[data-sign=policy] input.pin", PASS);
  await submitAndWait("document.querySelector('form[data-sign=policy] button[type=submit]').click()");
  check("the signed policy is applied", (await flash()).startsWith("Policy applied"), await flash());
  check("unlock after migration still works", (await ev("JSON.parse(localStorage.getItem('xbt-wallet-human-key-v1')).iter")) === 210000);
  // 5. a tampered review is refused before signing
  await go("/policy");
  await submitAndWait("document.querySelector('form.policy').submit()");
  await ev("document.querySelector('pre.signed-text').textContent += ' '");
  await set("form[data-sign=policy] input.pin", PASS);
  await ev("document.querySelector('form[data-sign=policy] button[type=submit]').click()");
  await sleep(300);
  check("text shown != text signed is refused", (await ev("document.querySelector('form[data-sign=policy] .sign-msg').textContent")).includes("refused"));
  // 6. every page renders, with no script errors, on a desktop and a phone
  for (const [p, name] of [["/", "06-overview"], ["/channels", "07-channels"], ["/signatures", "08-signatures"], ["/keys", "09-keys"], ["/hub", "10-hub"], ["/setup", "11-setup"]]) {
    await go(p);
    await shot(name, 1100);
    await shot(name + "-phone", 390);
    const overflow = await ev("document.documentElement.scrollWidth > window.innerWidth + 1");
    check(`${p} renders`, (await ev("document.querySelector('h1').textContent")).length > 0);
    check(`${p} has no horizontal page scroll on a phone`, !overflow);
  }
  for (const e of events) if (e.method === "Runtime.exceptionThrown" || (e.method === "Log.entryAdded" && e.params.entry.level === "error")) consoleErrors.push(JSON.stringify(e.params).slice(0, 300));
  check("no script errors or CSP violations", consoleErrors.length === 0, consoleErrors.join("\n"));
  writeFileSync(join(OUT, "browser_result.json"), JSON.stringify({ pub, results }, null, 2));
} catch (e) {
  check("browser run", false, e.stack);
} finally {
  ws.close(); chrome.kill("SIGKILL"); await sleep(200);
  try { rmSync(profile, { recursive: true, force: true }); } catch (e) { /* ignore */ }
}
const failed = results.filter((r) => !r.ok).length;
console.log(`browser_test: ${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
