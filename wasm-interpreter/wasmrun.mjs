import { readFileSync } from 'fs';

// usage: node wasmrun.mjs module.wasm request.json
// request.json: {"calls": [{"name": "main", "args": [["i32", 5], ["i64", "123"]]}]}
// prints: {"results": [{"ok": true, "value": ...} | {"ok": false, "trap": bool}], "logged": [...]}
const wasmPath = process.argv[2];
const reqPath = process.argv[3];
const buf = readFileSync(wasmPath);
const req = JSON.parse(readFileSync(reqPath, 'utf8'));

const logged = [];
const importObject = { env: { log: (x) => { logged.push(Number(x)); } } };

let instance;
try {
  const mod = new WebAssembly.Module(buf);
  instance = new WebAssembly.Instance(mod, importObject);
} catch (e) {
  console.log(JSON.stringify({ link_error: String(e && e.message || e) }));
  process.exit(0);
}

const out = [];
for (const c of req.calls) {
  const fn = instance.exports[c.name];
  if (typeof fn !== 'function') {
    out.push({ ok: false, trap: false, missing: true });
    continue;
  }
  try {
    const args = (c.args || []).map(a => a[0] === 'i64' ? BigInt(a[1]) : a[1]);
    let r = fn(...args);
    if (typeof r === 'bigint') r = { i64: r.toString() };
    out.push({ ok: true, value: r === undefined ? null : r });
  } catch (e) {
    out.push({ ok: false, trap: e instanceof WebAssembly.RuntimeError });
  }
}
console.log(JSON.stringify({ results: out, logged }));
