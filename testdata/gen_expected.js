// 用 Node.js 计算 cap.js 的权威期望值，供 Go 测试对比
// 用法（在项目根目录执行）：node testdata/gen_expected.js
// 会从 testdata/challenge.json 解压出 testdata/instr.js 并生成 testdata/expected.json
const fs = require('fs');
const zlib = require('zlib');

// ---- 复刻 cap widget 的确定性字符串生成函数 d(seed, length) ----
function d(e, t) {
  let i = (function (e) {
    let t = 2166136261;
    for (let i = 0; i < e.length; i++) t ^= e.charCodeAt(i), t += (t << 1) + (t << 4) + (t << 7) + (t << 8) + (t << 24);
    return t >>> 0;
  })(e), s = "";
  function r() { return i ^= i << 13, i ^= i >>> 17, i ^= i << 5, i >>> 0 }
  for (; s.length < t;) s += r().toString(16).padStart(8, "0");
  return s.substring(0, t);
}

// ---- 求解 PoW（与 worker 中 JS fallback 相同的语义）----
async function solve(salt, target) {
  const enc = new TextEncoder();
  const bits = 4 * target.length, full = Math.floor(bits / 8), rem = bits % 8;
  const hex = target.length % 2 === 0 ? target : target + "0";
  const tb = new Uint8Array(hex.length / 2);
  for (let i = 0; i < tb.length; i++) tb[i] = parseInt(hex.substring(2 * i, 2 * i + 2), 16);
  const mask = rem > 0 ? (255 << (8 - rem)) & 255 : 0;
  for (let nonce = 0; ; nonce++) {
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(salt + nonce)));
    let ok = true;
    for (let i = 0; i < full; i++) if (h[i] !== tb[i]) { ok = false; break }
    if (ok && rem > 0 && (h[full] & mask) !== (tb[full] & mask)) ok = false;
    if (ok) return nonce;
  }
}

// ---- 模拟 gm75n 使用的 DOM ----
class El {
  constructor(parent) { this.parentNode = parent; this.children = []; this._t = ""; }
  appendChild(c) { c.parentNode = this; this.children.push(c); }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); }
  get innerText() { return this._t; }
  set innerText(v) { this._t = String(v); }
}
const documentMock = {
  body: new El(null),
  createElement() { return new El(null); },
};

function gm(x, y, z) {
  const dEl = documentMock.createElement('div');
  dEl.style = {};
  documentMock.body.appendChild(dEl);
  function A(p, v) {
    for (let i = 0; i < 8; i++) {
      const c = documentMock.createElement('div');
      p.appendChild(c);
      c.innerText = v;
      if ((v & 1) === 0) p = c;
      v = v >> 1;
    }
    return p;
  }
  function B(n, r, s) {
    if (!n || n === r) return s % 256;
    while (n.children.length > 0) n.removeChild(n.children[n.children.length - 1]);
    return B(n.parentNode, r, s + parseInt(n.innerText));
  }
  const s = B(A(A(A(dEl, x), y), z), dEl, 0);
  dEl.parentNode.removeChild(dEl);
  return s;
}
function cs(a, b, c) {
  function F(dd) { this.v = function () { return this.k ^ dd; }; }
  const p = { k: c };
  const i = new F(a);
  i.k = b;
  F.prototype = p;
  return i.v() | (new F(b)).v();
}

// ---- 计算 instr 脚本的 state ----
function evalState(js) {
  const m = /var (\w+)=(\d+);var (\w+)=(\d+);var (\w+)=(\d+);var (\w+)=(\d+);/.exec(js);
  const names = [m[1], m[3], m[5], m[7]];
  const vals = [m[2], m[4], m[6], m[8]].map(Number);
  const csName = /function (\w+)\(a,b,c\)\{function F\(d\)\{this\.v=function\(\)\{return this\.k\^d;/.exec(js)[1];
  const gmName = /function (\w+)\(x,y,z\)\{var d=document\.createElement\('div'\)/.exec(js)[1];
  const start = js.search(new RegExp(`\\b${names[0]}\\s*=\\s*${names[0]}\\s*\\^`));
  const endRe = new RegExp(`${names[3]}\\s*=\\s*\\(\\(\\s*${names[3]}\\s*\\^\\s*\\d+\\s*\\)\\s*&\\s*0x7FFFFFFF\\)`);
  const em = endRe.exec(js);
  const end = js.indexOf(';', em.index + em[0].length) + 1;
  const block = js.slice(start, end);
  const body = `var ${names[0]}=${vals[0]},${names[1]}=${vals[1]},${names[2]}=${vals[2]},${names[3]}=${vals[3]};` +
    block + `return {${names[0]},${names[1]},${names[2]},${names[3]}};`;
  const fn = new Function(gmName, csName, 'navigator', body);
  return fn(gm, cs, { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0' });
}

(async () => {
  const ch = JSON.parse(fs.readFileSync('testdata/challenge.json', 'utf8'));
  const token = ch.token;
  const c = ch.challenge.c, s = ch.challenge.s, diff = ch.challenge.d;

  const salts = [], targets = [], nonces = [];
  for (let i = 1; i <= 3; i++) {
    const salt = d(`${token}${i}`, s), target = d(`${token}${i}d`, diff);
    salts.push(salt); targets.push(target); nonces.push(await solve(salt, target));
  }

  const js = zlib.inflateRawSync(Buffer.from(ch.instrumentation, 'base64')).toString('utf8');
  fs.writeFileSync('testdata/instr.js', js);
  const state = evalState(js);

  const out = {
    token,
    challenge: ch.challenge,
    salts, targets, nonces,
    nonce_instr: /nonce:\s*"([0-9a-fA-F]+)"/.exec(js)[1],
    state,
    gen_samples: [d('abc', 8), d('abc', 32), d(token + '1', 16), d(token + '1d', 6)],
  };
  fs.writeFileSync('testdata/expected.json', JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
})();
