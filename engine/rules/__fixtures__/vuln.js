const cp = require('child_process');
const crypto = require('crypto');
function a(req){ return eval(req.query.code); }
const f = new Function('a','b','return a+b');
setTimeout("doStuff()", 100);
function b(name){ return cp.exec(`ls ${name}`); }
function b2(name){ return cp.execSync('ls ' + name); }
function q1(db, id){ return db.query(`SELECT * FROM u WHERE id=${id}`); }
function q2(db, id){ return db.query('SELECT * FROM u WHERE id=' + id); }
function n1(col, code){ return col.find({ $where: code }); }
function deser(s){ return require('node-serialize').unserialize(s); }
function x1(el, v){ el.innerHTML = v; }
function x2(v){ document.write(v); }
function x3(el, v){ el.insertAdjacentHTML('beforeend', v); }
function h1(s){ return crypto.createHash('md5').update(s).digest('hex'); }
function h2(s){ return crypto.createHash("sha1").update(s).digest('hex'); }
const opts = { rejectUnauthorized: false };
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
function tok(){ return Math.random().toString(36); }
function ssrf(base, p){ return fetch(base + p); }
function ssrf2(base, p){ return axios.get(base + p); }
import * as fs from 'fs';
function pt(dir, name){ return fs.readFileSync(dir + name); }
