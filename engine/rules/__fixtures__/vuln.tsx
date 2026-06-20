import * as cp from 'child_process';
import * as crypto from 'crypto';
function a(input: string){ return eval(input); }
const f = new Function('x','return x');
function b(name: string){ return cp.exec(`ls ${name}`); }
function b2(name: string){ return cp.execSync('ls ' + name); }
function q1(db: any, id: string){ return db.query(`SELECT * FROM u WHERE id=${id}`); }
function q2(db: any, id: string){ return db.query('SELECT * FROM u WHERE id=' + id); }
function n1(col: any, code: string){ return col.find({ $where: code }); }
function deser(s: string){ return (require('node-serialize') as any).unserialize(s); }
function x1(el: any, v: string){ el.innerHTML = v; }
function x2(v: string){ document.write(v); }
function x3(el: any, v: string){ el.insertAdjacentHTML('beforeend', v); }
function h1(s: string){ return crypto.createHash('md5').update(s).digest('hex'); }
function h2(s: string){ return crypto.createHash("sha1").update(s).digest('hex'); }
const opts = { rejectUnauthorized: false };
function tok(){ return Math.random().toString(36); }
export const C = ({html}: {html: string}) => <div dangerouslySetInnerHTML={{__html: html}} />;
function t2(){ setTimeout("x()", 1); }
function t3(){ process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; }
function ssrf(base, p){ return fetch(base + p); }
function ssrf2(base, p){ return axios.get(base + p); }
import * as fs from 'fs';
function pt(dir, name){ return fs.readFileSync(dir + name); }
