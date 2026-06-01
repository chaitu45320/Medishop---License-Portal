/**
 * models/db.js — PostgreSQL persistent storage
 * Tables: license_keys | activations | validation_log
 */
const { Client } = require('pg');
const fs   = require('fs');
const path = require('path');

// Fallback JSON file if no PostgreSQL
const DATA_DIR = path.join(__dirname, '..', 'data');
const JSON_PATH = path.join(DATA_DIR, 'licenses.json');

let pgClient = null;
let useJSON  = false;
let jsonDB   = { license_keys: [], activations: [], validation_log: [] };

async function init() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

  const url = process.env.DATABASE_URL;
  if (!url) {
    console.log('[DB] No DATABASE_URL — using JSON file (data lost on restart!)');
    useJSON = true;
    loadJSON();
    return;
  }

  try {
    pgClient = new Client({ connectionString: url, ssl: { rejectUnauthorized: false } });
    await pgClient.connect();
    await pgClient.query(`
      CREATE TABLE IF NOT EXISTS license_keys (
        id          SERIAL PRIMARY KEY,
        key_hash    TEXT UNIQUE NOT NULL,
        key_display TEXT NOT NULL,
        type        TEXT NOT NULL CHECK(type IN ('full','trial')),
        email       TEXT NOT NULL,
        max_devices INTEGER NOT NULL DEFAULT 1,
        is_active   INTEGER NOT NULL DEFAULT 1,
        issued_at   BIGINT NOT NULL,
        notes       TEXT DEFAULT '',
        trial_days  INTEGER
      )
    `);
    await pgClient.query(`
      CREATE TABLE IF NOT EXISTS activations (
        id           SERIAL PRIMARY KEY,
        key_hash     TEXT NOT NULL,
        device_id    TEXT NOT NULL,
        device_name  TEXT,
        device_fp    TEXT,
        app_version  TEXT,
        activated_at BIGINT NOT NULL,
        last_seen    BIGINT,
        is_revoked   INTEGER NOT NULL DEFAULT 0,
        token_hash   TEXT,
        UNIQUE(key_hash, device_id)
      )
    `);
    await pgClient.query(`
      CREATE TABLE IF NOT EXISTS validation_log (
        id        SERIAL PRIMARY KEY,
        key_hash  TEXT NOT NULL,
        device_id TEXT DEFAULT '',
        ip        TEXT DEFAULT '',
        action    TEXT NOT NULL,
        result    TEXT NOT NULL,
        detail    TEXT DEFAULT '',
        ts        BIGINT NOT NULL
      )
    `);
    console.log('[DB] PostgreSQL connected — PERSISTENT storage active');
  } catch(e) {
    console.error('[DB] PostgreSQL failed:', e.message, '— falling back to JSON');
    pgClient = null;
    useJSON = true;
    loadJSON();
  }
}

// ── JSON fallback ─────────────────────────────────────────────
function loadJSON() {
  try { jsonDB = JSON.parse(fs.readFileSync(JSON_PATH, 'utf8')); }
  catch(e) { jsonDB = { license_keys: [], activations: [], validation_log: [] }; }
}
function saveJSON() {
  try { fs.writeFileSync(JSON_PATH, JSON.stringify(jsonDB, null, 2)); }
  catch(e) { console.error('[DB] JSON save error:', e.message); }
}

// ── Universal query functions ─────────────────────────────────
async function run(sql, params = []) {
  if (pgClient) {
    await pgClient.query(sql, params);
    return;
  }
  // JSON fallback: parse simple INSERT/UPDATE/DELETE
  _jsonExec(sql, params);
  saveJSON();
}

async function get(sql, params = []) {
  if (pgClient) {
    const r = await pgClient.query(sql, params);
    return r.rows[0] || null;
  }
  return _jsonQuery(sql, params)[0] || null;
}

async function all(sql, params = []) {
  if (pgClient) {
    const r = await pgClient.query(sql, params);
    return r.rows;
  }
  return _jsonQuery(sql, params);
}

async function log(keyHash, deviceId, ip, action, result, detail = '') {
  await run(
    'INSERT INTO validation_log (key_hash,device_id,ip,action,result,detail,ts) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [keyHash||'', deviceId||'', ip||'', action, result, detail, Date.now()]
  );
}

// Simple JSON DB helpers (for fallback only)
function _jsonQuery(sql, params) {
  const s = sql.toLowerCase();
  if (s.includes('from license_keys')) {
    let rows = [...jsonDB.license_keys];
    if (s.includes('where key_hash')) rows = rows.filter(r => r.key_hash === params[0]);
    if (s.includes("where type='full'") || s.includes('where type = $1')) rows = rows.filter(r => r.type === (params[0]||'full'));
    if (s.includes('where is_active=1') || s.includes('where is_active = 1')) rows = rows.filter(r => r.is_active === 1);
    if (s.includes('order by issued_at desc')) rows.sort((a,b) => b.issued_at - a.issued_at);
    if (s.includes('limit')) rows = rows.slice(0, parseInt(s.match(/limit\s+(\d+)/)?.[1]||100));
    if (s.includes('count(*)')) return [{ n: rows.length }];
    return rows;
  }
  if (s.includes('from activations')) {
    let rows = [...jsonDB.activations];
    if (s.includes('where key_hash') && s.includes('device_id')) rows = rows.filter(r => r.key_hash === params[0] && r.device_id === params[1]);
    else if (s.includes('where key_hash')) rows = rows.filter(r => r.key_hash === params[0]);
    if (s.includes('is_revoked = 0') || s.includes('is_revoked=0')) rows = rows.filter(r => !r.is_revoked);
    if (s.includes('count(*)')) return [{ n: rows.length }];
    return rows;
  }
  if (s.includes('from validation_log')) {
    let rows = [...jsonDB.validation_log];
    if (s.includes('where key_hash')) rows = rows.filter(r => r.key_hash === params[0]);
    if (s.includes("where action =") || s.includes("where action='")) rows = rows.filter(r => r.action === params[0]);
    if (s.includes("result like 'fail%'") || s.includes("result like $")) rows = rows.filter(r => r.result.startsWith('fail'));
    rows.sort((a,b) => b.ts - a.ts);
    if (s.includes('limit')) rows = rows.slice(0, parseInt(s.match(/limit\s+\$?\d+/)?.[0]?.match(/\d+$/)?.[0]||100));
    return rows;
  }
  return [];
}

function _jsonExec(sql, params) {
  const s = sql.toLowerCase();
  if (s.includes('insert into license_keys')) {
    // remove existing with same hash first
    jsonDB.license_keys = jsonDB.license_keys.filter(r => r.key_hash !== params[0]);
    jsonDB.license_keys.push({ id: Date.now(), key_hash: params[0], key_display: params[1], type: params[2], email: params[3], max_devices: params[4], is_active: 1, issued_at: params[5], notes: params[6]||'', trial_days: params[7]||null });
  } else if (s.includes('update license_keys set is_active = 0')) {
    jsonDB.license_keys = jsonDB.license_keys.map(r => r.key_hash === params[0] ? {...r, is_active: 0} : r);
  } else if (s.includes('update license_keys set is_active = 1')) {
    jsonDB.license_keys = jsonDB.license_keys.map(r => r.key_hash === params[0] ? {...r, is_active: 1} : r);
  } else if (s.includes('insert into activations')) {
    jsonDB.activations = jsonDB.activations.filter(r => !(r.key_hash === params[0] && r.device_id === params[1]));
    jsonDB.activations.push({ id: Date.now(), key_hash: params[0], device_id: params[1], device_name: params[2], device_fp: params[3], app_version: params[4], activated_at: params[5], last_seen: params[6], is_revoked: 0, token_hash: params[7] });
  } else if (s.includes('update activations set last_seen')) {
    jsonDB.activations = jsonDB.activations.map(r => r.key_hash === params[2] && r.device_id === params[3] ? {...r, last_seen: params[0], token_hash: params[1]} : r);
  } else if (s.includes('update activations set is_revoked = 1')) {
    jsonDB.activations = jsonDB.activations.map(r => r.key_hash === params[0] && r.device_id === params[1] ? {...r, is_revoked: 1} : r);
  } else if (s.includes('delete from activations where key_hash') && s.includes('device_id')) {
    jsonDB.activations = jsonDB.activations.filter(r => !(r.key_hash === params[0] && r.device_id === params[1]));
  } else if (s.includes('delete from activations where key_hash')) {
    jsonDB.activations = jsonDB.activations.filter(r => r.key_hash !== params[0]);
  } else if (s.includes('insert into validation_log')) {
    jsonDB.validation_log.unshift({ id: Date.now(), key_hash: params[0], device_id: params[1], ip: params[2], action: params[3], result: params[4], detail: params[5], ts: params[6] });
    if (jsonDB.validation_log.length > 2000) jsonDB.validation_log = jsonDB.validation_log.slice(0, 2000);
  }
}

function save() { if (useJSON) saveJSON(); }

module.exports = { init, run, get, all, log, save };
