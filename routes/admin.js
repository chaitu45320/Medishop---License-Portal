/**
 * routes/admin.js — MediShop Admin API
 */
const express = require('express');
const router  = express.Router();
const db      = require('../models/db');
const { generateKey, validateKey, hashKey, getDaysLeft, isTrialExpired } = require('../utils/license');

const MAX_DEVICES = parseInt(process.env.MAX_DEVICES || '1');
const API_SECRET  = process.env.API_SECRET || 'MediShopAdmin2024';

router.use((req, res, next) => {
  const auth = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (auth === API_SECRET) { next(); return; }
  return res.status(401).json({ success: false, error: 'Unauthorized' });
});

// ── POST /admin/keys/generate ─────────────────────────────────
router.post('/keys/generate', async (req, res) => {
  const { email, type, maxDevices, notes, trialDays } = req.body;
  if (!email || !type) return res.status(400).json({ success: false, error: 'email and type required' });
  if (!['full','trial'].includes(type)) return res.status(400).json({ success: false, error: 'type must be full or trial' });
  const key     = generateKey(type);
  const keyHash = hashKey(key);
  const max     = parseInt(maxDevices) || MAX_DEVICES;
  const tDays   = type === 'trial' ? (parseInt(trialDays) || parseInt(process.env.TRIAL_DAYS || '7')) : null;
  await db.run(
    'INSERT INTO license_keys (key_hash,key_display,type,email,max_devices,is_active,issued_at,notes,trial_days) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8)',
    [keyHash, key, type, email.trim().toLowerCase(), max, Date.now(), notes||'', tDays]
  );
  console.log('[KEY GENERATED]', key, '|', type, '|', email);
  return res.json({ success: true, key, type, email: email.trim().toLowerCase(), maxDevices: max, trialDays: tDays });
});

// ── POST /admin/keys/import ───────────────────────────────────
router.post('/keys/import', async (req, res) => {
  const { licenseKey, email, type, maxDevices, notes } = req.body;
  if (!licenseKey || !email || !type) return res.status(400).json({ success: false, error: 'licenseKey, email, type required' });
  const key = licenseKey.trim().toUpperCase(), v = validateKey(key);
  if (!v.ok && !v.valid) return res.status(400).json({ success: false, error: 'Invalid key: ' + (v.reason||'format error') });
  const keyHash = hashKey(key);
  const existing = await db.get('SELECT id FROM license_keys WHERE key_hash=$1', [keyHash]);
  if (existing) return res.status(409).json({ success: false, error: 'Key already registered.' });
  const max   = parseInt(maxDevices) || MAX_DEVICES;
  const tDays = type === 'trial' ? parseInt(process.env.TRIAL_DAYS||'7') : null;
  await db.run(
    'INSERT INTO license_keys (key_hash,key_display,type,email,max_devices,is_active,issued_at,notes,trial_days) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8)',
    [keyHash, key, type, email.trim().toLowerCase(), max, Date.now(), notes||'', tDays]
  );
  return res.json({ success: true, key, type, email: email.trim().toLowerCase(), message: 'Key registered. Customer can now activate.' });
});

// ── GET /admin/keys ───────────────────────────────────────────
router.get('/keys', async (req, res) => {
  const keys = await db.all(`
    SELECT k.*,
      (SELECT COUNT(*) FROM activations a WHERE a.key_hash=k.key_hash AND a.is_revoked=0) as active_devices,
      (SELECT COUNT(*) FROM validation_log l WHERE l.key_hash=k.key_hash AND l.result LIKE 'fail%') as fail_count
    FROM license_keys k ORDER BY k.issued_at DESC`);
  return res.json({ success: true, keys: keys.map(k => ({ ...k, daysLeft: getDaysLeft(k.issued_at, k.type, k.trial_days), isExpired: k.type==='trial' && isTrialExpired(k.issued_at, k.trial_days), is_active: !!k.is_active })), total: keys.length });
});

// ── GET /admin/keys/:hash ─────────────────────────────────────
router.get('/keys/:hash', async (req, res) => {
  const key = await db.get('SELECT * FROM license_keys WHERE key_hash=$1', [req.params.hash]);
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });
  const devices = await db.all('SELECT * FROM activations WHERE key_hash=$1 ORDER BY activated_at DESC', [req.params.hash]);
  const logs    = await db.all('SELECT * FROM validation_log WHERE key_hash=$1 ORDER BY ts DESC LIMIT 50', [req.params.hash]);
  return res.json({ success: true, key: { ...key, daysLeft: getDaysLeft(key.issued_at, key.type, key.trial_days), isExpired: key.type==='trial' && isTrialExpired(key.issued_at, key.trial_days) }, devices, logs });
});

// ── POST /admin/keys/:hash/revoke ─────────────────────────────
router.post('/keys/:hash/revoke', async (req, res) => {
  const key = await db.get('SELECT * FROM license_keys WHERE key_hash=$1', [req.params.hash]);
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });
  await db.run('UPDATE license_keys SET is_active=0 WHERE key_hash=$1', [req.params.hash]);
  await db.log(req.params.hash, '', req.ip||'', 'admin_revoke', 'ok', 'Admin revoked');
  return res.json({ success: true, message: 'License revoked.' });
});

// ── POST /admin/keys/:hash/restore ────────────────────────────
router.post('/keys/:hash/restore', async (req, res) => {
  const key = await db.get('SELECT * FROM license_keys WHERE key_hash=$1', [req.params.hash]);
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });
  await db.run('UPDATE license_keys SET is_active=1 WHERE key_hash=$1', [req.params.hash]);
  await db.log(req.params.hash, '', req.ip||'', 'admin_restore', 'ok', 'Admin restored');
  return res.json({ success: true, message: 'License restored.' });
});

// ── POST /admin/devices/:hash/:did/revoke ─────────────────────
router.post('/devices/:hash/:did/revoke', async (req, res) => {
  await db.run('UPDATE activations SET is_revoked=1 WHERE key_hash=$1 AND device_id=$2', [req.params.hash, req.params.did]);
  await db.log(req.params.hash, req.params.did, req.ip||'', 'admin_device_revoke', 'ok', '');
  return res.json({ success: true, message: 'Device revoked.' });
});

// ── POST /admin/devices/:hash/:did/transfer ───────────────────
router.post('/devices/:hash/:did/transfer', async (req, res) => {
  await db.run('DELETE FROM activations WHERE key_hash=$1 AND device_id=$2', [req.params.hash, req.params.did]);
  await db.log(req.params.hash, req.params.did, req.ip||'', 'admin_transfer', 'ok', 'Slot freed');
  return res.json({ success: true, message: 'Device slot freed.' });
});

// ── POST /admin/devices/:hash/transfer-all ────────────────────
router.post('/devices/:hash/transfer-all', async (req, res) => {
  await db.run('DELETE FROM activations WHERE key_hash=$1', [req.params.hash]);
  await db.log(req.params.hash, '', req.ip||'', 'admin_transfer_all', 'ok', 'All slots freed');
  return res.json({ success: true, message: 'All devices removed. Ready for fresh activation.' });
});

// ── POST /admin/verify ───────────────────────────────────────
router.post('/verify', async (req, res) => {
  const key = (req.body.licenseKey || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ success: false, error: 'licenseKey required' });
  const v = validateKey(key);
  if (!v.valid) return res.status(400).json({ success: false, error: 'Invalid key format: ' + v.reason });
  const keyHash   = hashKey(key);
  const keyRecord = await db.get('SELECT * FROM license_keys WHERE key_hash=$1', [keyHash]);
  if (!keyRecord) return res.status(404).json({ success: false, error: 'Key not found. Generate it first via admin dashboard.' });
  const devices   = await db.all('SELECT * FROM activations WHERE key_hash=$1 ORDER BY activated_at DESC', [keyHash]);
  const daysLeft  = getDaysLeft(keyRecord.issued_at, keyRecord.type, keyRecord.trial_days);
  const isExpired = keyRecord.type === 'trial' && isTrialExpired(keyRecord.issued_at, keyRecord.trial_days);
  return res.json({ success: true, type: keyRecord.type, email: keyRecord.email, daysLeft, isExpired, isActive: !!keyRecord.is_active, deviceCount: devices.filter(d=>!d.is_revoked).length, maxDevices: keyRecord.max_devices, keyHash,
    devices: devices.map(d => ({ deviceId: d.device_id, deviceName: d.device_name, activatedAt: d.activated_at, lastSeen: d.last_seen, isRevoked: !!d.is_revoked })) });
});

// ── GET /admin/suspicious ─────────────────────────────────────
router.get('/suspicious', async (req, res) => {
  const suspicious = await db.all(`
    SELECT l.key_hash, k.key_display, k.email, k.type,
           COUNT(*) as fail_count, MAX(l.ts) as last_attempt
    FROM validation_log l
    LEFT JOIN license_keys k ON k.key_hash = l.key_hash
    WHERE l.result LIKE 'fail%'
    GROUP BY l.key_hash, k.key_display, k.email, k.type
    HAVING COUNT(*) >= 3
    ORDER BY fail_count DESC`);
  return res.json({ success: true, suspicious, count: suspicious.length });
});

// ── GET /admin/dashboard ──────────────────────────────────────
router.get('/dashboard', async (req, res) => {
  const totalKeys    = (await db.get('SELECT COUNT(*) as n FROM license_keys'))?.n || 0;
  const fullKeys     = (await db.get("SELECT COUNT(*) as n FROM license_keys WHERE type='full'"))?.n || 0;
  const trialKeys    = (await db.get("SELECT COUNT(*) as n FROM license_keys WHERE type='trial'"))?.n || 0;
  const activeKeys   = (await db.get('SELECT COUNT(*) as n FROM license_keys WHERE is_active=1'))?.n || 0;
  const totalDevices = (await db.get('SELECT COUNT(*) as n FROM activations WHERE is_revoked=0'))?.n || 0;
  const todayActs    = await db.all('SELECT * FROM validation_log WHERE action=$1 AND result=$2 AND ts>$3 ORDER BY ts DESC', ['activate','ok', Date.now()-86400000]);
  const recentKeys   = await db.all('SELECT * FROM license_keys ORDER BY issued_at DESC LIMIT 10');
  return res.json({ success: true,
    stats: { totalKeys, fullKeys, trialKeys, activeKeys, totalDevices },
    todayActivations: todayActs.length,
    recentKeys: recentKeys.map(k => ({ ...k, daysLeft: getDaysLeft(k.issued_at, k.type, k.trial_days) })) });
});

// ── GET /admin/logs ───────────────────────────────────────────
router.get('/logs', async (req, res) => {
  const limit  = parseInt(req.query.limit) || 200;
  const filter = req.query.action || '';
  const logs   = filter
    ? await db.all('SELECT * FROM validation_log WHERE action=$1 ORDER BY ts DESC LIMIT $2', [filter, limit])
    : await db.all('SELECT * FROM validation_log ORDER BY ts DESC LIMIT $1', [limit]);
  return res.json({ success: true, logs, count: logs.length });
});

// ── GET /admin/export ─────────────────────────────────────────
router.get('/export', async (req, res) => {
  const keys        = await db.all('SELECT * FROM license_keys ORDER BY issued_at DESC');
  const activations = await db.all('SELECT * FROM activations ORDER BY activated_at DESC');
  const logs        = await db.all('SELECT * FROM validation_log ORDER BY ts DESC LIMIT 1000');
  res.setHeader('Content-Disposition', 'attachment; filename="medishop-licenses-' + Date.now() + '.json"');
  res.setHeader('Content-Type', 'application/json');
  return res.send(JSON.stringify({ exportedAt: new Date().toISOString(), application: 'MediShop License Server v3.0', keys, activations, logs }, null, 2));
});

module.exports = router;
