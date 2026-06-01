/**
 * routes/license.js — MediShop
 * POST /api/activate
 * POST /api/validate
 * POST /api/deactivate
 */
const express = require('express');
const router  = express.Router();
const db      = require('../models/db');
const { validateKey, hashKey, hashToken, signToken, verifyToken, getDaysLeft, isTrialExpired } = require('../utils/license');

router.post('/activate', async (req, res) => {
  const { licenseKey, email, deviceId, deviceName, deviceFp, appVersion } = req.body;
  const ip = req.ip || '';

  if (!licenseKey) return res.status(400).json({ success: false, error: 'License key is required' });
  if (!email)      return res.status(400).json({ success: false, error: 'Email is required' });
  if (!deviceId)   return res.status(400).json({ success: false, error: 'Device ID is required' });

  const key = licenseKey.trim().toUpperCase();
  const v   = validateKey(key);
  if (!v.valid) {
    await db.log('', deviceId, ip, 'activate', 'fail', 'Invalid key: ' + v.reason);
    return res.status(400).json({ success: false, error: 'Invalid license key: ' + v.reason });
  }

  const keyHash = hashKey(key);
  const emailLc = email.trim().toLowerCase();
  const keyRecord = await db.get('SELECT * FROM license_keys WHERE key_hash = $1', [keyHash]);

  if (!keyRecord) {
    await db.log(keyHash, deviceId, ip, 'activate', 'fail_notfound', 'Key not found');
    return res.status(404).json({ success: false, error: 'License key not found. Contact Cloud Sprint: 9985223448' });
  }
  if (!keyRecord.is_active) {
    await db.log(keyHash, deviceId, ip, 'activate', 'fail_revoked', 'Key revoked');
    return res.status(403).json({ success: false, error: 'This license has been revoked. Contact Cloud Sprint.' });
  }
  if (keyRecord.email !== emailLc) {
    await db.log(keyHash, deviceId, ip, 'activate', 'fail_email', 'Email mismatch');
    return res.status(403).json({ success: false, error: 'This key is registered to a different email address.' });
  }
  if (keyRecord.type === 'trial' && isTrialExpired(keyRecord.issued_at, keyRecord.trial_days)) {
    await db.log(keyHash, deviceId, ip, 'activate', 'fail_expired', 'Trial expired');
    return res.status(403).json({ success: false, error: 'Trial license has expired. Contact Cloud Sprint: 9985223448' });
  }

  const existing = await db.get('SELECT * FROM activations WHERE key_hash = $1 AND device_id = $2', [keyHash, deviceId]);
  if (existing) {
    if (existing.is_revoked) {
      await db.log(keyHash, deviceId, ip, 'activate', 'fail_device_revoked', 'Device revoked');
      return res.status(403).json({ success: false, error: 'This device has been revoked. Contact Cloud Sprint.' });
    }
    const token = signToken({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
    await db.run(
      'UPDATE activations SET last_seen=$1, token_hash=$2, device_name=$3, app_version=$4 WHERE key_hash=$5 AND device_id=$6',
      [Date.now(), hashToken(token), deviceName||existing.device_name, appVersion||existing.app_version, keyHash, deviceId]
    );
    await db.log(keyHash, deviceId, ip, 'reactivate', 'ok', deviceName||'');
    return res.json({ success: true, type: keyRecord.type, email: emailLc, daysLeft: getDaysLeft(keyRecord.issued_at, keyRecord.type, keyRecord.trial_days), token, message: 'License verified' });
  }

  const activeDevices = await db.all('SELECT * FROM activations WHERE key_hash = $1 AND is_revoked = 0', [keyHash]);
  if (activeDevices.length >= keyRecord.max_devices) {
    const names = activeDevices.map(d => d.device_name || d.device_id).join(', ');
    await db.log(keyHash, deviceId, ip, 'activate', 'fail_limit', 'Devices: ' + names);
    return res.status(409).json({ success: false, error: 'License already active on ' + activeDevices.length + ' device(s): ' + names + '. Contact Cloud Sprint: 9985223448', code: 'DEVICE_LIMIT' });
  }

  const token = signToken({ keyHash, deviceId, type: keyRecord.type, email: emailLc });
  await db.run(
    'INSERT INTO activations (key_hash,device_id,device_name,device_fp,app_version,activated_at,last_seen,token_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [keyHash, deviceId, deviceName||'Unknown Device', deviceFp||'', appVersion||'1.0.0', Date.now(), Date.now(), hashToken(token)]
  );
  await db.log(keyHash, deviceId, ip, 'activate', 'ok', deviceName||'');
  const daysLeft = getDaysLeft(keyRecord.issued_at, keyRecord.type, keyRecord.trial_days);
  console.log('[ACTIVATED]', key, '|', emailLc, '|', deviceName, '|', ip);
  return res.json({ success: true, type: keyRecord.type, email: emailLc, daysLeft, token,
    message: keyRecord.type === 'full' ? 'Full license activated!' : 'Trial: ' + daysLeft + ' day(s) remaining.' });
});

router.post('/validate', async (req, res) => {
  const { token, deviceId } = req.body;
  const ip = req.ip || '';
  if (!token || !deviceId) return res.status(400).json({ success: false, error: 'token and deviceId required' });
  const payload = verifyToken(token);
  if (!payload || payload.deviceId !== deviceId) {
    await db.log('', deviceId, ip, 'validate', 'fail', 'Invalid JWT');
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
  const { keyHash } = payload;
  const activation = await db.get('SELECT * FROM activations WHERE key_hash = $1 AND device_id = $2', [keyHash, deviceId]);
  if (!activation || activation.is_revoked) {
    await db.log(keyHash, deviceId, ip, 'validate', 'fail', 'Not activated or revoked');
    return res.status(401).json({ success: false, error: 'Device not authorized' });
  }
  const keyRecord = await db.get('SELECT * FROM license_keys WHERE key_hash = $1', [keyHash]);
  if (!keyRecord || !keyRecord.is_active) {
    await db.log(keyHash, deviceId, ip, 'validate', 'fail', 'Key inactive');
    return res.status(403).json({ success: false, error: 'License deactivated' });
  }
  if (keyRecord.type === 'trial' && isTrialExpired(keyRecord.issued_at, keyRecord.trial_days)) {
    await db.log(keyHash, deviceId, ip, 'validate', 'fail', 'Trial expired');
    return res.status(403).json({ success: false, error: 'Trial expired' });
  }
  await db.run('UPDATE activations SET last_seen=$1 WHERE key_hash=$2 AND device_id=$3', [Date.now(), keyHash, deviceId]);
  await db.log(keyHash, deviceId, ip, 'validate', 'ok', '');
  return res.json({ success: true, type: keyRecord.type, email: keyRecord.email, daysLeft: getDaysLeft(keyRecord.issued_at, keyRecord.type, keyRecord.trial_days), valid: true });
});

router.post('/deactivate', async (req, res) => {
  const { token, deviceId } = req.body;
  if (!token || !deviceId) return res.status(400).json({ success: false, error: 'token and deviceId required' });
  const payload = verifyToken(token);
  if (!payload || payload.deviceId !== deviceId) return res.status(401).json({ success: false, error: 'Invalid token' });
  await db.run('DELETE FROM activations WHERE key_hash=$1 AND device_id=$2', [payload.keyHash, deviceId]);
  await db.log(payload.keyHash, deviceId, req.ip||'', 'deactivate', 'ok', 'Self deactivated');
  return res.json({ success: true, message: 'Device deactivated.' });
});

module.exports = router;
