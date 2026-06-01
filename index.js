/**
 * MediShop License Server v3.0
 * Cloud Sprint | contact@cloudsprint.in
 * Run: node index.js
 */

require('dotenv').config();

const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');
const db        = require('./models/db');

const PORT           = process.env.PORT           || 10000;
const API_SECRET     = process.env.API_SECRET     || 'MediShopAdmin2024';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'MediShop';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'MediShop@2024';

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.set('trust proxy', 1);

app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/admin'))
    console.log('[' + new Date().toISOString() + '] ' + req.method + ' ' + req.path);
  next();
});

// Rate limiting
app.use('/api/activate',  rateLimit({ windowMs: 15*60*1000, max: 20, message: { success: false, error: 'Too many activation attempts. Wait 15 minutes.' } }));
app.use('/api/validate',  rateLimit({ windowMs: 60*60*1000, max: 200, message: { success: false, error: 'Validation rate limit exceeded.' } }));
app.use('/admin',         rateLimit({ windowMs: 60*60*1000, max: 200, message: { success: false, error: 'Admin rate limit exceeded.' } }));
app.use('/admin-login',   rateLimit({ windowMs: 15*60*1000, max: 10,  message: { success: false, error: 'Too many login attempts. Wait 15 minutes.' } }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

// Routes
app.use('/api',   require('./routes/license'));
app.use('/admin', require('./routes/admin'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Login endpoint
app.post('/admin-login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    console.log('[LOGIN] Success:', username, req.ip);
    return res.json({ success: true, token: API_SECRET });
  }
  console.log('[LOGIN FAILED] username="' + username + '" ip=' + req.ip);
  return res.status(401).json({ success: false, error: 'Invalid username or password' });
});

// Dashboard / Login page
app.get('/', (req, res) => {
  const token = (req.query.token || req.headers['authorization']?.replace('Bearer ', '') || '').trim();
  if (token === API_SECRET) {
    return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  }
  // Show login page
  res.status(200).send(`<!DOCTYPE html>
<html><head>
<title>💊 MediShop Admin Login</title>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#060d19;color:#e2eaf4;font-family:'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}
.card{background:#0a1628;border:1px solid #162035;border-radius:12px;padding:40px 36px;width:100%;max-width:380px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
.logo{text-align:center;font-size:50px;margin-bottom:10px}
h2{text-align:center;font-size:20px;font-weight:700;color:#00c9a7;margin-bottom:4px}
.sub{text-align:center;color:#4a6080;font-size:12px;margin-bottom:28px}
label{display:block;font-size:11px;font-weight:700;color:#4a6080;margin-bottom:5px;text-transform:uppercase;letter-spacing:.05em}
input{width:100%;padding:11px 14px;background:#0f1f35;border:1px solid #162035;border-radius:8px;color:#e2eaf4;font-size:14px;margin-bottom:16px;outline:none;transition:border-color .2s}
input:focus{border-color:#00c9a7}
button{width:100%;padding:12px;background:#00c9a7;color:#000;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.85}button:disabled{opacity:.5;cursor:not-allowed}
.err{background:rgba(239,68,68,.1);border:1px solid #ef4444;color:#ef4444;border-radius:8px;padding:10px 14px;font-size:12px;margin-bottom:14px;display:none}
.footer{text-align:center;color:#4a6080;font-size:11px;margin-top:20px}
</style></head>
<body>
<div class="card">
  <div class="logo">💊</div>
  <h2>MediShop License Admin</h2>
  <p class="sub">Cloud Sprint | 9985223448</p>
  <div class="err" id="err"></div>
  <label for="user">Username</label>
  <input type="text" id="user" placeholder="Enter username" autocomplete="username" onkeydown="if(event.key==='Enter')document.getElementById('pass').focus()"/>
  <label for="pass">Password</label>
  <input type="password" id="pass" placeholder="Enter password" autocomplete="current-password" onkeydown="if(event.key==='Enter')login()"/>
  <button id="btn" onclick="login()">🔑 Login</button>
  <div class="footer">Cloud Sprint © 2024 | contact@cloudsprint.in</div>
</div>
<script>
window.onload=function(){document.getElementById('user').focus();};
function login(){
  var u=document.getElementById('user').value.trim();
  var p=document.getElementById('pass').value.trim();
  var e=document.getElementById('err');
  var b=document.getElementById('btn');
  e.style.display='none';
  if(!u||!p){e.textContent='Please enter username and password.';e.style.display='block';return;}
  b.disabled=true;b.textContent='Logging in…';
  var xhr=new XMLHttpRequest();
  xhr.open('POST','/admin-login',true);
  xhr.setRequestHeader('Content-Type','application/json');
  xhr.timeout=10000;
  xhr.ontimeout=function(){e.textContent='Server timeout. Try again.';e.style.display='block';b.disabled=false;b.textContent='🔑 Login';};
  xhr.onerror=function(){e.textContent='Network error. Try again.';e.style.display='block';b.disabled=false;b.textContent='🔑 Login';};
  xhr.onload=function(){
    try{var d=JSON.parse(xhr.responseText);
      if(d.success){sessionStorage.setItem('ms_admin_token',d.token);window.location.href='/dashboard.html';}
      else{e.textContent='Invalid username or password.';e.style.display='block';b.disabled=false;b.textContent='🔑 Login';document.getElementById('pass').value='';document.getElementById('pass').focus();}
    }catch(ex){e.textContent='Server error. Try again.';e.style.display='block';b.disabled=false;b.textContent='🔑 Login';}
  };
  xhr.send(JSON.stringify({username:u,password:p}));
}
</script></body></html>`);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'MediShop License Server', version: '3.0.0', timestamp: new Date().toISOString(), db: process.env.DATABASE_URL ? 'postgresql' : 'json' });
});

// Keep-alive (prevents Render free tier from sleeping)
function startKeepAlive() {
  const url = process.env.RENDER_EXTERNAL_URL || ('http://localhost:' + PORT);
  setInterval(() => {
    const mod = url.startsWith('https') ? require('https') : require('http');
    const req = mod.get(url + '/health', (res) => { res.resume(); console.log('[KeepAlive] OK —', new Date().toISOString()); });
    req.on('error', (e) => console.warn('[KeepAlive] Failed:', e.message));
    req.end();
  }, 14 * 60 * 1000);
}

app.use((req, res) => res.status(404).json({ success: false, error: 'Not found' }));
app.use((err, req, res, next) => { console.error('[ERROR]', err.message); res.status(500).json({ success: false, error: 'Internal server error' }); });

// Start
db.init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('[MediShop License Server] Port:', PORT);
    console.log('[DB]', process.env.DATABASE_URL ? 'PostgreSQL PERSISTENT ✅' : 'JSON file (ephemeral)');
    console.log('[Admin] Login at: /');
    startKeepAlive();
  });
}).catch(err => {
  console.error('[FATAL] DB init failed:', err.message);
  process.exit(1);
});
