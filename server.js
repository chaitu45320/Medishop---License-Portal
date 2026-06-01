'use strict';
const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const jwt     = require('jsonwebtoken');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

const PORT       = process.env.PORT        || 10000;
const API_SECRET = process.env.API_SECRET  || process.env.ADMIN_KEY || 'MediShop@Chaitanya2024';
const ADMIN_KEY  = process.env.ADMIN_KEY   || API_SECRET;
const JWT_SECRET = process.env.JWT_SECRET  || 'MS_JWT_Medishop_2024_Ultra_Secure_Key_99';
const LIC_SECRET = process.env.LICENSE_SECRET || 'MS@Medishop#2024!PharmacyBilling$Key@Secure99';
const TRIAL_DAYS = parseInt(process.env.TRIAL_DAYS  || '7');
const MAX_DEV    = parseInt(process.env.MAX_DEVICES || '1');
const PREFIX     = 'MEDSHP';
const CHARS      = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization,X-Admin-Key');
  if(req.method==='OPTIONS'){res.status(204).end();return;}
  next();
});
app.use((req,res,next)=>{
  if(req.path!=='/health'&&req.path!=='/favicon.ico')
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

const DATA_DIR = path.join(__dirname,'data');
const DB_FILE  = path.join(DATA_DIR,'licenses.json');
if(!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR,{recursive:true});

let _db = null;
let _pg = null;

function loadDB(){
  if(_db) return _db;
  try{ _db=JSON.parse(fs.readFileSync(DB_FILE,'utf8')); }
  catch(e){ _db={keys:{},logs:[]}; }
  return _db;
}

function saveDB(db){
  if(db.logs&&db.logs.length>2000) db.logs=db.logs.slice(0,2000);
  _db=db;
  try{ fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2)); }catch(e){}
  if(_pg) savePG(db).catch(()=>{});
}

async function initPG(){
  const url=process.env.DATABASE_URL;
  if(!url){ console.log('[DB] No DATABASE_URL — JSON file mode'); return; }
  try{
    const {Client}=require('pg');
    _pg=new Client({ connectionString:url, ssl:{rejectUnauthorized:false} });
    await _pg.connect();
    await _pg.query('CREATE TABLE IF NOT EXISTS ms_store(id TEXT PRIMARY KEY, data TEXT NOT NULL)');
    const r=await _pg.query("SELECT data FROM ms_store WHERE id='db'");
    if(r.rows.length){
      _db=JSON.parse(r.rows[0].data);
      console.log('[DB] PostgreSQL loaded. Keys:',Object.keys(_db.keys||{}).length);
    } else {
      if(!_db) _db={keys:{},logs:[]};
      await savePG(_db);
      console.log('[DB] PostgreSQL ready (fresh)');
    }
  }catch(e){
    console.error('[DB] PG failed:',e.message);
    _pg=null;
  }
}

async function savePG(db){
  if(!_pg) return;
  try{
    await _pg.query(
      "INSERT INTO ms_store(id,data) VALUES('db',$1) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data",
      [JSON.stringify(db)]
    );
  }catch(e){ console.error('[DB] PG save error:',e.message); }
}

function dbLog(db,kh,did,ip,action,result,detail){
  if(!db.logs) db.logs=[];
  db.logs.unshift({kh:kh||'',did:did||'',ip:ip||'',action,result,detail:detail||'',ts:Date.now()});
  if(db.logs.length>2000) db.logs=db.logs.slice(0,2000);
}

function hmacSeg(data,len){
  const b=crypto.createHmac('sha256',LIC_SECRET).update(data).digest();
  let r=''; for(let i=0;i<b.length&&r.length<len;i++) r+=CHARS[b[i]%CHARS.length]; return r;
}
function randSeg(p){ let r=p||''; while(r.length<6) r+=CHARS[Math.floor(Math.random()*CHARS.length)]; return r.slice(0,6); }
function genKey(type){ const tc=type==='full'?'FULL':'TRAL',tf=type==='full'?'F':'T',s1=randSeg(tf),s2=randSeg(),s3=hmacSeg(s1+'-'+s2,6); return PREFIX+'-'+tc+'-'+s1+'-'+s2+'-'+s3; }
function validateFmt(k){
  const p=k.trim().toUpperCase().split('-');
  if(p.length!==5) return{ok:false,reason:'Must have 5 segments'};
  if(p[0]!==PREFIX) return{ok:false,reason:'Must start with MEDSHP'};
  if(!['FULL','TRAL'].includes(p[1])) return{ok:false,reason:'Segment 2 must be FULL or TRAL'};
  if([p[2],p[3],p[4]].some(s=>s.length!==6)) return{ok:false,reason:'Each segment must be 6 chars'};
  if(p[4]!==hmacSeg(p[2]+'-'+p[3],6)) return{ok:false,reason:'Checksum mismatch'};
  if(p[1]==='FULL'&&p[2][0]!=='F') return{ok:false,reason:'Type flag mismatch'};
  if(p[1]==='TRAL'&&p[2][0]!=='T') return{ok:false,reason:'Type flag mismatch'};
  return{ok:true,type:p[1]==='FULL'?'full':'trial'};
}
function hashKey(k){ return crypto.createHmac('sha256',LIC_SECRET).update(k.toUpperCase()).digest('hex'); }
function signJWT(p){ return jwt.sign(p,JWT_SECRET,{expiresIn:'365d'}); }
function verifyJWT(t){ try{return jwt.verify(t,JWT_SECRET);}catch{return null;} }
function daysLeft(at,type){ if(type==='full')return null; if(!at)return TRIAL_DAYS; return Math.max(0,Math.ceil(((at+TRIAL_DAYS*86400000)-Date.now())/86400000)); }
function trialExpired(at,type){ if(type==='full'||!at)return false; return Date.now()>at+TRIAL_DAYS*86400000; }
function adminAuth(req,res,next){
  const t=(req.headers['authorization']||'').replace('Bearer ','').trim()||(req.headers['x-admin-key']||'').trim()||(req.query.token||'').trim();
  if(t===API_SECRET||t===ADMIN_KEY){next();return;}
  res.status(401).json({success:false,error:'Unauthorized'});
}
function enrich(kh,kr,db){
  try{
    const acts=Object.values(kr.activations||{}),active=acts.filter(d=>!d.isRevoked);
    const firstAt=active.length>0?Math.min.apply(null,active.map(d=>d.activatedAt||0)):null;
    return{key_hash:kh,key_display:kr.key||'',email:kr.email||'',type:kr.type||'trial',
      max_devices:kr.maxDevices||MAX_DEV,is_active:kr.isActive?1:0,issued_at:kr.issuedAt||0,
      notes:kr.notes||'',active_devices:active.length,
      fail_count:(db.logs||[]).filter(l=>l.kh===kh&&l.result&&l.result.startsWith('fail')).length,
      daysLeft:daysLeft(firstAt,kr.type),isExpired:kr.type==='trial'?trialExpired(firstAt,kr.type):false,
      activations:acts.map(d=>({deviceId:d.deviceId||'',deviceName:d.deviceName||'Unknown',activatedAt:d.activatedAt||0,lastSeen:d.lastSeen||0,isRevoked:!!d.isRevoked}))};
  }catch(e){return{key_hash:kh,key_display:kr.key||kh,email:kr.email||'',type:kr.type||'trial',max_devices:MAX_DEV,is_active:0,issued_at:0,notes:'',active_devices:0,fail_count:0,daysLeft:0,isExpired:false,activations:[]};}
}

app.post('/api/activate',(req,res)=>{
  const{licenseKey,email,deviceId,deviceName,appVersion}=req.body;
  if(!licenseKey||!email||!deviceId) return res.status(400).json({success:false,error:'licenseKey, email, deviceId required'});
  const key=licenseKey.trim().toUpperCase(),em=email.trim().toLowerCase(),fmt=validateFmt(key);
  if(!fmt.ok) return res.status(400).json({success:false,error:'Invalid key: '+fmt.reason});
  const db=loadDB(),kh=hashKey(key),kr=db.keys?.[kh];
  if(!kr){dbLog(db,kh,deviceId,req.ip,'activate','fail_notfound','');saveDB(db);return res.status(404).json({success:false,error:'License not found. Contact 9985223448.'});}
  if(!kr.isActive){dbLog(db,kh,deviceId,req.ip,'activate','fail_revoked','');saveDB(db);return res.status(403).json({success:false,error:'License revoked.'});}
  if(kr.email!==em){dbLog(db,kh,deviceId,req.ip,'activate','fail_email','');saveDB(db);return res.status(403).json({success:false,error:'Email does not match.'});}
  if(!kr.activations) kr.activations={};
  const ex=kr.activations[deviceId];
  if(ex){
    if(ex.isRevoked) return res.status(403).json({success:false,error:'Device revoked.'});
    if(kr.type==='trial'&&trialExpired(ex.activatedAt,'trial')) return res.status(403).json({success:false,error:'Trial expired. Call 9985223448.'});
    const token=signJWT({kh,deviceId,type:kr.type,email:em});
    ex.lastSeen=Date.now();ex.deviceName=deviceName||ex.deviceName;
    dbLog(db,kh,deviceId,req.ip,'reactivate','ok',deviceName||'');saveDB(db);
    return res.json({success:true,token,type:kr.type,daysLeft:daysLeft(ex.activatedAt,kr.type),email:em,message:'License verified.'});
  }
  const active=Object.values(kr.activations).filter(d=>!d.isRevoked);
  if(active.length>=(kr.maxDevices||MAX_DEV)) return res.status(409).json({success:false,code:'DEVICE_LIMIT',error:'Already active on '+active.length+' device(s). Contact support.'});
  const now=Date.now(),token=signJWT({kh,deviceId,type:kr.type,email:em});
  kr.activations[deviceId]={deviceId,deviceName:deviceName||'Unknown',appVersion:appVersion||'1.0',activatedAt:now,lastSeen:now,isRevoked:false};
  dbLog(db,kh,deviceId,req.ip,'activate','ok',deviceName||'');saveDB(db);
  return res.json({success:true,token,type:kr.type,daysLeft:daysLeft(now,kr.type),activatedAt:now,email:em,message:kr.type==='full'?'Full license activated!':'Trial activated — '+daysLeft(now,kr.type)+' days remaining.'});
});

function doValidate(token,deviceId,res,db,ip){
  if(!token||!deviceId) return res.status(400).json({success:false,active:false,error:'token and deviceId required'});
  const p=verifyJWT(token);
  if(!p||p.deviceId!==deviceId) return res.status(401).json({success:false,active:false,error:'Invalid token'});
  const kr=db.keys?.[p.kh],act=kr?.activations?.[deviceId];
  if(!act||act.isRevoked) return res.status(401).json({success:false,active:false,error:'Device not authorized'});
  if(!kr||!kr.isActive) return res.status(403).json({success:false,active:false,error:'License deactivated'});
  if(kr.type==='trial'&&trialExpired(act.activatedAt,'trial')) return res.status(403).json({success:false,active:false,error:'Trial expired'});
  act.lastSeen=Date.now();dbLog(db,p.kh,deviceId,ip,'validate','ok','');saveDB(db);
  return res.json({success:true,valid:true,active:true,type:kr.type,daysLeft:daysLeft(act.activatedAt,kr.type),email:kr.email});
}
app.post('/api/validate',(req,res)=>doValidate(req.body.token,req.body.deviceId,res,loadDB(),req.ip||''));
app.get('/api/validate',(req,res)=>doValidate(req.query.token,req.query.machine_id||req.query.deviceId,res,loadDB(),req.ip||''));
app.post('/api/deactivate',(req,res)=>{
  const{token,deviceId}=req.body;
  if(!token||!deviceId) return res.status(400).json({success:false,error:'required'});
  const p=verifyJWT(token);
  if(!p||p.deviceId!==deviceId) return res.status(401).json({success:false,error:'Invalid token'});
  const db=loadDB();
  if(db.keys?.[p.kh]?.activations?.[deviceId]){delete db.keys[p.kh].activations[deviceId];dbLog(db,p.kh,deviceId,req.ip||'','deactivate','ok','');saveDB(db);}
  return res.json({success:true,message:'Device deactivated.'});
});
app.get('/health',(req,res)=>{const db=loadDB(),keys=Object.values(db.keys||{});res.json({status:'ok',version:'4.0',keys:keys.length,db:_pg?'postgresql':'json',port:PORT});});

app.get('/admin/dashboard',adminAuth,(req,res)=>{
  try{const db=loadDB(),keys=Object.values(db.keys||{}),today=Date.now()-86400000;
  res.json({success:true,stats:{totalKeys:keys.length,fullKeys:keys.filter(k=>k.type==='full').length,trialKeys:keys.filter(k=>k.type==='trial').length,activeKeys:keys.filter(k=>k.isActive).length,totalDevices:keys.reduce((n,k)=>n+Object.values(k.activations||{}).filter(d=>!d.isRevoked).length,0)},todayActivations:(db.logs||[]).filter(l=>l.action==='activate'&&l.result==='ok'&&l.ts>today).length});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.get('/admin/keys',adminAuth,(req,res)=>{
  try{const db=loadDB();const keys=Object.entries(db.keys||{}).map(([h,k])=>enrich(h,k,db)).sort((a,b)=>b.issued_at-a.issued_at);res.json({success:true,keys,total:keys.length});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.post('/admin/keys/generate',adminAuth,(req,res)=>{
  try{const{email,type,maxDevices,notes}=req.body;if(!email||!type)return res.status(400).json({success:false,error:'email and type required'});if(!['full','trial'].includes(type))return res.status(400).json({success:false,error:'type must be full or trial'});const key=genKey(type),kh=hashKey(key),db=loadDB();if(!db.keys)db.keys={};db.keys[kh]={key,email:email.trim().toLowerCase(),type,maxDevices:parseInt(maxDevices)||MAX_DEV,isActive:true,issuedAt:Date.now(),notes:notes||'',activations:{}};saveDB(db);res.json({success:true,key,type,email:email.trim().toLowerCase(),maxDevices:parseInt(maxDevices)||MAX_DEV});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.post('/admin/keys/import',adminAuth,(req,res)=>{
  try{const{licenseKey,email,type,maxDevices,notes}=req.body;if(!licenseKey||!email||!type)return res.status(400).json({success:false,error:'licenseKey, email, type required'});const key=licenseKey.trim().toUpperCase(),fmt=validateFmt(key);if(!fmt.ok)return res.status(400).json({success:false,error:'Invalid key: '+fmt.reason});const db=loadDB(),kh=hashKey(key);if(!db.keys)db.keys={};if(db.keys[kh])return res.status(409).json({success:false,error:'Key already registered.'});db.keys[kh]={key,email:email.trim().toLowerCase(),type,maxDevices:parseInt(maxDevices)||MAX_DEV,isActive:true,issuedAt:Date.now(),notes:notes||'',activations:{}};saveDB(db);res.json({success:true,key,type,email:email.trim().toLowerCase(),message:'Key registered.'});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.post('/admin/keys/:hash/revoke',adminAuth,(req,res)=>{try{const db=loadDB();if(!db.keys?.[req.params.hash])return res.status(404).json({success:false,error:'Not found'});db.keys[req.params.hash].isActive=false;dbLog(db,req.params.hash,'',req.ip||'','admin_revoke','ok','');saveDB(db);res.json({success:true,message:'Revoked.'});}catch(e){res.status(500).json({success:false,error:e.message});}});
app.post('/admin/keys/:hash/restore',adminAuth,(req,res)=>{try{const db=loadDB();if(!db.keys?.[req.params.hash])return res.status(404).json({success:false,error:'Not found'});db.keys[req.params.hash].isActive=true;dbLog(db,req.params.hash,'',req.ip||'','admin_restore','ok','');saveDB(db);res.json({success:true,message:'Restored.'});}catch(e){res.status(500).json({success:false,error:e.message});}});
app.post('/admin/devices/:hash/transfer-all',adminAuth,(req,res)=>{try{const db=loadDB();if(!db.keys?.[req.params.hash])return res.status(404).json({success:false,error:'Not found'});db.keys[req.params.hash].activations={};dbLog(db,req.params.hash,'',req.ip||'','transfer_all','ok','');saveDB(db);res.json({success:true,message:'All slots freed.'});}catch(e){res.status(500).json({success:false,error:e.message});}});
app.post('/admin/verify',adminAuth,(req,res)=>{
  try{const key=(req.body.licenseKey||'').trim().toUpperCase();if(!key)return res.status(400).json({success:false,error:'licenseKey required'});const fmt=validateFmt(key);if(!fmt.ok)return res.status(400).json({success:false,error:'Invalid: '+fmt.reason});const db=loadDB(),kh=hashKey(key),kr=db.keys?.[kh];if(!kr)return res.status(404).json({success:false,error:'Key not found. Generate in admin first.'});const acts=Object.values(kr.activations||{}),active=acts.filter(d=>!d.isRevoked),firstAt=active.length>0?Math.min.apply(null,active.map(d=>d.activatedAt||0)):null;res.json({success:true,type:kr.type,email:kr.email,daysLeft:daysLeft(firstAt,kr.type),isExpired:trialExpired(firstAt,kr.type),isActive:!!kr.isActive,deviceCount:active.length,maxDevices:kr.maxDevices||MAX_DEV,keyHash:kh,devices:acts.map(d=>({deviceId:d.deviceId||'',deviceName:d.deviceName||'Unknown',activatedAt:d.activatedAt||0,lastSeen:d.lastSeen||0,isRevoked:!!d.isRevoked}))});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.get('/admin/suspicious',adminAuth,(req,res)=>{
  try{const db=loadDB(),fm={};(db.logs||[]).filter(l=>l.result&&l.result.startsWith('fail')).forEach(l=>{const h=l.kh||'unknown';if(!fm[h])fm[h]={kh:h,count:0,last:0,ips:new Set()};fm[h].count++;if(l.ts>fm[h].last)fm[h].last=l.ts;if(l.ip)fm[h].ips.add(l.ip);});const sus=Object.values(fm).filter(e=>e.count>=3).sort((a,b)=>b.count-a.count).map(e=>{const k=db.keys?.[e.kh];return{key_hash:e.kh,key_display:k?.key||e.kh.slice(0,12)+'…',email:k?.email||'—',type:k?.type||'—',fail_count:e.count,last_attempt:e.last,ips:[...e.ips].join(', ')};});res.json({success:true,suspicious:sus,count:sus.length});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.get('/admin/logs',adminAuth,(req,res)=>{
  try{const db=loadDB(),limit=Math.min(parseInt(req.query.limit)||200,1000);let logs=db.logs||[];if(req.query.action)logs=logs.filter(l=>l.action===req.query.action);res.json({success:true,logs:logs.slice(0,limit),count:Math.min(logs.length,limit)});}
  catch(e){res.status(500).json({success:false,error:e.message});}
});
app.get('/admin/export',adminAuth,(req,res)=>{const db=loadDB();res.setHeader('Content-Disposition','attachment; filename="medishop-export-'+Date.now()+'.json"');res.json({exportedAt:new Date().toISOString(),application:'MediShop License Server v4.0',...db});});


app.get('/',(req,res)=>{
  if(req.query.signout) return res.redirect('/');
  const tok=(req.query.token||req.headers['x-admin-key']||'').trim();
  if(tok!==API_SECRET&&tok!==ADMIN_KEY){
    return res.status(401).send('<!DOCTYPE html><html><head><title>MediShop License</title><meta charset="UTF-8"/><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#060d19;color:#e2e8f0;font-family:Segoe UI,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;gap:16px;text-align:center;padding:24px}.logo{font-size:60px}h2{color:#00c9a7;font-size:22px}p{color:#6b8ab0;font-size:14px;max-width:400px;line-height:1.6}code{background:#0c1a2e;padding:4px 10px;border-radius:6px;font-family:monospace;color:#7dd3fc;font-size:12px}</style></head><body><div class="logo">💊</div><h2>MediShop License Admin</h2><p>Access requires a valid admin token.</p><p>URL format:<br><code>/?token=YOUR_API_SECRET</code></p><p style="margin-top:8px;font-size:12px">Support: 9985223448 | Cloud Sprint</p></body></html>');
  }
  const ASEC=API_SECRET, TD=TRIAL_DAYS, MD=MAX_DEV;
  res.send(`<!DOCTYPE html>
<html lang="en"><head>
<title>💊 MediShop License Admin</title>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#060d19;color:#e2eaf4;min-height:100vh}
.bar{background:#0a1628;border-bottom:1px solid #162035;padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50}
.bar-l{display:flex;align-items:center;gap:10px}
.bar-title{font-size:16px;font-weight:700;color:#00c9a7}
.bar-sub{font-size:11px;color:#4a6080}
.bar-r{display:flex;align-items:center;gap:8px}
.dot{width:8px;height:8px;background:#22c55e;border-radius:50%;animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.online{font-size:11px;color:#22c55e;display:flex;align-items:center;gap:5px}
.wrap{max-width:1280px;margin:0 auto;padding:20px}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.stat{background:#0a1628;border:1px solid #162035;border-radius:8px;padding:14px 18px;flex:1;min-width:130px;border-top-width:3px}
.sl{font-size:10px;color:#4a6080;text-transform:uppercase;font-weight:700;letter-spacing:.05em;margin-bottom:6px}
.sv{font-size:26px;font-weight:800}
.tabs{display:flex;border-bottom:2px solid #162035;margin-bottom:18px;gap:2px;overflow-x:auto}
.tab{padding:9px 16px;cursor:pointer;font-size:13px;font-weight:600;color:#4a6080;border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap;transition:.15s}
.tab:hover{color:#cbd5e1}.tab.on{color:#00c9a7;border-bottom-color:#00c9a7}
.pane{display:none}.pane.on{display:block}
.card{background:#0a1628;border:1px solid #162035;border-radius:8px;padding:18px;margin-bottom:14px}
.ch{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.ct{font-size:13px;font-weight:700;color:#7dd3fc}
input,select{background:#0f1f35;border:1px solid #162035;color:#e2eaf4;padding:8px 11px;border-radius:6px;font-size:13px;outline:none}
input:focus,select:focus{border-color:#00c9a7}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.btn{padding:8px 14px;border-radius:6px;border:none;cursor:pointer;font-size:12px;font-weight:700;transition:opacity .15s;white-space:nowrap}
.btn:hover{opacity:.8}.btn:disabled{opacity:.4;cursor:not-allowed}
.bg{background:#00c9a7;color:#000}.bb{background:#0ea5e9;color:#fff}
.br{background:#ef4444;color:#fff}.bo{background:#f59e0b;color:#000}.bd{background:#1e3050;color:#cbd5e1}
.alert{padding:10px 13px;border-radius:6px;font-size:12px;margin-top:8px;display:none}
.ok{background:rgba(34,197,94,.1);border:1px solid #22c55e;color:#22c55e;display:block}
.er{background:rgba(239,68,68,.1);border:1px solid #ef4444;color:#ef4444;display:block}
.kbox{background:#0f1f35;border:2px solid #00c9a7;border-radius:8px;padding:16px;margin-top:12px;display:none;text-align:center}
.kval{font-family:monospace;font-size:17px;font-weight:700;color:#00c9a7;letter-spacing:.05em;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:12px}
th{padding:7px 9px;text-align:left;color:#4a6080;font-size:10px;text-transform:uppercase;border-bottom:1px solid #162035;white-space:nowrap}
td{padding:8px 9px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:middle}
tr:hover td{background:rgba(0,201,167,.025)}
.mono{font-family:monospace;color:#00c9a7;font-size:11px}
.bf{background:rgba(34,197,94,.12);color:#22c55e;padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700}
.bt{background:rgba(245,158,11,.14);color:#f59e0b;padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700}
.ba{background:rgba(0,201,167,.12);color:#00c9a7;padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700}
.bv{background:rgba(239,68,68,.12);color:#ef4444;padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700}
.sp{display:inline-block;width:13px;height:13px;border:2px solid rgba(0,201,167,.2);border-top-color:#00c9a7;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:5px}
@keyframes spin{to{transform:rotate(360deg)}}
.vbox{padding:14px;border-radius:8px;margin-top:12px;display:none}
.vok{background:rgba(0,201,167,.08);border:1px solid #00c9a7;display:block}
.ver{background:rgba(239,68,68,.08);border:1px solid #ef4444;display:block}
.vrow{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)}
.vrow:last-child{border:none}.vlb{font-size:10px;color:#4a6080;text-transform:uppercase}.vvl{font-weight:700;font-size:13px}
.dt td,.dt th{padding:5px 7px}.dt th{background:#0a1628;color:#4a6080;font-size:10px;text-transform:uppercase}
</style></head>
<body>
<div class="bar">
  <div class="bar-l">
    <span style="font-size:24px">💊</span>
    <span class="bar-title">MediShop License Admin</span>
    <span class="bar-sub">Cloud Sprint | contact@cloudsprint.in | 9985223448</span>
  </div>
  <div class="bar-r">
    <div class="online"><div class="dot"></div>Online</div>
    <button class="btn bb" onclick="exportData()" style="font-size:11px;padding:5px 10px">⬇ Export</button>
    <button class="btn br" onclick="location.href='/'" style="font-size:11px;padding:5px 10px">🚪 Sign Out</button>
  </div>
</div>
<div class="wrap">
  <div id="stats" class="stats">
    <div class="stat" style="border-top-color:#00c9a7;flex:1"><div class="sl"><span class="sp"></span>Loading stats…</div><div class="sv" style="color:#4a6080">—</div></div>
  </div>
  <div class="tabs">
    <div class="tab on" onclick="tab('all')">📋 All Licenses</div>
    <div class="tab"    onclick="tab('gen')">⚡ Generate Key</div>
    <div class="tab"    onclick="tab('imp')">📥 Register Existing</div>
    <div class="tab"    onclick="tab('ver')">🔍 Verify &amp; Manage</div>
    <div class="tab"    onclick="tab('sus')">⚠ Suspicious</div>
    <div class="tab"    onclick="tab('log')">📋 Activity Logs</div>
  </div>
  <div id="p-all" class="pane on">
    <div class="card">
      <div class="ch"><span class="ct">📋 All License Keys</span><button class="btn bd" onclick="loadKeys()" style="font-size:11px;padding:5px 10px">↻ Refresh</button></div>
      <div style="overflow-x:auto"><table><thead><tr><th>License Key</th><th>Email</th><th>Type</th><th>Devices</th><th>Status</th><th>Issued</th><th>Actions</th></tr></thead>
      <tbody id="kb"><tr><td colspan="7" style="text-align:center;padding:30px;color:#4a6080"><span class="sp"></span>Loading…</td></tr></tbody></table></div>
    </div>
  </div>
  <div id="p-gen" class="pane">
    <div class="card">
      <div class="ch"><span class="ct">⚡ Generate New License Key</span></div>
      <div class="row">
        <input type="email" id="gEm" placeholder="Customer email *" style="min-width:210px"/>
        <select id="gTy"><option value="full">Full License (Permanent)</option><option value="trial">Trial (${TD} days)</option></select>
        <input type="number" id="gDv" value="${MD}" min="1" max="10" style="width:65px" title="Max Devices"/>
        <input type="text" id="gNt" placeholder="Notes (shop name…)" style="min-width:180px"/>
        <button class="btn bg" id="gBt" onclick="genKey()">✨ Generate &amp; Register</button>
      </div>
      <div id="gAl" class="alert"></div>
      <div class="kbox" id="kbx">
        <div class="kval" id="ktx"></div>
        <div id="kmt" style="font-size:11px;color:#4a6080;margin-top:5px"></div>
        <div style="display:flex;gap:8px;margin-top:10px">
          <button class="btn bd" style="flex:1" onclick="copyKey()">📋 Copy</button>
          <button class="btn bg" style="flex:1" onclick="waShare()">📱 WhatsApp</button>
        </div>
      </div>
    </div>
  </div>
  <div id="p-imp" class="pane">
    <div class="card">
      <div class="ch"><span class="ct">📥 Register Existing Key</span></div>
      <p style="font-size:12px;color:#4a6080;margin-bottom:12px">Use when a key was already shared with a customer before being registered on the server.</p>
      <div class="row">
        <input type="text" id="iKy" placeholder="MEDSHP-TRAL-XXXXXX-XXXXXX-XXXXXX *" style="min-width:300px;font-family:monospace"/>
        <input type="email" id="iEm" placeholder="Customer email *" style="min-width:210px"/>
        <select id="iTy"><option value="trial">Trial</option><option value="full">Full License</option></select>
        <input type="text" id="iNt" placeholder="Notes" style="min-width:140px"/>
        <button class="btn bb" id="iBt" onclick="importKey()">📥 Register Key</button>
      </div>
      <div id="iAl" class="alert"></div>
    </div>
  </div>
  <div id="p-ver" class="pane">
    <div class="card">
      <div class="ch"><span class="ct">🔍 Verify / Lookup Key</span></div>
      <div class="row"><input type="text" id="vKy" placeholder="Enter license key…" style="min-width:300px;font-family:monospace"/><button class="btn bb" id="vBt" onclick="verifyKey()">🔍 Verify</button></div>
      <div id="vRes" class="vbox"></div>
    </div>
    <div class="card">
      <div class="ch"><span class="ct">🔄 Transfer License to New Device</span></div>
      <p style="font-size:12px;color:#4a6080;margin-bottom:12px">Frees all device slots so customer can activate on a new device.</p>
      <div class="row"><input type="text" id="tKy" placeholder="License key…" style="min-width:300px;font-family:monospace"/><button class="btn bo" id="tBt" onclick="transferKey()">🔄 Free All Devices</button></div>
      <div id="tAl" class="alert"></div>
    </div>
    <div class="card">
      <div class="ch"><span class="ct">🚫 Revoke License</span></div>
      <p style="font-size:12px;color:#4a6080;margin-bottom:12px">Blocks this license — customer loses access on next validation.</p>
      <div class="row"><input type="text" id="rKy" placeholder="License key…" style="min-width:300px;font-family:monospace"/><button class="btn br" id="rBt" onclick="revokeKey()">🚫 Revoke License</button></div>
      <div id="rAl" class="alert"></div>
    </div>
  </div>
  <div id="p-sus" class="pane">
    <div class="card">
      <div class="ch"><span class="ct">⚠ Suspicious Activity</span><button class="btn bd" onclick="loadSus()" style="font-size:11px;padding:5px 10px">↻ Refresh</button></div>
      <div style="overflow-x:auto"><table><thead><tr><th>Key</th><th>Email</th><th>Type</th><th>Fails</th><th>Last Attempt</th><th>IPs</th></tr></thead>
      <tbody id="sb"><tr><td colspan="6" style="text-align:center;padding:20px;color:#4a6080">Click Refresh</td></tr></tbody></table></div>
    </div>
  </div>
  <div id="p-log" class="pane">
    <div class="card">
      <div class="ch"><span class="ct">📋 Activity Logs</span><button class="btn bd" onclick="loadLogs()" style="font-size:11px;padding:5px 10px">↻ Refresh</button></div>
      <div style="overflow-x:auto"><table><thead><tr><th>Time</th><th>Action</th><th>Result</th><th>Key</th><th>Device</th><th>IP</th><th>Detail</th></tr></thead>
      <tbody id="lb"><tr><td colspan="7" style="text-align:center;padding:20px;color:#4a6080">Click Refresh</td></tr></tbody></table></div>
    </div>
  </div>
</div>
<script>
const S='${ASEC}',B=location.origin;
function tab(t){
  document.querySelectorAll('.tab').forEach((e,i)=>e.classList.toggle('on',['all','gen','imp','ver','sus','log'][i]===t));
  document.querySelectorAll('.pane').forEach(e=>e.classList.remove('on'));
  document.getElementById('p-'+t).classList.add('on');
  if(t==='all')loadKeys();if(t==='sus')loadSus();if(t==='log')loadLogs();
}
async function api(m,p,b){
  try{
    const c=new AbortController(),tid=setTimeout(()=>c.abort(),15000);
    const r=await fetch(B+'/admin'+p,{method:m,headers:{'Authorization':'Bearer '+S,'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined,signal:c.signal});
    clearTimeout(tid);
    const tx=await r.text();
    try{return JSON.parse(tx);}catch(e){return{success:false,error:'Bad response: '+tx.slice(0,100)};}
  }catch(e){
    if(e.name==='AbortError')return{success:false,error:'Timed out. Server may be waking up — wait 30s and refresh.'};
    return{success:false,error:'Network: '+e.message};
  }
}
function fd(ts){if(!ts)return'—';return new Date(+ts).toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'});}
function fdt(ts){if(!ts)return'—';return new Date(+ts).toLocaleString('en-IN',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});}
async function loadStats(){
  const r=await api('GET','/dashboard');
  if(!r.success){document.getElementById('stats').innerHTML='<div class="stat" style="border-top-color:#ef4444;flex:1"><div class="sl">⚠ Error loading stats</div><div class="sv" style="color:#ef4444;font-size:12px">'+(r.error||'Unknown error')+'</div></div>';return;}
  const s=r.stats||{};
  document.getElementById('stats').innerHTML=[['Total Keys',s.totalKeys||0,'#00c9a7'],['Full',s.fullKeys||0,'#22c55e'],['Trial',s.trialKeys||0,'#f59e0b'],['Active Devices',s.totalDevices||0,'#0ea5e9'],["Today's Acts",r.todayActivations||0,'#a78bfa']].map(([l,v,c])=>'<div class="stat" style="border-top-color:'+c+'"><div class="sl">'+l+'</div><div class="sv" style="color:'+c+'">'+v+'</div></div>').join('');
}
async function loadKeys(){
  document.getElementById('kb').innerHTML='<tr><td colspan="7" style="text-align:center;padding:30px;color:#4a6080"><span class="sp"></span>Loading…</td></tr>';
  const r=await api('GET','/keys');
  if(!r.success){document.getElementById('kb').innerHTML='<tr><td colspan="7" style="text-align:center;padding:20px;color:#ef4444">❌ '+(r.error||'Error')+'</td></tr>';return;}
  if(!r.keys||!r.keys.length){document.getElementById('kb').innerHTML='<tr><td colspan="7" style="text-align:center;padding:30px;color:#4a6080">No license keys yet — go to Generate Key tab</td></tr>';return;}
  document.getElementById('kb').innerHTML=r.keys.map(k=>{
    const tb=k.type==='full'?'<span class="bf">✓ FULL</span>':'<span class="bt">⏱ TRIAL</span>',sb=k.is_active?'<span class="ba">● Active</span>':'<span class="bv">● Revoked</span>',dl=k.type==='full'?'♾':(k.daysLeft<=0?'<span style="color:#ef4444">Expired</span>':k.daysLeft+'d');
    return '<tr><td class="mono">'+k.key_display+'</td><td style="font-size:11px">'+k.email+(k.notes?'<br><span style="color:#4a6080">'+k.notes+'</span>':'')+'</td><td>'+tb+'</td><td style="text-align:center;font-weight:700">'+(k.active_devices||0)+'/'+k.max_devices+'</td><td>'+sb+'</td><td style="font-size:11px;color:#4a6080">'+fd(k.issued_at)+'</td><td><div style="display:flex;gap:4px;flex-wrap:wrap">'+(k.is_active?'<button class="btn br" style="font-size:10px;padding:3px 7px" onclick="rvk(\''+k.key_hash+'\')">Revoke</button>':'<button class="btn bg" style="font-size:10px;padding:3px 7px" onclick="rst(\''+k.key_hash+'\')">Restore</button>')+'<button class="btn bo" style="font-size:10px;padding:3px 7px" onclick="fsl(\''+k.key_hash+'\')">Free Slots</button></div></td></tr>';
  }).join('');
}
async function genKey(){
  const a=document.getElementById('gAl');a.className='alert';const em=document.getElementById('gEm').value.trim();
  if(!em){a.textContent='Email required.';a.className='alert er';return;}
  const bt=document.getElementById('gBt');bt.disabled=true;bt.innerHTML='<span class="sp"></span>Generating…';
  const r=await api('POST','/keys/generate',{email:em,type:document.getElementById('gTy').value,maxDevices:document.getElementById('gDv').value,notes:document.getElementById('gNt').value.trim()});
  bt.disabled=false;bt.textContent='✨ Generate & Register';
  if(!r.success){a.textContent='❌ '+r.error;a.className='alert er';return;}
  document.getElementById('ktx').textContent=r.key;document.getElementById('kmt').textContent=r.type.toUpperCase()+' | '+r.email+' | '+r.maxDevices+' device(s)';document.getElementById('kbx').style.display='block';a.textContent='✅ Key generated!';a.className='alert ok';loadKeys();loadStats();
}
function copyKey(){navigator.clipboard.writeText(document.getElementById('ktx').textContent).then(()=>alert('Copied!'));}
function waShare(){const k=document.getElementById('ktx').textContent;window.open('https://wa.me/?text='+encodeURIComponent('Your MediShop Pro license key:\n\n*'+k+'*\n\nActivate in the app under License Setup.\nSupport: 9985223448'),'_blank');}
async function importKey(){
  const a=document.getElementById('iAl');a.className='alert';const ky=document.getElementById('iKy').value.trim(),em=document.getElementById('iEm').value.trim();
  if(!ky){a.textContent='License key required.';a.className='alert er';return;}if(!em){a.textContent='Email required.';a.className='alert er';return;}
  const bt=document.getElementById('iBt');bt.disabled=true;bt.innerHTML='<span class="sp"></span>Registering…';
  const r=await api('POST','/keys/import',{licenseKey:ky,email:em,type:document.getElementById('iTy').value,notes:document.getElementById('iNt').value.trim()});
  bt.disabled=false;bt.textContent='📥 Register Key';
  if(!r.success){a.textContent='❌ '+r.error;a.className='alert er';return;}
  a.textContent='✅ Key registered! Customer can now activate.';a.className='alert ok';document.getElementById('iKy').value='';document.getElementById('iEm').value='';loadKeys();loadStats();
}
async function verifyKey(){
  const ky=document.getElementById('vKy').value.trim();if(!ky)return;
  const bt=document.getElementById('vBt');bt.disabled=true;bt.innerHTML='<span class="sp"></span>Verifying…';
  const r=await api('POST','/verify',{licenseKey:ky});bt.disabled=false;bt.textContent='🔍 Verify';
  const d=document.getElementById('vRes');
  if(!r.success){d.innerHTML='<strong>✗ '+r.error+'</strong>';d.className='vbox ver';return;}
  const dl=r.type==='full'?'Never expires':(r.daysLeft<=0?'<span style="color:#ef4444">EXPIRED</span>':r.daysLeft+' days remaining');
  const drows=(r.devices||[]).map(dv=>'<tr><td>'+dv.deviceName+'</td><td class="mono" style="font-size:10px">'+dv.deviceId.slice(0,20)+'</td><td>'+fdt(dv.activatedAt)+'</td><td>'+fdt(dv.lastSeen)+'</td><td>'+(dv.isRevoked?'<span style="color:#ef4444">Revoked</span>':'<span style="color:#22c55e">Active</span>')+'</td></tr>').join('');
  d.className='vbox vok';d.innerHTML='<div class="vrow"><span class="vlb">Status</span><span class="vvl">'+(r.isActive?'<span style="color:#22c55e">✓ VALID '+r.type.toUpperCase()+'</span>':'<span style="color:#ef4444">✗ REVOKED</span>')+'</span></div><div class="vrow"><span class="vlb">Email</span><span class="vvl">'+r.email+'</span></div><div class="vrow"><span class="vlb">Validity</span><span class="vvl">'+dl+'</span></div><div class="vrow"><span class="vlb">Devices</span><span class="vvl">'+r.deviceCount+' / '+r.maxDevices+'</span></div>'+(drows?'<div style="margin-top:10px"><table class="dt"><thead><tr><th>Device</th><th>ID</th><th>Activated</th><th>Last Seen</th><th>Status</th></tr></thead><tbody>'+drows+'</tbody></table></div>':'');
}
async function transferKey(){
  const ky=document.getElementById('tKy').value.trim(),a=document.getElementById('tAl');a.className='alert';if(!ky){a.textContent='Enter a license key.';a.className='alert er';return;}
  if(!confirm('Free all device slots?'))return;
  const rv=await api('POST','/verify',{licenseKey:ky});if(!rv.success){a.textContent='❌ '+rv.error;a.className='alert er';return;}
  const r=await api('POST','/devices/'+rv.keyHash+'/transfer-all');r.success?(a.textContent='✅ All slots freed.',a.className='alert ok',loadKeys()):(a.textContent='❌ '+r.error,a.className='alert er');
}
async function revokeKey(){
  const ky=document.getElementById('rKy').value.trim(),a=document.getElementById('rAl');a.className='alert';if(!ky){a.textContent='Enter a license key.';a.className='alert er';return;}
  if(!confirm('REVOKE this license?'))return;
  const rv=await api('POST','/verify',{licenseKey:ky});if(!rv.success){a.textContent='❌ '+rv.error;a.className='alert er';return;}
  const r=await api('POST','/keys/'+rv.keyHash+'/revoke');r.success?(a.textContent='✅ License revoked.',a.className='alert ok',loadKeys()):(a.textContent='❌ '+r.error,a.className='alert er');
}
async function rvk(h){if(!confirm('Revoke?'))return;const r=await api('POST','/keys/'+h+'/revoke');if(r.success)loadKeys();}
async function rst(h){const r=await api('POST','/keys/'+h+'/restore');if(r.success)loadKeys();}
async function fsl(h){if(!confirm('Free all slots?'))return;const r=await api('POST','/devices/'+h+'/transfer-all');if(r.success)loadKeys();}
async function loadSus(){
  document.getElementById('sb').innerHTML='<tr><td colspan="6" style="text-align:center;padding:20px"><span class="sp"></span>Loading…</td></tr>';
  const r=await api('GET','/suspicious');
  if(!r.success||!r.suspicious.length){document.getElementById('sb').innerHTML='<tr><td colspan="6" style="text-align:center;padding:20px;color:#22c55e">✅ No suspicious activity</td></tr>';return;}
  document.getElementById('sb').innerHTML=r.suspicious.map(s=>'<tr><td class="mono">'+s.key_display+'</td><td>'+s.email+'</td><td>'+s.type+'</td><td style="color:#ef4444;font-weight:700">'+s.fail_count+'</td><td style="font-size:11px">'+fdt(s.last_attempt)+'</td><td style="font-size:10px;color:#4a6080">'+s.ips+'</td></tr>').join('');
}
async function loadLogs(){
  document.getElementById('lb').innerHTML='<tr><td colspan="7" style="text-align:center;padding:20px"><span class="sp"></span>Loading…</td></tr>';
  const r=await api('GET','/logs');
  if(!r.success||!r.logs.length){document.getElementById('lb').innerHTML='<tr><td colspan="7" style="text-align:center;padding:20px;color:#4a6080">No logs yet</td></tr>';return;}
  const c={'ok':'#22c55e','reactivate':'#00c9a7'};
  document.getElementById('lb').innerHTML=r.logs.map(l=>'<tr><td style="font-size:10px;color:#4a6080;white-space:nowrap">'+fdt(l.ts)+'</td><td style="font-weight:700;color:#7dd3fc">'+l.action+'</td><td style="color:'+(c[l.result]||'#ef4444')+'">'+l.result+'</td><td class="mono" style="font-size:10px">'+(l.kh||'').slice(0,10)+'…</td><td style="font-size:11px">'+(l.did||'').slice(0,18)+'</td><td style="font-size:11px;color:#4a6080">'+(l.ip||'')+'</td><td style="font-size:11px">'+(l.detail||'')+'</td></tr>').join('');
}
function exportData(){window.open(B+'/admin/export','_blank');}
loadStats();loadKeys();
</script></body></html>`);
});

app.use((req,res)=>res.status(404).json({success:false,error:'Not found',path:req.path}));
app.use((err,req,res,next)=>{console.error('[ERR]',err.message);res.status(500).json({success:false,error:err.message});});

(async()=>{
  await initPG();
  if(!_db) loadDB();
  app.listen(PORT,'0.0.0.0',()=>{
    console.log('[Server] MediShop License Server v4.0 | Port:',PORT);
    console.log('[DB]',_pg?'PostgreSQL PERSISTENT':'JSON file (ephemeral)');
  });
})();
