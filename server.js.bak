import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const ASSIGNMENTS = path.join(__dirname, 'assignments.json');
const USERS = path.join(__dirname, 'users.json');

app.use(cors({origin:true,credentials:true}));
app.use(express.json({limit:'2mb'}));
app.use((req,res,next)=>req.path==='/users.json'?res.status(404).end():next());
app.use(express.static(__dirname, { index: false }));

async function readJson(file, fallback=[]) { try { return JSON.parse(await fs.readFile(file,'utf8')); } catch { return fallback; } }
async function writeJson(file, data) { await fs.writeFile(file, JSON.stringify(data,null,2)); }
const samsaraConfigured = () => !!process.env.SAMSARA_API_TOKEN;
const knoxConfigured = () => !!(process.env.KNOX_CLIENT_ID && process.env.KNOX_CLIENT_SECRET && process.env.KNOX_TENANT_ID);

function hashPassword(password, salt=crypto.randomBytes(16).toString('hex')) {
  const hash=crypto.scryptSync(String(password),salt,64).toString('hex');
  return {salt,hash};
}
function verifyPassword(password, user) {
  try { const hash=crypto.scryptSync(String(password),user.salt,64).toString('hex'); return crypto.timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(user.hash,'hex')); } catch { return false; }
}
async function ensureUsers(){
  let users=await readJson(USERS,null);
  if(!Array.isArray(users)||!users.length){
    const username=process.env.ADMIN_USERNAME||'admin';
    const password=process.env.ADMIN_PASSWORD||'Admin@1234';
    const hp=hashPassword(password);
    users=[{id:crypto.randomUUID(),username,displayName:'Administrator',role:'admin',...hp,createdAt:new Date().toISOString()}];
    await writeJson(USERS,users);
    console.log(`Initial admin created: ${username}`);
  }
  return users;
}
const sessions=new Map();
function setSession(res,user){const token=crypto.randomBytes(32).toString('hex');sessions.set(token,{userId:user.id,expires:Date.now()+1000*60*60*12});res.setHeader('Set-Cookie',`fleet_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`);}
function clearSession(res,token){if(token)sessions.delete(token);res.setHeader('Set-Cookie','fleet_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');}
function sessionUser(req){const m=String(req.headers.cookie||'').match(/(?:^|; )fleet_session=([^;]+)/);if(!m)return null;const s=sessions.get(m[1]);if(!s||s.expires<Date.now()){sessions.delete(m?.[1]);return null;}return s.userId;}
async function currentUser(req){const id=sessionUser(req);if(!id)return null;const users=await ensureUsers();return users.find(u=>u.id===id)||null;}
function safeUser(u){return u?{id:u.id,username:u.username,displayName:u.displayName,role:u.role,createdAt:u.createdAt}:null;}
async function requireAuth(req,res,next){const u=await currentUser(req);if(!u)return res.status(401).json({error:'Login required'});req.user=u;next();}
async function requireAdmin(req,res,next){const u=await currentUser(req);if(!u)return res.status(401).json({error:'Login required'});if(u.role!=='admin')return res.status(403).json({error:'Admin access required'});req.user=u;next();}

app.get('/api/auth/me',async(req,res)=>res.json({user:safeUser(await currentUser(req))}));
app.post('/api/auth/login',async(req,res)=>{const {username,password}=req.body||{};const users=await ensureUsers();const u=users.find(x=>x.username.toLowerCase()===String(username||'').trim().toLowerCase());if(!u||!verifyPassword(password||'',u))return res.status(401).json({error:'Invalid ID or password'});setSession(res,u);res.json({ok:true,user:safeUser(u)});});
app.post('/api/auth/logout',async(req,res)=>{const m=String(req.headers.cookie||'').match(/(?:^|; )fleet_session=([^;]+)/);clearSession(res,m?.[1]);res.json({ok:true});});

app.get('/api/admin/users',requireAdmin,async(req,res)=>{const users=await ensureUsers();res.json({users:users.map(safeUser)});});
app.post('/api/admin/users',requireAdmin,async(req,res)=>{const {username,password,displayName,role}=req.body||{};const un=String(username||'').trim();if(un.length<3||String(password||'').length<6)return res.status(400).json({error:'Username must be 3+ characters and password 6+ characters'});const users=await ensureUsers();if(users.some(u=>u.username.toLowerCase()===un.toLowerCase()))return res.status(409).json({error:'Username already exists'});const hp=hashPassword(password);const u={id:crypto.randomUUID(),username:un,displayName:String(displayName||un),role:role==='admin'?'admin':'viewer',...hp,createdAt:new Date().toISOString()};users.push(u);await writeJson(USERS,users);res.json({ok:true,user:safeUser(u)});});
app.delete('/api/admin/users/:id',requireAdmin,async(req,res)=>{const users=await ensureUsers();if(req.params.id===req.user.id)return res.status(400).json({error:'You cannot delete your own admin account'});const next=users.filter(u=>u.id!==req.params.id);if(next.length===users.length)return res.status(404).json({error:'User not found'});await writeJson(USERS,next);res.json({ok:true});});

app.get('/api/health',(req,res)=>res.json({ok:true,time:new Date().toISOString(),samsaraConfigured:samsaraConfigured(),knoxConfigured:knoxConfigured()}));
app.get('/api/assignments',async(req,res)=>res.json(await readJson(ASSIGNMENTS,[])));
app.post('/api/assignments',async(req,res)=>{const a=req.body||{};if(!a.imei)return res.status(400).json({error:'imei is required'});const all=await readJson(ASSIGNMENTS,[]);const i=all.findIndex(x=>x.imei===String(a.imei));const rec={imei:String(a.imei),serial:a.serial||'',driver:a.driver||'',truck:a.truck||'',samsaraVehicleId:a.samsaraVehicleId||'',samsaraVehicleName:a.samsaraVehicleName||'',notes:a.notes||'',updatedAt:new Date().toISOString()};if(i>=0)all[i]=rec;else all.push(rec);await writeJson(ASSIGNMENTS,all);res.json(rec);});
app.delete('/api/assignments/:imei',async(req,res)=>{const all=await readJson(ASSIGNMENTS,[]);await writeJson(ASSIGNMENTS,all.filter(x=>x.imei!==req.params.imei));res.json({ok:true});});

async function samsara(pathname){const r=await fetch('https://api.samsara.com'+pathname,{headers:{Authorization:`Bearer ${process.env.SAMSARA_API_TOKEN}`}});const d=await r.json();return {status:r.status,data:d};}
app.get('/api/samsara/vehicles',async(req,res)=>{if(!samsaraConfigured())return res.status(503).json({error:'Samsara API token not configured'});try{const x=await samsara('/fleet/vehicles?limit=512');res.status(x.status).json(x.data)}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/samsara/locations',async(req,res)=>{if(!samsaraConfigured())return res.status(503).json({error:'Samsara API token not configured'});try{const x=await samsara('/fleet/vehicles/locations');res.status(x.status).json(x.data)}catch(e){res.status(500).json({error:e.message})}});

let knoxToken={value:null,expires:0};
async function getKnoxToken(){if(knoxToken.value&&Date.now()<knoxToken.expires-60000)return knoxToken.value;const region=process.env.KNOX_REGION||'ap01';const body=new URLSearchParams({grant_type:'client_credentials',client_id:`${process.env.KNOX_CLIENT_ID}@${process.env.KNOX_TENANT_ID}`,client_secret:process.env.KNOX_CLIENT_SECRET});const r=await fetch(`https://${region}.manage.samsungknox.com/emm/oauth/token`,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});const d=await r.json();if(!r.ok)throw new Error(d.error_description||d.error||'Knox token request failed');knoxToken={value:d.access_token,expires:Date.now()+(Number(d.expires_in)||3600)*1000};return knoxToken.value;}
app.post('/api/knox/locations',async(req,res)=>{if(!knoxConfigured())return res.status(503).json({error:'Knox API credentials not configured'});const list=Array.isArray(req.body?.devices)?req.body.devices:[];if(!list.length)return res.json({locations:[]});try{const region=process.env.KNOX_REGION||'ap01';const token=await getKnoxToken();const out=[];for(const item of list.slice(0,100)){const mobileId=item.mobileId||item.imei;const body=new URLSearchParams();body.set('mobileId',mobileId);try{const r=await fetch(`https://${region}.manage.samsungknox.com/emm/oapi/device/selectDeviceLocation`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/x-www-form-urlencoded'},body});const d=await r.json();if(r.ok)out.push({imei:String(item.imei||mobileId),mobileId,...(d.data||d.result||d)});}catch{}}res.json({locations:out,checked:list.length,returned:out.length,serverTime:new Date().toISOString()});}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/knox/location',async(req,res)=>{if(!knoxConfigured())return res.status(503).json({error:'Knox API credentials not configured'});const {deviceId,mobileId}=req.body||{};if(!deviceId&&!mobileId)return res.status(400).json({error:'deviceId or mobileId required'});try{const region=process.env.KNOX_REGION||'ap01';const token=await getKnoxToken();const body=new URLSearchParams();if(deviceId)body.set('deviceId',deviceId);if(mobileId)body.set('mobileId',mobileId);const r=await fetch(`https://${region}.manage.samsungknox.com/emm/oapi/device/selectDeviceLocation`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/x-www-form-urlencoded'},body});const d=await r.json();if(!r.ok)return res.status(r.status).json(d);res.json(d)}catch(e){res.status(500).json({error:e.message})}});

await ensureUsers();
app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.listen(PORT,()=>console.log(`Knox × Samsara running on http://localhost:${PORT}`));
