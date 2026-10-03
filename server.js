require('dotenv').config();
const express=require('express');
const cors=require('cors');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');
const app=express();
app.set('trust proxy',true); app.use(cors()); app.use(express.json({limit:'2mb'}));
const PORT=Number(process.env.PORT||3000), D=path.join(__dirname,'data'); fs.mkdirSync(D,{recursive:true});
const files={users:'users.json',sessions:'sessions.json',posts:'posts.json',messages:'messages.json',keys:'keys.json',state:'server_state.json',banned_ips:'banned_ips.json'};
const read=(n,f)=>{try{return JSON.parse(fs.readFileSync(path.join(D,files[n]),'utf8'))}catch{return f}};
const write=(n,v)=>{const p=path.join(D,files[n]),t=p+'.tmp';fs.writeFileSync(t,JSON.stringify(v,null,2));fs.renameSync(t,p)};
for(const [n,f] of Object.entries({users:[],sessions:{},posts:[],messages:[],keys:[],state:{status:'normal',display:''},banned_ips:[]})) if(!fs.existsSync(path.join(D,files[n]))) write(n,f);
const users=()=>read('users',[]), sessions=()=>read('sessions',{}), posts=()=>read('posts',[]), messages=()=>read('messages',[]), keys=()=>read('keys',[]), state=()=>read('state',{status:'normal',display:''}), bannedIps=()=>read('banned_ips',[]);
const save=(n,v)=>write(n,v);
const pub=u=>{if(!u)return null; const {passwordHash,salt,...x}=u; return x};
const hash=p=>new Promise((res,rej)=>{const salt=crypto.randomBytes(16).toString('hex');crypto.scrypt(p,salt,64,(e,k)=>e?rej(e):res({salt,hash:k.toString('hex')}))});
const verify=(p,u)=>new Promise((res,rej)=>crypto.scrypt(p,u.salt,64,(e,k)=>{if(e)return rej(e);res(crypto.timingSafeEqual(Buffer.from(u.passwordHash,'hex'),k))}));
const token=()=>crypto.randomBytes(32).toString('hex');
function auth(req){const h=String(req.headers.authorization||'');if(!h.startsWith('Bearer '))return null;const id=sessions()[h.slice(7)];return users().find(u=>u.id===id)||null}
function requireAuth(req,res,next){const u=auth(req);if(!u)return res.status(401).json({error:'Đăng nhập trước.'});if(u.banned)return res.status(403).json({error:'Tài khoản đã bị BAN.'});req.user=u;next()}
function requireAdmin(req,res,next){requireAuth(req,res,()=>{if(req.user.role!=='admin')return res.status(403).json({error:'Admin only'});next()})}
function safeUrl(v){return !v||/^https?:\/\//i.test(v)}
function clientIp(req){return String(req.ip||req.headers['x-forwarded-for']||'').split(',')[0].trim().replace(/^::ffff:/,'')}
app.use((req,res,next)=>{const ip=clientIp(req); if(ip && bannedIps().includes(ip)) return res.status(403).json({error:'IP của bạn đã bị BAN.'}); next()});
app.get('/',(_,r)=>r.json({ok:true,service:'HOANG MOD BACKEND',status:'online'}));
app.get('/api/health',(_,r)=>r.json({ok:true,mode:'shared-node',database:'json'}));
app.post('/api/auth/register',async(req,res)=>{try{const username=String(req.body?.username||'').trim(),email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||'');if(!/^[A-Za-z0-9_.-]{3,12}$/.test(username))return res.status(400).json({error:'Tên tài khoản 3-12 ký tự.'});if(!/^\S+@\S+\.\S+$/.test(email))return res.status(400).json({error:'Email không hợp lệ.'});if(password.length<6)return res.status(400).json({error:'Mật khẩu tối thiểu 6 ký tự.'});let list=users();if(list.some(u=>u.email===email))return res.status(409).json({error:'Email đã tồn tại.'});if(list.some(u=>u.username.toLowerCase()===username.toLowerCase()))return res.status(409).json({error:'Tên tài khoản đã tồn tại.'});const h=await hash(password);const u={id:crypto.randomUUID(),username,email,passwordHash:h.hash,salt:h.salt,avatar:'',role:'user',banned:false,created_at:new Date().toISOString(),last_ip:clientIp(req)};list.push(u);save('users',list);const t=token();let ss=sessions();ss[t]=u.id;save('sessions',ss);res.json({token:t,user:pub(u)})}catch(e){console.error(e);res.status(500).json({error:'Không tạo được tài khoản.'})}});
app.post('/api/auth/login',async(req,res)=>{try{const email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||'');const list=users(),u=list.find(x=>x.email===email);if(!u||!(await verify(password,u)))return res.status(401).json({error:'Email hoặc mật khẩu không đúng.'});if(u.banned)return res.status(403).json({error:'Tài khoản đã bị BAN.'});u.last_ip=clientIp(req);save('users',list);const t=token(),ss=sessions();ss[t]=u.id;save('sessions',ss);res.json({token:t,user:pub(u)})}catch(e){console.error(e);res.status(500).json({error:'Không đăng nhập được.'})}});
app.get('/api/auth/me',requireAuth,(req,res)=>res.json({user:pub(req.user)}));
app.post('/api/auth/logout',(req,res)=>{const h=String(req.headers.authorization||'');if(h.startsWith('Bearer ')){const ss=sessions();delete ss[h.slice(7)];save('sessions',ss)}res.json({ok:true})});
app.post('/api/auth/password',requireAuth,async(req,res)=>{const p=String(req.body?.password||'');if(p.length<6)return res.status(400).json({error:'Mật khẩu tối thiểu 6 ký tự.'});const h=await hash(p),list=users(),u=list.find(x=>x.id===req.user.id);u.passwordHash=h.hash;u.salt=h.salt;save('users',list);res.json({ok:true})});
app.post('/api/profile/avatar',requireAuth,(req,res)=>{const avatar=String(req.body?.avatar||'');if(avatar.length>700000)return res.status(400).json({error:'Ảnh quá lớn.'});const list=users(),u=list.find(x=>x.id===req.user.id);u.avatar=avatar;save('users',list);res.json({user:pub(u)})});
app.get('/api/public/users',(_,res)=>res.json({users:users().map(pub).map(u=>({id:u.id,username:u.username,avatar:u.avatar||'',role:u.role||'user',banned:!!u.banned,created_at:u.created_at}))}));
app.get('/api/admin/users',requireAdmin,(_,res)=>res.json({users:users().map(pub)}));
app.post('/api/admin/users/:id/ban',requireAdmin,(req,res)=>{const list=users(),u=list.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Không tìm thấy user.'});if(u.id===req.user.id)return res.status(400).json({error:'Không thể tự BAN chính mình.'});u.banned=!!req.body?.banned;save('users',list);res.json({user:pub(u)})});
app.post('/api/admin/users/:id/role',requireAdmin,(req,res)=>{const role=String(req.body?.role||'user');if(!['user','admin','free_fire','free_fire_max'].includes(role))return res.status(400).json({error:'Role không hợp lệ.'});const list=users(),u=list.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Không tìm thấy user.'});u.role=role;save('users',list);res.json({user:pub(u)})});
app.post('/api/admin/ban-ip',requireAdmin,(req,res)=>{const ip=String(req.body?.ip||'').trim();if(!ip)return res.status(400).json({error:'Thiếu IP.'});let ips=bannedIps();if(!ips.includes(ip))ips.push(ip);save('banned_ips',ips);const list=users();list.forEach(u=>{if(u.last_ip===ip)u.banned=true});save('users',list);res.json({ok:true,ip})});
app.post('/api/admin/unban-ip',requireAdmin,(req,res)=>{const ip=String(req.body?.ip||'').trim();let ips=bannedIps().filter(x=>x!==ip);save('banned_ips',ips);res.json({ok:true,ip})});
app.get('/api/admin/banned-ips',requireAdmin,(_,res)=>res.json({ips:bannedIps()}));
app.get('/api/posts',(_,res)=>res.json({posts:posts().filter(p=>p.active!==false).sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at)))}));
app.post('/api/admin/posts',requireAdmin,(req,res)=>{const p=req.body||{};if(!p.title)return res.status(400).json({error:'Thiếu tiêu đề.'});if(!safeUrl(p.link))return res.status(400).json({error:'Link không hợp lệ.'});const list=posts();const x={id:crypto.randomUUID(),title:String(p.title).slice(0,80),tag:String(p.tag||'').slice(0,24),link:p.link||'',image_url:String(p.image_url||''),button_text:String(p.button_text||'👑 LẤY FREE (9999)').slice(0,30),hot:!!p.hot,active:true,created_by:req.user.id,created_at:new Date().toISOString()};list.push(x);save('posts',list);res.json({post:x})});
app.post('/api/admin/posts/:id/toggle',requireAdmin,(req,res)=>{const list=posts(),p=list.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Không tìm thấy bài.'});p.active=!!req.body?.active;save('posts',list);res.json({post:p})});
app.get('/api/chat',requireAuth,(_,res)=>res.json({messages:messages().slice(-200)}));
app.post('/api/chat',requireAuth,(req,res)=>{const m=String(req.body?.message||'').trim(),img=String(req.body?.image_url||'');if(m.length>500)return res.status(400).json({error:'Tin nhắn tối đa 500 ký tự.'});if(!m&&!img)return res.status(400).json({error:'Tin nhắn trống.'});const list=messages();const x={id:crypto.randomUUID(),user_id:req.user.id,username:req.user.username,avatar:req.user.avatar||'',message:m,image_url:img,created_at:new Date().toISOString()};list.push(x);save('messages',list.slice(-1000));res.json({message:x})});
app.get('/api/admin/chat',requireAdmin,(_,res)=>res.json({messages:messages().slice(-100)}));
app.post('/api/admin/broadcast',requireAdmin,(req,res)=>{const m=String(req.body?.message||'').trim();if(!m)return res.status(400).json({error:'Thông báo trống.'});const list=messages();list.push({id:crypto.randomUUID(),user_id:req.user.id,username:'Admin',avatar:req.user.avatar||'',message:'📢 '+m,image_url:'',created_at:new Date().toISOString()});save('messages',list.slice(-1000));res.json({ok:true})});
app.get('/api/keys',requireAdmin,(_,res)=>res.json({keys:keys()}));
app.post('/api/admin/keys',requireAdmin,(req,res)=>{const key=String(req.body?.key||'').trim(),date=String(req.body?.date||'');const limit=Math.max(1,Number(req.body?.limit||1));if(!key||!date)return res.status(400).json({error:'Thiếu KEY hoặc ngày.'});const list=keys();if(list.some(k=>k.key===key))return res.status(409).json({error:'KEY đã tồn tại.'});const x={id:crypto.randomUUID(),key,date,limit,used:0,active:true,created_at:new Date().toISOString()};list.push(x);save('keys',list);res.json({key:x})});
app.post('/api/admin/keys/:id/toggle',requireAdmin,(req,res)=>{const list=keys(),k=list.find(x=>x.id===req.params.id);if(!k)return res.status(404).json({error:'Không tìm thấy KEY.'});k.active=!k.active;save('keys',list);res.json({key:k})});
app.post('/api/claim-key',requireAuth,(req,res)=>{const d=new Date().toLocaleDateString('en-CA',{timeZone:'Asia/Ho_Chi_Minh'}),list=keys();if(state().status!=='normal')return res.status(503).json({error:'Server đang tạm đóng.'});for(const k of list){k.claims=Array.isArray(k.claims)?k.claims:[];if(k.claims.some(c=>c.user_id===req.user.id&&c.date===d))return res.status(409).json({error:'Bạn đã nhận KEY hôm nay.'})}const k=list.find(x=>x.date===d&&x.active&&x.used<x.limit);if(!k)return res.status(404).json({error:'Hôm nay chưa có KEY hoặc KEY đã hết lượt.'});k.claims=Array.isArray(k.claims)?k.claims:[];k.used++;k.claims.push({user_id:req.user.id,date:d,created_at:new Date().toISOString()});save('keys',list);res.json({key:k.key})});
app.get('/api/game/dino/leaderboard',(_,res)=>{const list=users().filter(u=>Number(u.dino_best||0)>0).map(u=>({username:u.username,score:Number(u.dino_best||0),role:u.role||'user'})).sort((a,b)=>b.score-a.score||a.username.localeCompare(b.username)).slice(0,50);res.json({scores:list})});
app.post('/api/game/dino/score',requireAuth,(req,res)=>{const score=Math.floor(Number(req.body?.score));if(!Number.isFinite(score)||score<0||score>100000)return res.status(400).json({error:'Điểm không hợp lệ.'});const list=users(),u=list.find(x=>x.id===req.user.id);if(score>Number(u.dino_best||0)){u.dino_best=score;u.dino_best_at=new Date().toISOString();save('users',list)}res.json({ok:true,best:Number(u.dino_best||0)})});
app.get('/api/state',(_,res)=>res.json(state()));
app.post('/api/admin/state',requireAdmin,(req,res)=>{const s={status:String(req.body?.status||'normal'),display:String(req.body?.display||'')};save('state',s);res.json(s)});
app.get('/api/stats',(_,res)=>{const us=users(),ks=keys();res.json({users:us.length,banned:us.filter(u=>u.banned).length,keys:ks.filter(k=>k.active).length,online:0})});
app.post('/api/admin/bootstrap',async(req,res)=>{const setup=String(req.headers['x-admin-setup']||'');if(!process.env.ADMIN_SETUP_TOKEN||setup!==process.env.ADMIN_SETUP_TOKEN)return res.status(403).json({error:'Không hợp lệ.'});const email=String(req.body?.email||process.env.ADMIN_EMAIL||'').trim().toLowerCase(),password=String(req.body?.password||process.env.ADMIN_PASSWORD||'');if(!email||password.length<6)return res.status(400).json({error:'Cấu hình ADMIN_EMAIL/ADMIN_PASSWORD.'});const list=users();let u=list.find(x=>x.email===email);if(u){u.role='admin';save('users',list);return res.json({ok:true,existing:true})}const h=await hash(password);u={id:crypto.randomUUID(),username:String(process.env.ADMIN_USERNAME||'admin').slice(0,12),email,passwordHash:h.hash,salt:h.salt,avatar:'',role:'admin',banned:false,created_at:new Date().toISOString(),last_ip:''};list.push(u);save('users',list);res.json({ok:true,existing:false})});
async function ensureAdminFromEnv(){
  const email=String(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
  const password=String(process.env.ADMIN_PASSWORD||'');
  if(!email || password.length<6) return;
  const list=users();
  let u=list.find(x=>x.email===email);
  if(u){ if(u.role!=='admin'){u.role='admin'; save('users',list);} return; }
  const h=await hash(password);
  u={id:crypto.randomUUID(),username:String(process.env.ADMIN_USERNAME||'admin').slice(0,12)||'admin',email,passwordHash:h.hash,salt:h.salt,avatar:'',role:'admin',banned:false,created_at:new Date().toISOString(),last_ip:'',dino_best:0};
  list.push(u); save('users',list); console.log('Admin account initialized from environment.');
}
app.use(express.static(__dirname));
app.use((req,res,next)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'API endpoint không tồn tại.'});res.sendFile(path.join(__dirname,'index.html'))});
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Internal server error'})});
ensureAdminFromEnv().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`HOANG MOD backend listening on 0.0.0.0:${PORT}`))).catch(e=>{console.error('Admin initialization failed',e);process.exit(1)});
