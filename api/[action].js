const c=require('crypto');
const _pf=new Intl.DateTimeFormat('en-u-ca-persian-nu-latn',{year:'numeric',month:'numeric',day:'numeric',timeZone:'UTC'});
const _toJ=t=>{const p=_pf.formatToParts(new Date(t)),g=k=>+p.find(x=>x.type===k).value;return[g('year'),g('month'),g('day')]};
const _p2=n=>String(n).padStart(2,'0');
function parseJ(s){s=String(s||'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).trim();let m=s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/),y,mo,d;if(m){d=+m[1];mo=+m[2];y=+m[3]}else if(m=s.match(/^(\d{4})\/(\d{1,2})\/(\d{1,2})$/)){y=+m[1];mo=+m[2];d=+m[3]}else return null;if(mo<1||mo>12||d<1||d>31)return null;const base=Date.UTC(y+621,2,21)+((mo<=6?(mo-1)*31:186+(mo-7)*30)+d-1)*864e5;for(let k=-2;k<=2;k++){const t=base+k*864e5,j=_toJ(t);if(j[0]===y&&j[1]===mo&&j[2]===d)return{t,s:_p2(d)+'/'+_p2(mo)+'/'+y}}return null}
const JEND=parseJ('29/12/1405');
const LBL={full_name:'نام و نام خانوادگی',father_name:'نام پدر',id_booklet_no:'شماره شناسنامه',national_id:'کد ملی',birth_date:'تاریخ تولد',birth_place:'محل تولد',marital_status:'وضعیت تأهل',military_status:'وضعیت خدمت',address:'نشانی',postal_code:'کد پستی',phone_landline:'شماره ثابت',mobile:'شماره همراه',bank_name:'نام بانک',bank_account:'شماره حساب (شبا)',promoter_code:'کد بازاریاب',expert_name:'نام کارشناس',supervisor_name:'نام ناظر قرارداد',activity_city:'شهر فعالیت',contract_number:'شماره قرارداد',contract_date:'تاریخ قرارداد'};
const REQ=Object.keys(LBL),UID=/^[\w-]{1,64}$/,KIND=['selfie','identity','bank','sana'],MIME={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','application/pdf':'pdf'};
const ST=()=>process.env.SUPABASE_URL+'/storage/v1';
async function st(p,o={}){const K=process.env.SUPABASE_SERVICE_ROLE_KEY;if(!K||!process.env.SUPABASE_URL)throw new Error('cfg');const r=await fetch(ST()+p,{...o,headers:{apikey:K,Authorization:'Bearer '+K,'Content-Type':'application/json',...(o.headers||{})}});const t=await r.text();if(!r.ok)throw new Error('st:'+r.status+' '+t.slice(0,150));return t?JSON.parse(t):{}}
async function all(q){let rows=[];for(let i=0;;i+=1000){let b;try{b=await sb(q,{headers:{Range:i+'-'+(i+999)}})}catch(e){if(String(e.message).includes('db:416'))break;throw e}rows=rows.concat(b);if(b.length<1000)break}return rows}
const FIELDS=['full_name','father_name','id_booklet_no','national_id','birth_date','birth_place','marital_status','military_status','address','postal_code','phone_landline','mobile','bank_name','bank_account','promoter_code','expert_name','supervisor_name','activity_city','contract_number','contract_date','contract_end_date','duration_days'];
const DUMMY='scrypt$AAAAAAAAAAAAAAAAAAAAAA==$'+Buffer.alloc(32).toString('base64');
const tries=new Map();
const sec=()=>process.env.SESSION_SECRET||'';
const hm=d=>c.createHmac('sha256',sec()).update(d).digest('base64url');
const sign=p=>{const d=Buffer.from(JSON.stringify(p)).toString('base64url');return d+'.'+hm(d)};
function verify(t){const[d,s]=String(t||'').split('.');if(!d||!s)return null;const a=Buffer.from(s),b=Buffer.from(hm(d));if(a.length!==b.length||!c.timingSafeEqual(a,b))return null;try{const p=JSON.parse(Buffer.from(d,'base64url'));return p.exp>Date.now()?p:null}catch{return null}}
const envUsers=()=>{try{return JSON.parse(process.env.AUTH_USERS||'[]')}catch{return[]}};
const safeRole=r=>['admin','supervisor','specialist'].includes(r)?r:'specialist';
const hashPw=pw=>{const salt=c.randomBytes(16);return 'scrypt
function checkPw(pw,h){const[t,s,x]=String(h).split('$');if(t!=='scrypt')return false;const d=c.scryptSync(pw,Buffer.from(s,'base64'),32),e=Buffer.from(x,'base64');return e.length===d.length&&c.timingSafeEqual(d,e)}
async function sess(req){
 const k=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('sid='));
 const p=k&&verify(k.slice(4)); if(!p)return null;
 const us=await users(),u=us.find(x=>(x.username||x.u)===p.u);
 return u&&u.active!==false?{u:u.username||u.u,r:safeRole(u.role||u.r),city:u.city||'',name:u.display_name||u.n||u.username||u.u,permissions:u.permissions||{}}:null
}
async function sb(path,o={}){const K=process.env.SUPABASE_SERVICE_ROLE_KEY,U=process.env.SUPABASE_URL;if(!K||!U)throw new Error('cfg');const r=await fetch(U+'/rest/v1/'+path,{...o,headers:{apikey:K,Authorization:'Bearer '+K,'Content-Type':'application/json','Range-Unit':'items',Prefer:'return=representation',...(o.headers||{})}});const t=await r.text();if(!r.ok)throw new Error('db:'+r.status+' '+t.slice(0,200));return t?JSON.parse(t):[]}
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 const a=req.query.action,m=req.method,send=(s,o)=>res.status(s).json(o);
 try{
  if(sec().length<32)return send(500,{error:'تنظیمات سرور ناقص است (SESSION_SECRET)'});
  if(m!=='GET'&&!String(req.headers['content-type']||'').includes('application/json'))return send(415,{error:'درخواست نامعتبر'});
  if(a==='login'&&m==='POST'){
   const ip=String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||'x';
   const t=tries.get(ip)||{n:0,t:Date.now()};if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}
   if(t.n>=10)return send(429,{error:'تلاش ناموفق زیاد بود؛ چند دقیقه بعد دوباره امتحان کنید'});
   const b=req.body||{},un=String(b.username||'').trim().toLowerCase(),us=await users(),u=us.find(x=>(x.username||x.u)===un);
   if(!(checkPw(String(b.password||''),u?(u.password_hash||u.h):DUMMY)&&u&&u.active!==false)){t.n++;tries.set(ip,t);return send(401,{error:'نام کاربری یا کلمه عبور اشتباه است'})}
   tries.delete(ip);
   res.setHeader('Set-Cookie','sid='+sign({u:u.u,exp:Date.now()+6048e5})+'; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800');
   return send(200,{username:u.u,role:u.r});
  }
  if(a==='logout'&&m==='POST'){res.setHeader('Set-Cookie','sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return send(200,{ok:true})}
  const s=await sess(req);if(!s)return send(401,{error:'نیاز به ورود'});
  const admin=s.r==='admin',manager=admin||s.r==='supervisor',id=String(req.query.id||'');
  const city=s.city||'';
  const canSeeCity=x=>manager||!city||String(x||'')===city;
  if(a==='me'&&m==='GET')return send(200,{username:s.u,role:s.r});
  if(a==='users'){
   if(!admin)return send(403,{error:'فقط مدیر می‌تواند کاربران را مدیریت کند'});
   if(m==='GET'){const us=await users();return send(200,{users:us.map(x=>({id:x.id,username:x.username||x.u,name:x.display_name||x.n||x.username||x.u,city:x.city||'',role:safeRole(x.role||x.r),active:x.active!==false,permissions:x.permissions||{}}))})}
   if(m==='POST'){
    const b=req.body||{},un=String(b.username||'').trim().toLowerCase(),pw=String(b.password||'');
    if(!/^[a-z0-9._-]{3,64}$/.test(un))return send(400,{error:'نام کاربری فقط حروف انگلیسی، عدد، نقطه، خط تیره و زیرخط باشد'});
    if(pw.length<8)return send(400,{error:'کلمه عبور حداقل ۸ کاراکتر باشد'});
    if(!String(b.name||'').trim())return send(400,{error:'نام کاربر الزامی است'});
    if(!['admin','supervisor','specialist'].includes(b.role))return send(400,{error:'نقش نامعتبر است'});
    const city0=String(b.city||'').trim();
    if(b.role!=='admin'&&!city0)return send(400,{error:'شهر برای این نقش الزامی است'});
    try{const r=await sb('app_users',{method:'POST',body:JSON.stringify({username:un,password_hash:hashPw(pw),display_name:String(b.name).trim().slice(0,120),city:city0.slice(0,80),role:safeRole(b.role),active:b.active!==false,permissions:b.permissions||{},updated_at:new Date().toISOString()})});return send(200,{ok:true,id:r[0]&&r[0].id})}
    catch(e){return send(400,{error:String(e.message).includes('db:409')?'این نام کاربری قبلاً ثبت شده است':'ذخیره کاربر ناموفق بود: '+String(e.message).slice(0,180)})}
   }
   if(m==='PATCH'){
    if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});
    const old=(await sb('app_users?select=id,username,password_hash& id=eq.'+encodeURIComponent(id)))[0];
    if(!old)return send(404,{error:'کاربر یافت نشد'});
    const b=req.body||{},o={};
    if(b.name!=null)o.display_name=String(b.name).trim().slice(0,120);
    if(b.city!=null)o.city=String(b.city).trim().slice(0,80);
    if(b.role!=null){if(!['admin','supervisor','specialist'].includes(b.role))return send(400,{error:'نقش نامعتبر است'});o.role=b.role}
    if(b.active!=null)o.active=!!b.active;
    if(b.permissions!=null)o.permissions=b.permissions||{};
    if(b.password!=null&&String(b.password).length){if(String(b.password).length<8)return send(400,{error:'کلمه عبور حداقل ۸ کاراکتر باشد'});o.password_hash=hashPw(b.password)}
    o.updated_at=new Date().toISOString();
    if(old.username===s.u&&o.active===false)return send(400,{error:'نمی‌توانید حساب خودتان را غیرفعال کنید'});
    await sb('app_users?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(o)});return send(200,{ok:true})
   }
   if(m==='DELETE'){
    if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});
    const old=(await sb('app_users?select=id,username,role&id=eq.'+encodeURIComponent(id)))[0];
    if(!old)return send(404,{error:'کاربر یافت نشد'});
    if(old.username===s.u)return send(400,{error:'نمی‌توانید حساب خودتان را حذف کنید'});
    if(old.role==='admin'&& (await sb('app_users?select=id&role=eq.admin&active=eq.true')).length<=1)return send(400,{error:'آخرین مدیر را نمی‌توان حذف کرد'});
    await sb('app_users?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})
   }
  }
  if(a==='template'&&m==='GET'){const T=require('./_tpl.js'),t=req.query.type;return T[t]&&(t==='cab'||t==='box')?send(200,{b64:T[t]}):send(400,{error:'نوع نامعتبر'})}
  if(a==='promoters'){
   if(m==='GET'){const q=manager?'contract_promoters?select=*&order=full_name':'contract_promoters?select=*&activity_city=eq.'+encodeURIComponent(city)+'&order=full_name';const rows=await all(q);const ids=rows.map(r=>r.id).filter(Boolean);const fl=ids.length?await all('promoter_files?select=promoter_id,kind&order=id'):[];const mp={};fl.forEach(f=>(mp[f.promoter_id]=mp[f.promoter_id]||[]).push(f.kind));rows.forEach(r=>r.docs=mp[r.id]||[]);return send(200,{rows})}
   if(m==='POST'||m==='PATCH'){const b=req.body||{},o={};FIELDS.forEach(k=>o[k]=b[k]==null?'':String(b[k]).trim().slice(0,500));
    if(!manager){o.activity_city=city;o.expert_name=s.name;}
    for(const k of REQ)if(!o[k])return send(400,{error:'فیلد «'+LBL[k]+'» الزامی است'});
    const cd=parseJ(o.contract_date),bd=parseJ(o.birth_date);if(!cd||!bd)return send(400,{error:'تاریخ نامعتبر است؛ قالب صحیح مانند 10/10/1405'});
    const dur=Math.round((JEND.t-cd.t)/864e5);if(dur<0)return send(400,{error:'تاریخ قرارداد نباید بعد از 29/12/1405 باشد'});
    o.contract_date=cd.s;o.birth_date=bd.s;o.contract_end_date=JEND.s;o.duration_days=String(dur);o.updated_at=new Date().toISOString();
    if(m==='POST'){const r=await sb('contract_promoters',{method:'POST',body:JSON.stringify(o)});return send(200,{ok:true,id:r[0]&&r[0].id})}
    if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const old=(await sb('contract_promoters?select=activity_city&id=eq.'+encodeURIComponent(id)))[0];if(!old)return send(404,{error:'بازاریاب یافت نشد'});if(!canSeeCity(old.activity_city))return send(403,{error:'به اطلاعات این شهر دسترسی ندارید'});await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(o)});return send(200,{ok:true,id})}
   if(m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});
    for(const f of await sb('promoter_files?select=storage_path&promoter_id=eq.'+encodeURIComponent(id)))await st('/object/promoter-docs/'+f.storage_path,{method:'DELETE'}).catch(()=>{});
    await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  }
  if(a==='files'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});return send(200,{files:await sb('promoter_files?select=id,kind,file_name,size_bytes,uploaded_by,uploaded_at&promoter_id=eq.'+encodeURIComponent(id))})}
  if(a==='upload'&&m==='POST'){const b=req.body||{},ext=MIME[b.mime];if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!ext||!(b.size>0&&b.size<=10485760))return send(400,{error:'نوع یا حجم فایل مجاز نیست (تصویر یا PDF تا ۱۰ مگابایت)'});
   const path=b.promoter_id+'/'+b.kind+'-'+Date.now()+'-'+c.randomBytes(4).toString('hex')+'.'+ext,j=await st('/object/upload/sign/promoter-docs/'+path,{method:'POST'}),u=j.url||j.signedUrl;return send(200,{path,url:/^http/.test(u)?u:ST()+u})}
  if(a==='fileok'&&m==='POST'){const b=req.body||{};if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!String(b.path).startsWith(b.promoter_id+'/'+b.kind+'-'))return send(400,{error:'درخواست نامعتبر'});
   const old=await sb('promoter_files?select=storage_path&promoter_id=eq.'+b.promoter_id+'&kind=eq.'+b.kind);
   await sb('promoter_files?on_conflict=promoter_id,kind',{method:'POST',headers:{Prefer:'resolution=merge-duplicates,return=minimal'},body:JSON.stringify({promoter_id:b.promoter_id,kind:b.kind,file_name:String(b.file_name||'').slice(0,200),storage_path:b.path,mime_type:b.mime,size_bytes:b.size,uploaded_by:s.u,uploaded_at:new Date().toISOString()})});
   for(const f of old)if(f.storage_path!==b.path)await st('/object/promoter-docs/'+f.storage_path,{method:'DELETE'}).catch(()=>{});return send(200,{ok:true})}
  if(a==='fileview'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path&id=eq.'+encodeURIComponent(id)))[0];if(!row)return send(404,{error:'یافت نشد'});const j=await st('/object/sign/promoter-docs/'+row.storage_path,{method:'POST',body:JSON.stringify({expiresIn:60})});return send(200,{url:ST()+j.signedURL})}
  if(a==='filedel'&&m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path&id=eq.'+encodeURIComponent(id)))[0];if(row)await st('/object/promoter-docs/'+row.storage_path,{method:'DELETE'}).catch(()=>{});await sb('promoter_files?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  return send(404,{error:'یافت نشد'});
 }catch(e){return send(500,{error:e.message==='cfg'?'تنظیمات سرور ناقص است (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)':'خطا در ارتباط با پایگاه داده: '+String(e.message).slice(0,200)})}
};
+salt.toString('base64')+'
function checkPw(pw,h){const[t,s,x]=String(h).split('$');if(t!=='scrypt')return false;const d=c.scryptSync(pw,Buffer.from(s,'base64'),32),e=Buffer.from(x,'base64');return e.length===d.length&&c.timingSafeEqual(d,e)}
function sess(req){const k=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('sid='));const p=k&&verify(k.slice(4));const u=p&&users().find(x=>x.u===p.u);return u?{u:u.u,r:u.r}:null}
async function sb(path,o={}){const K=process.env.SUPABASE_SERVICE_ROLE_KEY,U=process.env.SUPABASE_URL;if(!K||!U)throw new Error('cfg');const r=await fetch(U+'/rest/v1/'+path,{...o,headers:{apikey:K,Authorization:'Bearer '+K,'Content-Type':'application/json','Range-Unit':'items',Prefer:'return=representation',...(o.headers||{})}});const t=await r.text();if(!r.ok)throw new Error('db:'+r.status+' '+t.slice(0,200));return t?JSON.parse(t):[]}
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 const a=req.query.action,m=req.method,send=(s,o)=>res.status(s).json(o);
 try{
  if(sec().length<32)return send(500,{error:'تنظیمات سرور ناقص است (SESSION_SECRET)'});
  if(m!=='GET'&&!String(req.headers['content-type']||'').includes('application/json'))return send(415,{error:'درخواست نامعتبر'});
  if(a==='login'&&m==='POST'){
   const ip=String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||'x';
   const t=tries.get(ip)||{n:0,t:Date.now()};if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}
   if(t.n>=10)return send(429,{error:'تلاش ناموفق زیاد بود؛ چند دقیقه بعد دوباره امتحان کنید'});
   const b=req.body||{},un=String(b.username||'').trim().toLowerCase(),u=users().find(x=>x.u===un);
   if(!(checkPw(String(b.password||''),u?u.h:DUMMY)&&u)){t.n++;tries.set(ip,t);return send(401,{error:'نام کاربری یا کلمه عبور اشتباه است'})}
   tries.delete(ip);
   res.setHeader('Set-Cookie','sid='+sign({u:u.u,exp:Date.now()+6048e5})+'; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800');
   return send(200,{username:u.u,role:u.r});
  }
  if(a==='logout'&&m==='POST'){res.setHeader('Set-Cookie','sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return send(200,{ok:true})}
  const s=sess(req);if(!s)return send(401,{error:'نیاز به ورود'});
  const admin=s.r==='admin',id=String(req.query.id||'');
  if(a==='me'&&m==='GET')return send(200,{username:s.u,role:s.r});
  if(a==='users'&&m==='GET')return admin?send(200,{users:users().map(x=>({username:x.u,role:x.r}))}):send(403,{error:'دسترسی ندارید'});
  if(a==='template'&&m==='GET'){const T=require('./_tpl.js'),t=req.query.type;return T[t]&&(t==='cab'||t==='box')?send(200,{b64:T[t]}):send(400,{error:'نوع نامعتبر'})}
  if(a==='promoters'){
   if(m==='GET'){const[rows,fl]=await Promise.all([all('contract_promoters?select=*&order=full_name'),all('promoter_files?select=promoter_id,kind&order=id')]);const mp={};fl.forEach(f=>(mp[f.promoter_id]=mp[f.promoter_id]||[]).push(f.kind));rows.forEach(r=>r.docs=mp[r.id]||[]);return send(200,{rows})}
   if(m==='POST'||m==='PATCH'){const b=req.body||{},o={};FIELDS.forEach(k=>o[k]=b[k]==null?'':String(b[k]).trim().slice(0,500));
    for(const k of REQ)if(!o[k])return send(400,{error:'فیلد «'+LBL[k]+'» الزامی است'});
    const cd=parseJ(o.contract_date),bd=parseJ(o.birth_date);if(!cd||!bd)return send(400,{error:'تاریخ نامعتبر است؛ قالب صحیح مانند 10/10/1405'});
    const dur=Math.round((JEND.t-cd.t)/864e5);if(dur<0)return send(400,{error:'تاریخ قرارداد نباید بعد از 29/12/1405 باشد'});
    o.contract_date=cd.s;o.birth_date=bd.s;o.contract_end_date=JEND.s;o.duration_days=String(dur);o.updated_at=new Date().toISOString();
    if(m==='POST'){const r=await sb('contract_promoters',{method:'POST',body:JSON.stringify(o)});return send(200,{ok:true,id:r[0]&&r[0].id})}
    if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(o)});return send(200,{ok:true,id})}
   if(m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});
    for(const f of await sb('promoter_files?select=storage_path&promoter_id=eq.'+encodeURIComponent(id)))await st('/object/promoter-docs/'+f.storage_path,{method:'DELETE'}).catch(()=>{});
    await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  }
  if(a==='files'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});return send(200,{files:await sb('promoter_files?select=id,kind,file_name,size_bytes,uploaded_by,uploaded_at&promoter_id=eq.'+encodeURIComponent(id))})}
  if(a==='upload'&&m==='POST'){const b=req.body||{},ext=MIME[b.mime];if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!ext||!(b.size>0&&b.size<=10485760))return send(400,{error:'نوع یا حجم فایل مجاز نیست (تصویر یا PDF تا ۱۰ مگابایت)'});
   const path=b.promoter_id+'/'+b.kind+'-'+Date.now()+'-'+c.randomBytes(4).toString('hex')+'.'+ext,j=await st('/object/upload/sign/promoter-docs/'+path,{method:'POST'}),u=j.url||j.signedUrl;return send(200,{path,url:/^http/.test(u)?u:ST()+u})}
  if(a==='fileok'&&m==='POST'){const b=req.body||{};if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!String(b.path).startsWith(b.promoter_id+'/'+b.kind+'-'))return send(400,{error:'درخواست نامعتبر'});
   const old=await sb('promoter_files?select=storage_path&promoter_id=eq.'+b.promoter_id+'&kind=eq.'+b.kind);
   await sb('promoter_files?on_conflict=promoter_id,kind',{method:'POST',headers:{Prefer:'resolution=merge-duplicates,return=minimal'},body:JSON.stringify({promoter_id:b.promoter_id,kind:b.kind,file_name:String(b.file_name||'').slice(0,200),storage_path:b.path,mime_type:b.mime,size_bytes:b.size,uploaded_by:s.u,uploaded_at:new Date().toISOString()})});
   for(const f of old)if(f.storage_path!==b.path)await st('/object/promoter-docs/'+f.storage_path,{method:'DELETE'}).catch(()=>{});return send(200,{ok:true})}
  if(a==='fileview'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path&id=eq.'+encodeURIComponent(id)))[0];if(!row)return send(404,{error:'یافت نشد'});const j=await st('/object/sign/promoter-docs/'+row.storage_path,{method:'POST',body:JSON.stringify({expiresIn:60})});return send(200,{url:ST()+j.signedURL})}
  if(a==='filedel'&&m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path&id=eq.'+encodeURIComponent(id)))[0];if(row)await st('/object/promoter-docs/'+row.storage_path,{method:'DELETE'}).catch(()=>{});await sb('promoter_files?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  return send(404,{error:'یافت نشد'});
 }catch(e){return send(500,{error:e.message==='cfg'?'تنظیمات سرور ناقص است (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)':'خطا در ارتباط با پایگاه داده: '+String(e.message).slice(0,200)})}
};
+c.scryptSync(String(pw),salt,32).toString('base64')};
async function users(){
  try{
    const r=await sb('app_users?select=id,username,password_hash,display_name,city,role,active,permissions,created_at,updated_at&order=display_name');
    return r.length?r:envUsers().map(x=>({id:null,username:x.u,password_hash:x.h,display_name:x.n||x.u,city:x.city||'',role:safeRole(x.r),active:x.active!==false,permissions:x.permissions||{}}));
  }catch(e){return envUsers().map(x=>({id:null,username:x.u,password_hash:x.h,display_name:x.n||x.u,city:x.city||'',role:safeRole(x.r),active:x.active!==false,permissions:x.permissions||{}}))}
}
function checkPw(pw,h){const[t,s,x]=String(h).split('$');if(t!=='scrypt')return false;const d=c.scryptSync(pw,Buffer.from(s,'base64'),32),e=Buffer.from(x,'base64');return e.length===d.length&&c.timingSafeEqual(d,e)}
function sess(req){const k=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('sid='));const p=k&&verify(k.slice(4));const u=p&&users().find(x=>x.u===p.u);return u?{u:u.u,r:u.r}:null}
async function sb(path,o={}){const K=process.env.SUPABASE_SERVICE_ROLE_KEY,U=process.env.SUPABASE_URL;if(!K||!U)throw new Error('cfg');const r=await fetch(U+'/rest/v1/'+path,{...o,headers:{apikey:K,Authorization:'Bearer '+K,'Content-Type':'application/json','Range-Unit':'items',Prefer:'return=representation',...(o.headers||{})}});const t=await r.text();if(!r.ok)throw new Error('db:'+r.status+' '+t.slice(0,200));return t?JSON.parse(t):[]}
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 const a=req.query.action,m=req.method,send=(s,o)=>res.status(s).json(o);
 try{
  if(sec().length<32)return send(500,{error:'تنظیمات سرور ناقص است (SESSION_SECRET)'});
  if(m!=='GET'&&!String(req.headers['content-type']||'').includes('application/json'))return send(415,{error:'درخواست نامعتبر'});
  if(a==='login'&&m==='POST'){
   const ip=String(req.headers['x-forwarded-for']||'').split(',')[0].trim()||'x';
   const t=tries.get(ip)||{n:0,t:Date.now()};if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}
   if(t.n>=10)return send(429,{error:'تلاش ناموفق زیاد بود؛ چند دقیقه بعد دوباره امتحان کنید'});
   const b=req.body||{},un=String(b.username||'').trim().toLowerCase(),u=users().find(x=>x.u===un);
   if(!(checkPw(String(b.password||''),u?u.h:DUMMY)&&u)){t.n++;tries.set(ip,t);return send(401,{error:'نام کاربری یا کلمه عبور اشتباه است'})}
   tries.delete(ip);
   res.setHeader('Set-Cookie','sid='+sign({u:u.u,exp:Date.now()+6048e5})+'; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800');
   return send(200,{username:u.u,role:u.r});
  }
  if(a==='logout'&&m==='POST'){res.setHeader('Set-Cookie','sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return send(200,{ok:true})}
  const s=sess(req);if(!s)return send(401,{error:'نیاز به ورود'});
  const admin=s.r==='admin',id=String(req.query.id||'');
  if(a==='me'&&m==='GET')return send(200,{username:s.u,role:s.r});
  if(a==='users'&&m==='GET')return admin?send(200,{users:users().map(x=>({username:x.u,role:x.r}))}):send(403,{error:'دسترسی ندارید'});
  if(a==='template'&&m==='GET'){const T=require('./_tpl.js'),t=req.query.type;return T[t]&&(t==='cab'||t==='box')?send(200,{b64:T[t]}):send(400,{error:'نوع نامعتبر'})}
  if(a==='promoters'){
   if(m==='GET'){const[rows,fl]=await Promise.all([all('contract_promoters?select=*&order=full_name'),all('promoter_files?select=promoter_id,kind&order=id')]);const mp={};fl.forEach(f=>(mp[f.promoter_id]=mp[f.promoter_id]||[]).push(f.kind));rows.forEach(r=>r.docs=mp[r.id]||[]);return send(200,{rows})}
   if(m==='POST'||m==='PATCH'){const b=req.body||{},o={};FIELDS.forEach(k=>o[k]=b[k]==null?'':String(b[k]).trim().slice(0,500));
    for(const k of REQ)if(!o[k])return send(400,{error:'فیلد «'+LBL[k]+'» الزامی است'});
    const cd=parseJ(o.contract_date),bd=parseJ(o.birth_date);if(!cd||!bd)return send(400,{error:'تاریخ نامعتبر است؛ قالب صحیح مانند 10/10/1405'});
    const dur=Math.round((JEND.t-cd.t)/864e5);if(dur<0)return send(400,{error:'تاریخ قرارداد نباید بعد از 29/12/1405 باشد'});
    o.contract_date=cd.s;o.birth_date=bd.s;o.contract_end_date=JEND.s;o.duration_days=String(dur);o.updated_at=new Date().toISOString();
    if(m==='POST'){const r=await sb('contract_promoters',{method:'POST',body:JSON.stringify(o)});return send(200,{ok:true,id:r[0]&&r[0].id})}
    if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(o)});return send(200,{ok:true,id})}
   if(m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});
    for(const f of await sb('promoter_files?select=storage_path&promoter_id=eq.'+encodeURIComponent(id)))await st('/object/promoter-docs/'+f.storage_path,{method:'DELETE'}).catch(()=>{});
    await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  }
  if(a==='files'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});return send(200,{files:await sb('promoter_files?select=id,kind,file_name,size_bytes,uploaded_by,uploaded_at&promoter_id=eq.'+encodeURIComponent(id))})}
  if(a==='upload'&&m==='POST'){const b=req.body||{},ext=MIME[b.mime];if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!ext||!(b.size>0&&b.size<=10485760))return send(400,{error:'نوع یا حجم فایل مجاز نیست (تصویر یا PDF تا ۱۰ مگابایت)'});
   const path=b.promoter_id+'/'+b.kind+'-'+Date.now()+'-'+c.randomBytes(4).toString('hex')+'.'+ext,j=await st('/object/upload/sign/promoter-docs/'+path,{method:'POST'}),u=j.url||j.signedUrl;return send(200,{path,url:/^http/.test(u)?u:ST()+u})}
  if(a==='fileok'&&m==='POST'){const b=req.body||{};if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!String(b.path).startsWith(b.promoter_id+'/'+b.kind+'-'))return send(400,{error:'درخواست نامعتبر'});
   const old=await sb('promoter_files?select=storage_path&promoter_id=eq.'+b.promoter_id+'&kind=eq.'+b.kind);
   await sb('promoter_files?on_conflict=promoter_id,kind',{method:'POST',headers:{Prefer:'resolution=merge-duplicates,return=minimal'},body:JSON.stringify({promoter_id:b.promoter_id,kind:b.kind,file_name:String(b.file_name||'').slice(0,200),storage_path:b.path,mime_type:b.mime,size_bytes:b.size,uploaded_by:s.u,uploaded_at:new Date().toISOString()})});
   for(const f of old)if(f.storage_path!==b.path)await st('/object/promoter-docs/'+f.storage_path,{method:'DELETE'}).catch(()=>{});return send(200,{ok:true})}
  if(a==='fileview'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path&id=eq.'+encodeURIComponent(id)))[0];if(!row)return send(404,{error:'یافت نشد'});const j=await st('/object/sign/promoter-docs/'+row.storage_path,{method:'POST',body:JSON.stringify({expiresIn:60})});return send(200,{url:ST()+j.signedURL})}
  if(a==='filedel'&&m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path&id=eq.'+encodeURIComponent(id)))[0];if(row)await st('/object/promoter-docs/'+row.storage_path,{method:'DELETE'}).catch(()=>{});await sb('promoter_files?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  return send(404,{error:'یافت نشد'});
 }catch(e){return send(500,{error:e.message==='cfg'?'تنظیمات سرور ناقص است (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)':'خطا در ارتباط با پایگاه داده: '+String(e.message).slice(0,200)})}
};
