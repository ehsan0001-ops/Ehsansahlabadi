const c=require('crypto');
const _pf=new Intl.DateTimeFormat('en-u-ca-persian-nu-latn',{year:'numeric',month:'numeric',day:'numeric',timeZone:'UTC'});
const _toJ=t=>{const p=_pf.formatToParts(new Date(t)),g=k=>+p.find(x=>x.type===k).value;return[g('year'),g('month'),g('day')]};
const _p2=n=>String(n).padStart(2,'0');
function parseJ(s){s=String(s||'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).trim();let m=s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/),y,mo,d;if(m){d=+m[1];mo=+m[2];y=+m[3]}else if(m=s.match(/^(\d{4})\/(\d{1,2})\/(\d{1,2})$/)){y=+m[1];mo=+m[2];d=+m[3]}else return null;if(mo<1||mo>12||d<1||d>31)return null;const base=Date.UTC(y+621,2,21)+((mo<=6?(mo-1)*31:186+(mo-7)*30)+d-1)*864e5;for(let k=-2;k<=2;k++){const t=base+k*864e5,j=_toJ(t);if(j[0]===y&&j[1]===mo&&j[2]===d)return{t,s:_p2(d)+'/'+_p2(mo)+'/'+y}}return null}
const JEND=parseJ('29/12/1405');
const ROLEMAP={admin:'super_admin',user:'manager'},ROLES=['super_admin','manager','supervisor','specialist','viewer'],CITIES=['اراک','قزوین','قم'];
const PERM={super_admin:['view','write','upload','delfile','users','template'],manager:['view','write','upload','delfile','template'],supervisor:['view','write','upload','template'],specialist:['view','write','upload','template'],viewer:['view']};
const can=(s,a)=>(PERM[s.r]||[]).includes(a);
const hashPw=pw=>{const sl=c.randomBytes(16);return 'scrypt$'+sl.toString('base64')+'$'+c.scryptSync(pw,sl,32).toString('base64')};
const LBL={full_name:'نام و نام خانوادگی',father_name:'نام پدر',id_booklet_no:'شماره شناسنامه',national_id:'کد ملی',birth_date:'تاریخ تولد',birth_place:'محل تولد',marital_status:'وضعیت تأهل',military_status:'وضعیت خدمت',address:'نشانی',postal_code:'کد پستی',phone_landline:'شماره ثابت',mobile:'شماره همراه',bank_name:'نام بانک',bank_account:'شماره حساب (شبا)',promoter_code:'کد بازاریاب',expert_name:'نام کارشناس',supervisor_name:'نام ناظر قرارداد',activity_city:'شهر فعالیت',contract_number:'شماره قرارداد',contract_date:'تاریخ قرارداد'};
const EXP={'احسان سهل آبادی':'اراک','محمد سهل آبادی':'اراک','حسن آقاجان زاده':'قزوین','صمد شمسینی':'قزوین','علیرضا زین العابدینی':'قم'},CODE={'اراک':'13','قزوین':'12','قم':'6'};
const dg=s=>String(s||'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d));
const REQ=Object.keys(LBL).filter(k=>!['contract_number','promoter_code','activity_city'].includes(k)),UID=/^[\w-]{1,64}$/,KIND=['selfie','identity','bank','sana'],MIME={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','application/pdf':'pdf'};
const ST=()=>process.env.SUPABASE_URL+'/storage/v1';
async function st(p,o={}){const K=process.env.SUPABASE_SERVICE_ROLE_KEY;if(!K||!process.env.SUPABASE_URL)throw new Error('cfg');const r=await fetch(ST()+p,{...o,headers:{apikey:K,Authorization:'Bearer '+K,...(o.body?{'Content-Type':'application/json'}:{}),...(o.headers||{})}});const t=await r.text();if(!r.ok)throw new Error('st:'+r.status+' '+t.slice(0,150));return t?JSON.parse(t):{}}
const rm=a=>st('/object/promoter-docs',{method:'DELETE',body:JSON.stringify({prefixes:a})});
async function chk(s,pid){if(s.r!=='specialist')return true;const r=(await sb('contract_promoters?select=expert_name&id=eq.'+encodeURIComponent(pid)))[0];return !!s.expert&&!!r&&r.expert_name===s.expert}
function uval(b,isNew,own){const o={},un=String(b.username||'').trim().toLowerCase();
 if(isNew||b.username!=null){if(!/^[a-z0-9._-]{3,32}$/.test(un))return{err:'نام کاربری باید ۳ تا ۳۲ حرف انگلیسی کوچک، عدد یا . _ - باشد'};o.username=un}
 if(isNew||b.full_name!=null){if(!String(b.full_name||'').trim())return{err:'نام و نام خانوادگی الزامی است'};o.full_name=String(b.full_name).trim().slice(0,100)}
 if(isNew||b.role!=null){if(!ROLES.includes(b.role))return{err:'نقش نامعتبر است'};o.role=b.role}
 const role=o.role||own&&own.role;
 if(b.city!=null){if(b.city&&!CITIES.includes(b.city))return{err:'شهر نامعتبر است'};o.city=b.city||null}
 if(b.title!=null)o.title=String(b.title).trim().slice(0,100)||null;
 if(b.expert_name!=null||isNew){const e=String(b.expert_name||'');if(e&&!EXP[e])return{err:'کارشناس نامعتبر است'};o.expert_name=e||null}
 if(role==='specialist'&&!(o.expert_name!==undefined?o.expert_name:own&&own.expert_name))return{err:'برای نقش کارشناس، انتخاب کارشناس الزامی است'};
 if(b.is_active!=null)o.is_active=!!b.is_active;
 if(isNew||b.password){if(String(b.password||'').length<8)return{err:'کلمه عبور باید حداقل ۸ کاراکتر باشد'};o.password_hash=hashPw(String(b.password))}
 o.updated_at=new Date().toISOString();return{o}}
async function all(q){let rows=[];for(let i=0;;i+=1000){let b;try{b=await sb(q,{headers:{Range:i+'-'+(i+999)}})}catch(e){if(String(e.message).includes('db:416'))break;throw e}if(!Array.isArray(b))break;rows=rows.concat(b);if(b.length<1000)break}return rows}
const FIELDS=['promoter_kind','full_name','father_name','id_booklet_no','national_id','birth_date','birth_place','marital_status','military_status','address','postal_code','phone_landline','mobile','bank_name','bank_account','promoter_code','expert_name','supervisor_name','activity_city','contract_number','contract_date','contract_end_date','duration_days'];
const DUMMY='scrypt$AAAAAAAAAAAAAAAAAAAAAA==$'+Buffer.alloc(32).toString('base64');
const tries=new Map();
const sec=()=>process.env.SESSION_SECRET||'';
const hm=d=>c.createHmac('sha256',sec()).update(d).digest('base64url');
const sign=p=>{const d=Buffer.from(JSON.stringify(p)).toString('base64url');return d+'.'+hm(d)};
function verify(t){const[d,s]=String(t||'').split('.');if(!d||!s)return null;const a=Buffer.from(s),b=Buffer.from(hm(d));if(a.length!==b.length||!c.timingSafeEqual(a,b))return null;try{const p=JSON.parse(Buffer.from(d,'base64url'));return p.exp>Date.now()?p:null}catch{return null}}
const users=()=>{try{return JSON.parse(process.env.AUTH_USERS||'[]')}catch{return[]}};
function checkPw(pw,h){const[t,s,x]=String(h).split('$');if(t!=='scrypt')return false;const d=c.scryptSync(pw,Buffer.from(s,'base64'),32),e=Buffer.from(x,'base64');return e.length===d.length&&c.timingSafeEqual(d,e)}
async function sess(req){const k=(req.headers.cookie||'').split(/;\s*/).find(x=>x.startsWith('sid='));const p=k&&verify(k.slice(4));if(!p)return null;
 let d;try{d=(await sb('app_users?select=username,role,expert_name,full_name,is_active&username=eq.'+encodeURIComponent(p.u)))[0]}catch(e){d=undefined}
 if(d)return d.is_active?{u:d.username,r:d.role,expert:d.expert_name||'',name:d.full_name,src:'db'}:null;
 const e=users().find(x=>x.u===p.u);return e?{u:e.u,r:ROLEMAP[e.r]||e.r,expert:'',name:e.u,src:'env'}:null}
async function sb(path,o={}){const K=process.env.SUPABASE_SERVICE_ROLE_KEY,U=process.env.SUPABASE_URL;if(!K||!U)throw new Error('cfg');const r=await fetch(U+'/rest/v1/'+path,{...o,headers:{apikey:K,Authorization:'Bearer '+K,...(o.body?{'Content-Type':'application/json'}:{}),'Range-Unit':'items',Prefer:'return=representation',...(o.headers||{})}});const t=await r.text();if(!r.ok)throw new Error('db:'+r.status+' '+t.slice(0,200));return t?JSON.parse(t):[]}
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
   const b=req.body||{},un=String(b.username||'').trim().toLowerCase();let u=null,hash=null,found=false;try{const d=(await sb('app_users?select=username,password_hash,is_active&username=eq.'+encodeURIComponent(un)))[0];if(d){found=true;if(d.is_active){u={u:d.username};hash=d.password_hash}}}catch(e){found=false}
   if(!found){const e=users().find(x=>x.u===un);if(e){u=e;hash=e.h}}
   if(!(checkPw(String(b.password||''),hash||DUMMY)&&u)){t.n++;tries.set(ip,t);return send(401,{error:'نام کاربری یا کلمه عبور اشتباه است'})}
   tries.delete(ip);
   res.setHeader('Set-Cookie','sid='+sign({u:u.u,exp:Date.now()+6048e5})+'; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800');
   return send(200,{username:u.u,role:u.r});
  }
  if(a==='logout'&&m==='POST'){res.setHeader('Set-Cookie','sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return send(200,{ok:true})}
  const s=await sess(req);if(!s)return send(401,{error:'نیاز به ورود'});
  const admin=s.r==='super_admin',id=String(req.query.id||'');
  if(a==='me'&&m==='GET')return send(200,{username:s.u,role:s.r,expert:s.expert,name:s.name,source:s.src});
  if(a==='mypw'&&m==='POST'){if(s.src!=='db')return send(400,{error:'رمز این کاربر از طریق سایت قابل تغییر نیست'});
   const b=req.body||{},k='pw:'+s.u,t=tries.get(k)||{n:0,t:Date.now()};if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}if(t.n>=5)return send(429,{error:'تلاش‌های ناموفق زیاد است؛ چند دقیقه بعد دوباره امتحان کنید'});
   const cur=(await sb('app_users?select=password_hash&username=eq.'+encodeURIComponent(s.u)))[0];
   if(!cur||!checkPw(String(b.current||''),cur.password_hash)){t.n++;tries.set(k,t);return send(400,{error:'رمز فعلی اشتباه است'})}
   const np=String(b.password||'');if(np.length<8)return send(400,{error:'رمز جدید باید حداقل ۸ کاراکتر باشد'});if(np===String(b.current))return send(400,{error:'رمز جدید باید با رمز فعلی فرق داشته باشد'});
   await sb('app_users?username=eq.'+encodeURIComponent(s.u),{method:'PATCH',body:JSON.stringify({password_hash:hashPw(np),updated_at:new Date().toISOString()})});tries.delete(k);return send(200,{ok:true})}
  if(a==='users'){if(!can(s,'users'))return send(403,{error:'دسترسی ندارید'});const b=req.body||{};
   if(m==='GET'){const d=await sb('app_users?select=id,username,full_name,role,city,title,expert_name,is_active,created_at&order=created_at');return send(200,{users:[...users().filter(x=>!d.some(y=>y.username===x.u)).map(x=>({username:x.u,full_name:'(کاربر اضطراری)',role:ROLEMAP[x.r]||x.r,source:'env',is_active:true})),...d]})}
   if(m==='POST'){const v=uval(b,true);if(v.err)return send(400,{error:v.err});try{await sb('app_users',{method:'POST',body:JSON.stringify(v.o)})}catch(e){return send(400,{error:/23505|duplicate/.test(e.message)?'این نام کاربری قبلاً ثبت شده است':'خطا: '+e.message.slice(0,120)})}return send(200,{ok:true})}
   if(m==='PATCH'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const own=(await sb('app_users?select=username,role,expert_name&id=eq.'+encodeURIComponent(id)))[0];if(!own)return send(404,{error:'یافت نشد'});
    if(own.username===s.u&&((b.is_active!=null&&!b.is_active)||(b.role!=null&&b.role!==own.role)))return send(400,{error:'نمی‌توانید نقش یا وضعیت حساب خودتان را تغییر دهید'});
    const v=uval(b,false,own);if(v.err)return send(400,{error:v.err});
    try{await sb('app_users?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(v.o)})}catch(e){return send(400,{error:/23505|duplicate/.test(e.message)?'این نام کاربری قبلاً ثبت شده است':'خطا: '+e.message.slice(0,120)})}return send(200,{ok:true})}}
  if(a==='template'&&m==='GET'){if(!can(s,'template'))return send(403,{error:'دسترسی ندارید'});const T=require('./_tpl.js'),t=req.query.type;return T[t]&&(t==='cab'||t==='box')?send(200,{b64:T[t]}):send(400,{error:'نوع نامعتبر'})}
  if(a==='promoters'){
   if(m==='GET'){const[rows,fl]=await Promise.all([all('contract_promoters?select=*&order=full_name'+(s.r==='specialist'?'&expert_name=eq.'+encodeURIComponent(s.expert||'-'):'')),all('promoter_files?select=promoter_id,kind&order=id')]);const mp={};fl.forEach(f=>(mp[f.promoter_id]=mp[f.promoter_id]||[]).push(f.kind));rows.forEach(r=>r.docs=mp[r.id]||[]);return send(200,{rows})}
   if(m==='POST'||m==='PATCH'){if(!can(s,'write'))return send(403,{error:'دسترسی ندارید'});const b=req.body||{},o={};FIELDS.forEach(k=>o[k]=b[k]==null?'':String(b[k]).trim().slice(0,500));if(s.r==='specialist')o.expert_name=s.expert;
    ['national_id','promoter_code','mobile','postal_code','phone_landline','id_booklet_no'].forEach(k=>o[k]=dg(o[k]));
    o.bank_account=dg(o.bank_account).replace(/\s+/g,'').toUpperCase();o.promoter_kind=o.promoter_kind==='old'?'old':'new';
    for(const k of REQ)if(!o[k])return send(400,{error:'فیلد «'+LBL[k]+'» الزامی است'});
    if(!EXP[o.expert_name])return send(400,{error:'نام کارشناس نامعتبر است'});o.activity_city=EXP[o.expert_name];
    if(!/^\d{10}$/.test(o.national_id))return send(400,{error:'کد ملی باید دقیقاً ۱۰ رقم باشد'});
    if(o.promoter_kind==='old'){if(!/^\d{5}$/.test(o.promoter_code))return send(400,{error:'کد بازاریابی باید دقیقاً ۵ رقم باشد'})}else o.promoter_code='';
    if(!/^IR\d{24}$/.test(o.bank_account))return send(400,{error:'شماره شبا صحیح نمی باشد'});
    const cd=parseJ(o.contract_date),bd=parseJ(o.birth_date);if(!cd||!bd)return send(400,{error:'تاریخ نامعتبر است؛ قالب صحیح مانند 10/10/1405'});
    const dur=Math.round((JEND.t-cd.t)/864e5);if(dur<0)return send(400,{error:'تاریخ قرارداد نباید بعد از 29/12/1405 باشد'});
    o.contract_date=cd.s;o.birth_date=bd.s;o.contract_end_date=JEND.s;o.duration_days=String(dur);o.updated_at=new Date().toISOString();
    const idp=o.promoter_kind==='old'?o.promoter_code:o.national_id;delete o.contract_number;
    if(m==='POST'){o.id_part=idp;const r=await sb('rpc/create_promoter',{method:'POST',body:JSON.stringify({p:o})}),row=Array.isArray(r)?r[0]:r;return send(200,{ok:true,id:row&&row.id,contract_number:row&&row.contract_number})}
    if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});if(!await chk(s,id))return send(403,{error:'دسترسی ندارید'});
    const cur=(await sb('contract_promoters?select=contract_number,activity_city&id=eq.'+encodeURIComponent(id)))[0];if(!cur)return send(404,{error:'یافت نشد'});
    let seq=(String(cur.contract_number||'').match(/-(\d+)\s*$/)||[])[1];
    if(!seq||cur.activity_city!==o.activity_city)seq=String(await sb('rpc/next_contract_no',{method:'POST',body:JSON.stringify({p_city:o.activity_city})}));
    o.contract_number='Sn-'+CODE[o.activity_city]+'-'+idp+'-'+seq;
    await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(o)});return send(200,{ok:true,id,contract_number:o.contract_number})}
   if(m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});
    for(const f of await sb('promoter_files?select=storage_path&promoter_id=eq.'+encodeURIComponent(id)))await rm([f.storage_path]).catch(()=>{});
    await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  }
  if(a==='files'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});if(!can(s,'view')||!await chk(s,id))return send(403,{error:'دسترسی ندارید'});return send(200,{files:await sb('promoter_files?select=id,kind,file_name,size_bytes,uploaded_by,uploaded_at&promoter_id=eq.'+encodeURIComponent(id))})}
  if(a==='upload'&&m==='POST'){const b=req.body||{},ext=MIME[b.mime];if(!can(s,'upload')||!await chk(s,String(b.promoter_id)))return send(403,{error:'دسترسی ندارید'});if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!ext||!(b.size>0&&b.size<=10485760))return send(400,{error:'نوع یا حجم فایل مجاز نیست (تصویر یا PDF تا ۱۰ مگابایت)'});
   const path=b.promoter_id+'/'+b.kind+'-'+Date.now()+'-'+c.randomBytes(4).toString('hex')+'.'+ext,j=await st('/object/upload/sign/promoter-docs/'+path,{method:'POST',body:'{}'}),u=j.url||j.signedUrl;return send(200,{path,url:/^http/.test(u)?u:ST()+u})}
  if(a==='fileok'&&m==='POST'){const b=req.body||{};if(!can(s,'upload')||!await chk(s,String(b.promoter_id)))return send(403,{error:'دسترسی ندارید'});if(!UID.test(String(b.promoter_id))||!KIND.includes(b.kind)||!String(b.path).startsWith(b.promoter_id+'/'+b.kind+'-'))return send(400,{error:'درخواست نامعتبر'});
   const old=await sb('promoter_files?select=storage_path&promoter_id=eq.'+b.promoter_id+'&kind=eq.'+b.kind);
   await sb('promoter_files?on_conflict=promoter_id,kind',{method:'POST',headers:{Prefer:'resolution=merge-duplicates,return=minimal'},body:JSON.stringify({promoter_id:b.promoter_id,kind:b.kind,file_name:String(b.file_name||'').slice(0,200),storage_path:b.path,mime_type:b.mime,size_bytes:b.size,uploaded_by:s.u,uploaded_at:new Date().toISOString()})});
   for(const f of old)if(f.storage_path!==b.path)await rm([f.storage_path]).catch(()=>{});return send(200,{ok:true})}
  if(a==='fileview'&&m==='GET'){if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path,promoter_id&id=eq.'+encodeURIComponent(id)))[0];if(!row)return send(404,{error:'یافت نشد'});if(!can(s,'view')||!await chk(s,row.promoter_id))return send(403,{error:'دسترسی ندارید'});const j=await st('/object/sign/promoter-docs/'+row.storage_path,{method:'POST',body:JSON.stringify({expiresIn:60})});return send(200,{url:ST()+j.signedURL})}
  if(a==='filedel'&&m==='DELETE'){if(!can(s,'delfile'))return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!UID.test(id))return send(400,{error:'شناسه نامعتبر'});const row=(await sb('promoter_files?select=storage_path&id=eq.'+encodeURIComponent(id)))[0];if(row)await rm([row.storage_path]).catch(()=>{});await sb('promoter_files?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  return send(404,{error:'یافت نشد'});
 }catch(e){return send(500,{error:e.message==='cfg'?'تنظیمات سرور ناقص است (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)':'خطا در ارتباط با پایگاه داده: '+String(e.message).slice(0,200)})}
};
process.on('unhandledRejection',e=>console.error('unhandledRejection',e));
const _handler=module.exports;
module.exports=async(req,res)=>{try{await _handler(req,res)}catch(e){console.error(e);if(!res.headersSent){res.status(500).json({error:'خطای داخلی سرور: '+String((e&&e.stack)||e).slice(0,500)})}}};
