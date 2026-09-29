const c=require('crypto');
const FIELDS=['full_name','father_name','id_booklet_no','national_id','birth_date','birth_place','marital_status','military_status','address','postal_code','phone_landline','mobile','bank_name','bank_account','promoter_code','expert_name','supervisor_name','activity_city','contract_number','contract_date','contract_end_date','duration_days'];
const DUMMY='scrypt$AAAAAAAAAAAAAAAAAAAAAA==$'+Buffer.alloc(32).toString('base64');
const tries=new Map();
const sec=()=>process.env.SESSION_SECRET||'';
const hm=d=>c.createHmac('sha256',sec()).update(d).digest('base64url');
const sign=p=>{const d=Buffer.from(JSON.stringify(p)).toString('base64url');return d+'.'+hm(d)};
function verify(t){const[d,s]=String(t||'').split('.');if(!d||!s)return null;const a=Buffer.from(s),b=Buffer.from(hm(d));if(a.length!==b.length||!c.timingSafeEqual(a,b))return null;try{const p=JSON.parse(Buffer.from(d,'base64url'));return p.exp>Date.now()?p:null}catch{return null}}
const users=()=>{try{return JSON.parse(process.env.AUTH_USERS||'[]')}catch{return[]}};
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
   if(m==='GET'){let rows=[];for(let i=0;;i+=1000){let b;try{b=await sb('contract_promoters?select=*&order=full_name',{headers:{Range:i+'-'+(i+999)}})}catch(e){if(String(e.message).includes('db:416'))break;throw e}rows=rows.concat(b);if(b.length<1000)break}return send(200,{rows})}
   if(m==='POST'||m==='PATCH'){const b=req.body||{},o={};FIELDS.forEach(k=>o[k]=b[k]==null?'':String(b[k]).slice(0,500));if(!o.full_name.trim())return send(400,{error:'نام الزامی است'});o.updated_at=new Date().toISOString();
    if(m==='POST'){await sb('contract_promoters',{method:'POST',body:JSON.stringify(o)});return send(200,{ok:true})}
    if(!/^[\w-]{1,64}$/.test(id))return send(400,{error:'شناسه نامعتبر'});await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(o)});return send(200,{ok:true})}
   if(m==='DELETE'){if(!admin)return send(403,{error:'فقط مدیر می‌تواند حذف کند'});if(!/^[\w-]{1,64}$/.test(id))return send(400,{error:'شناسه نامعتبر'});await sb('contract_promoters?id=eq.'+encodeURIComponent(id),{method:'DELETE'});return send(200,{ok:true})}
  }
  return send(404,{error:'یافت نشد'});
 }catch(e){return send(500,{error:e.message==='cfg'?'تنظیمات سرور ناقص است (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)':'خطا در ارتباط با پایگاه داده: '+String(e.message).slice(0,200)})}
};
