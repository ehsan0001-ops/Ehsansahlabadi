module.exports=(req,res)=>{
 const out={node:process.version,env:{AUTH_USERS:!!process.env.AUTH_USERS,SESSION_SECRET_ok:(process.env.SESSION_SECRET||'').length>=32,SUPABASE_URL:!!process.env.SUPABASE_URL,SERVICE_KEY:!!process.env.SUPABASE_SERVICE_ROLE_KEY}};
 try{const a=JSON.parse(process.env.AUTH_USERS||'[]');out.authUsersIsArray=Array.isArray(a);out.authUsersCount=a.length;out.authUsersKeys=a[0]?Object.keys(a[0]):[]}catch(e){out.authUsersIsArray=false;out.authUsersError=String(e.message).slice(0,120)}
 try{require('./[action].js');out.actionFileLoads=true}catch(e){out.actionFileLoads=false;out.error=String((e&&e.stack)||e).slice(0,700)}
 res.setHeader('Content-Type','application/json; charset=utf-8');res.status(200).end(JSON.stringify(out,null,1));
};
