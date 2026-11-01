const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {assertResourceClear}=require("./resource-guard.cjs");
const ID=/^[a-f0-9]{32}$/,UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const NAME=/^u_copilot_[a-z0-9_]{1,60}$/;
const obj=(properties,required=Object.keys(properties))=>({type:"object",properties,required,additionalProperties:false});
const id={type:"string",pattern:ID.source},op={type:"string",pattern:UUID.source},version={type:"string",pattern:"^\\d+$"};
const specs={
 local_admin_group_create:{table:"sys_user_group",creating:true},
 local_admin_role_create:{table:"sys_user_role",creating:true},
 local_admin_group_member_add:{table:"sys_user_grmember",fields:["user","group"],adding:true},
 local_admin_group_member_remove:{table:"sys_user_grmember",fields:["user","group"],removing:true},
 local_admin_group_role_add:{table:"sys_group_has_role",fields:["group","role"],adding:true},
 local_admin_group_role_remove:{table:"sys_group_has_role",fields:["group","role"],removing:true},
 local_admin_user_role_add:{table:"sys_user_has_role",fields:["user","role"],adding:true},
 local_admin_user_role_remove:{table:"sys_user_has_role",fields:["user","role"],removing:true},
 local_admin_access_read:{read:true},
 local_admin_group_create_pending_adoption:{table:"sys_user_group",creating:true,deferred:true},
 local_admin_role_create_pending_adoption:{table:"sys_user_role",creating:true,deferred:true},
};
const tools=Object.entries(specs).map(([name,s])=>({name,annotations:{readOnlyHint:!!s.read,destructiveHint:!!s.removing,idempotentHint:false},
 description:s.read?"Read a supplied disabled locked native-user's direct/inherited roles and groups, after managed nonprivileged cohort checks. No arbitrary population, privilege grants or secrets.":
 s.deferred?"Create one supplied neutral definition with truthful source creation receipt but NO managed-access authority. Privilege/source/hooks guard and intended-value readback identical to normal create. Assessment plus trusted adoption required before relationship/description operations; no forged origin or deleted receipts.":
 s.creating?"Create one supplied u_copilot_ namespaced nonprivileged role or empty inactive local group with durable ownership receipt. No elevated/scoped admin, parent/manager/contact, ACL or contained-privilege defaults. Native audit/help metadata may be created.":
 "Add/remove one supplied direct relationship between an eligible disabled locked local human and privately managed nonprivileged role/group. Native inherited-role expansion/removal is read back, not synthesized. Removal targets only exact direct relationship/version; no automatic child deletes, role reassignments or security-admin grants. Group/role definitions are retained.",
 inputSchema:s.read?obj({user:id}):s.creating?obj({operation_id:op,name:{type:"string",pattern:NAME.source},description:{type:"string",maxLength:200}}):
 obj({operation_id:op,...Object.fromEntries(s.fields.map(f=>[f,id])),...(s.removing?{relationship_id:id,expected_mod_count:version}:{})})}));
function truth(v){if(![true,false,"true","false","0","1"].includes(v))throw new Error("Access guard boolean unknown.");return [true,"true","1"].includes(v);}
function check(args,schema){
 if(!args||typeof args!=="object"||Array.isArray(args)||Object.keys(args).some(k=>!schema.properties[k])||schema.required.some(k=>!Object.hasOwn(args,k)))throw new Error("Invalid access arguments.");
 for(const [k,v]of Object.entries(args)){const p=schema.properties[k];if(typeof v!=="string"||(p.pattern&&!new RegExp(p.pattern).test(v))||(p.maxLength&&v.length>p.maxLength))throw new Error("Invalid access argument: "+k);}
}
function createAccessOperations({policy,accessPolicy,list,request,record,claim,isAttempted,principal,directory,assessRolePickerImpact}){
 const folder=path.join(directory,"access-operation-receipts");
 const outcomes=new Map();
 function save(file,value,exclusive=false){fs.mkdirSync(folder,{recursive:true});const fd=fs.openSync(path.join(folder,file),exclusive?"wx":"w");
  try{fs.writeSync(fd,JSON.stringify(value));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 const load=file=>JSON.parse(fs.readFileSync(path.join(folder,file),"utf8"));
 async function rows(table,query,fields,limit=100){
  const equalities=query.split("^").map(p=>p.match(/^([a-z_]+)=([^=]*)$/)).filter(Boolean);
  fields=[...new Set([...fields.split(","),...equalities.map(m=>m[1])])].join(",");
  const r=await list(table,query,fields,limit);if(!Array.isArray(r)||r.length>=limit)throw new Error("Access evidence incomplete: "+table);
  for(const row of r){if(typeof row.sys_id!=="string"||!ID.test(row.sys_id))throw new Error("Invalid access record identity.");for(const f of fields.split(","))if(!Object.hasOwn(row,f))throw new Error("Access guard field omitted: "+table+"."+f);
   for(const [,field,value]of equalities)if(String(row[field])!==value)throw new Error("Access queried identity/endpoint mismatch:"+table+"."+field);}
  return r;
 }
 const signature=rows=>JSON.stringify(rows.map(r=>({sys_id:r.sys_id,sys_mod_count:r.sys_mod_count})).sort((a,b)=>a.sys_id.localeCompare(b.sys_id)));
 async function checkPolicy(){
  for(const [table,pin]of Object.entries(accessPolicy.tables)){
   const hooks=await rows("sys_script",`collection=${table}^active=true`,"sys_id,sys_mod_count");
   const dict=await rows("sys_dictionary",`name=${table}`,"sys_id,sys_mod_count");
   if(signature(hooks)!==signature(pin.rules)||signature(dict)!==signature(pin.dictionary))throw new Error("Access hook/schema policy drift; refresh exact-table review:"+table);
  }
 }
 async function managed(table,id){
  const receipt=load(`${table}-${id}.managed.json`);
  const adopted=receipt.origin==="reviewed_adoption"&&typeof receipt.assessment_id==="string"&&UUID.test(receipt.assessment_id);
  if(receipt.table!==table||receipt.sys_id!==id||
   (adopted?!/^[a-zA-Z0-9_. -]{1,100}$/.test(receipt.name):!NAME.test(receipt.name)))throw new Error("No valid managed nonprivileged identity receipt.");
  if(adopted&&table==="sys_user_role"){
   if(typeof assessRolePickerImpact!=="function")throw new Error("Adopted role native picker-impact guard is not wired.");
   const impact=await assessRolePickerImpact(receipt.name);
   if(!impact?.complete_bounded_read_visible||impact.references.length)throw new Error("Adopted role acquired or has unknown native picker access; fresh review required.");
  }
  return sourceDefinition(table,id,receipt.name,!adopted);
 }
 async function sourceDefinition(table,id,name,requireCreator){
  const fields=table==="sys_user_role"?"sys_id,name,sys_scope,sys_created_by,sys_mod_count,elevated_privilege,scoped_admin,assignable_by,can_delegate,includes_roles":
   "sys_id,name,sys_created_by,sys_mod_count,active,parent,manager,source,default_assignee";
  const found=await rows(table,`sys_id=${id}`,fields,2);
  if(found.length!==1||found[0].name!==name||requireCreator&&found[0].sys_created_by!==principal)throw new Error("Managed role/group source identity changed.");
  const r=found[0];
  if(table==="sys_user_role"){
   if(r.sys_scope!=="global"||truth(r.elevated_privilege)||truth(r.scoped_admin)||truth(r.can_delegate)||r.assignable_by||r.includes_roles)
    throw new Error("Role became elevated/scoped/delegated/contained.");
   if((await rows("sys_security_acl_role",`sys_user_role=${id}`,"sys_id",2)).length)throw new Error("Role became access-control-bearing.");
   if((await rows("sys_user_role_contains",`role=${id}`,"sys_id,contains",2)).length)throw new Error("Contained roles require separate privilege qualification.");
   if((await rows("sys_user_role_contains",`contains=${id}`,"sys_id,role",2)).length)throw new Error("Role has unknown containing privileges.");
  }else{
   if(truth(r.active)||r.parent||r.manager||r.source||r.default_assignee)throw new Error("Group is outside managed inactive empty-local cohort.");
   if((await rows("sys_user_group",`parent=${id}`,"sys_id",2)).length)throw new Error("Group has child inheritance.");
   for(const link of await rows("sys_group_has_role",`group=${id}`,"sys_id,group,role,inherits,sys_mod_count"))await managed("sys_user_role",link.role);
  }
  return r;
 }
 async function user(id){
  const f=await rows("sys_user",`sys_id=${id}`,"sys_id,user_name,active,locked_out,identity_type,internal_integration_user,web_service_access_only,manager,sys_mod_count,sys_class_name",2);
  if(f.length!==1||f[0].sys_class_name!=="sys_user"||f[0].user_name.toLowerCase()===principal.toLowerCase()||
   policy.protectedNames.includes(f[0].user_name.toLowerCase())||policy.protectedIds.includes(id)||
   truth(f[0].active)||!truth(f[0].locked_out)||f[0].identity_type!=="human"||truth(f[0].internal_integration_user)||truth(f[0].web_service_access_only)||f[0].manager)throw new Error("Protected/nonlocal/service/active access target.");
  if((await rows("sys_user",`sys_id=${id}^sourceISEMPTY^ldap_serverISEMPTY`,"sys_id",2)).length!==1)throw new Error("External-source user excluded.");
  if((await rows("provider_user_map",`user=${id}`,"sys_id",2)).length)throw new Error("Provider-linked user excluded.");
  for(const r of await rows("sys_user_has_role",`user=${id}`,"sys_id,role,inherited,granted_by,sys_mod_count,state"))await managed("sys_user_role",r.role);
  for(const r of await rows("sys_user_grmember",`user=${id}`,"sys_id,group,sys_mod_count"))await managed("sys_user_group",r.group);
  return f[0];
 }
 async function readAccess(id){
  await user(id);
  const roles=await rows("sys_user_has_role",`user=${id}`,"sys_id,user,role,inherited,granted_by,sys_mod_count,state");
  const memberships=await rows("sys_user_grmember",`user=${id}`,"sys_id,user,group,sys_mod_count");
  const originGraph={};
  for(const member of memberships)for(const link of await rows("sys_group_has_role",`group=${member.group}`,"sys_id,role,inherits")){
   if(truth(link.inherits))(originGraph[link.role]||(originGraph[link.role]=[])).push(member.group);
  }
  for(const role of roles)if(truth(role.inherited)){
   const origins=originGraph[role.role]||[];
   if(!origins.length||(!accessPolicy.directOriginDefaults.includes(role.granted_by)&&!origins.includes(role.granted_by)))
    throw new Error("Inherited role origin is ambiguous/outside qualified remaining membership graph.");
  }
  for(const roleId of Object.keys(originGraph))if(!roles.some(r=>r.role===roleId&&truth(r.inherited)))
   throw new Error("Native inherited role is missing despite a remaining qualified membership/group-role origin.");
  return {user:id,roles,memberships,origin_graph:originGraph,
   evidence:"Source direct and inherited relationship rows; not cached-session permission proof. No credential/token export."};
 }
 function pending(args){
  if(!fs.existsSync(folder))return;
  for(const name of fs.readdirSync(folder).filter(n=>n.endsWith(".operation.json"))){
   const r=load(name);if(!["confirmed","rejected"].includes(r.status)&&["user","group","role","name"].some(k=>Object.hasOwn(args,k)&&Object.hasOwn(r,k)&&r[k]===args[k]))
    throw new Error("Earlier access effect unresolved; no cross-UUID replay.");
  }
 }
 async function handleCore(name,args){
  const spec=specs[name],tool=tools.find(t=>t.name===name);if(!spec)throw new Error("Unknown access operation.");
  check(args,tool.inputSchema);if(spec.read)return readAccess(args.user);
  if(isAttempted(args.operation_id))throw new Error("Access operation already consumed.");
  pending(args);
  assertResourceClear(directory,args);
  await checkPolicy();
  let values,query,before,affectedMembers=[],groupInheritedRoles=[];
  if(spec.creating){
   if(/admin|security|maint|impersonat|oauth|mid_server|snc_/.test(args.name))throw new Error("Reserved privileged role/group name is not supported.");
   if((await rows(spec.table,`name=${args.name}`,"sys_id",2)).length)throw new Error("Access name exists; no create.");
   values=spec.table==="sys_user_role"?{name:args.name,description:args.description,sys_scope:"global",elevated_privilege:false,scoped_admin:false,can_delegate:false}:
    {name:args.name,description:args.description,active:false,parent:"",manager:"",source:"",default_assignee:"",email:""};
   query=`name=${args.name}`;
  }else{
   if(args.user)await readAccess(args.user);if(args.group)await managed("sys_user_group",args.group);if(args.role)await managed("sys_user_role",args.role);
   if(args.group){
    affectedMembers=(await rows("sys_user_grmember",`group=${args.group}`,"sys_id,user")).map(r=>r.user);
    for(const userId of affectedMembers)await readAccess(userId);
    groupInheritedRoles=(await rows("sys_group_has_role",`group=${args.group}`,"sys_id,role,inherits")).filter(r=>truth(r.inherits)).map(r=>r.role);
   }
   query=spec.fields.map(f=>`${f}=${args[f]}`).join("^");
   const existing=await rows(spec.table,query,"sys_id,sys_mod_count,"+spec.fields.join(",")+(spec.table==="sys_user_has_role"?",inherited,granted_by":""));
   if(spec.adding&&existing.length)throw new Error("Relationship already present; no duplicate assignment.");
   if(spec.removing){
    before=existing.find(r=>r.sys_id===args.relationship_id);
    if(!before||before.sys_mod_count!==args.expected_mod_count)throw new Error("Direct relationship identity/version changed.");
    if(spec.table==="sys_user_has_role"&&(truth(before.inherited)||!accessPolicy.directOriginDefaults.includes(before.granted_by)))
     throw new Error("Cannot directly delete an inherited/ambiguous-origin role; remove its managed membership/group-role source.");
   }
   values=Object.fromEntries(spec.fields.map(f=>[f,args[f]]));
   if(spec.table==="sys_group_has_role")values.inherits=true;
   if(spec.table==="sys_user_has_role"){values.inherited=false;values.granted_by="";}
  }
  const out={operation_id:args.operation_id,action:name,table:spec.table,...Object.fromEntries(Object.entries(args).filter(([k])=>k!=="operation_id")),
   status:"attempt",native_effects_declared:spec.creating?["native-help/audit/assessment-metadata"]:["source-role-expansion/removal","source-membership/cache/session-event-effects"]};
  outcomes.set(args.operation_id,out);
  save(args.operation_id+".operation.json",out,true);claim(args.operation_id,{action:name,table:spec.table,receipt:args.operation_id+".operation.json"});
  let response,failure;
  try{response=await request(spec.removing?"DELETE":"POST",spec.table,{sysparm_fields:"sys_id",sysparm_display_value:"false",sysparm_exclude_reference_link:"true"},spec.removing?undefined:values,spec.removing?args.relationship_id:undefined);}catch(e){failure=e;}
  if(response?.result?.sys_id&&ID.test(response.result.sys_id)){out.sys_id=response.result.sys_id;save(args.operation_id+".operation.json",out);}
  if(failure?.diagnostic?.status===401){out.status="uncertain";out.diagnostic=failure.diagnostic;save(args.operation_id+".operation.json",out);record(out);const err=new Error("Admin authentication rejected; no reconciliation/retry.");err.outcome=out;throw err;}
  try{
   const after=await rows(spec.table,query,"sys_id,sys_mod_count,"+(spec.creating?["name","sys_created_by",...Object.keys(values)].join(","):spec.fields.join(","))+
    (spec.table==="sys_user_has_role"?",inherited,granted_by":""));
   out.observed_ids=after.map(r=>r.sys_id);
   if(failure?.diagnostic?.status>=400&&failure.diagnostic.status<500)throw new Error("Source rejected request; observed state is not write attribution.");
   if(spec.removing){
    const exact=await rows(spec.table,`sys_id=${args.relationship_id}`,"sys_id,"+spec.fields.join(","),2);
    out.exact_relationship_absent=exact.length===0;
    if(exact.length)throw new Error("Exact relationship ID still exists or endpoints drifted; filtered absence is not deletion.");
    if(after.some(r=>r.sys_id===args.relationship_id))throw new Error("Direct relationship still present.");
    out.absent=true;out.sys_id=args.relationship_id;
   }else{
    if(after.length!==1||out.sys_id&&out.sys_id!==after[0].sys_id)throw new Error("Created relationship/name not unique or does not match source identity.");
    if(spec.creating&&after[0].sys_created_by!==principal)throw new Error("Created role/group not owned by operator.");
    out.sys_id=after[0].sys_id;out.sys_mod_count=after[0].sys_mod_count;
    if(spec.creating){
     const mismatched=Object.entries(values).filter(([field,value])=>typeof value==="boolean"?truth(after[0][field])!==value:after[0][field]!==value).map(([field])=>field);
     if(mismatched.length){out.mismatched_intended_fields=mismatched;throw new Error("Source ignored/changed intended definition fields; known created identity retained.");}
    }
    if(spec.creating){
     if(spec.deferred){
      await sourceDefinition(spec.table,out.sys_id,args.name,true);
      out.managed_access_authority=false;out.creation_provenance="source_created_pending_adoption";
     }else{save(`${spec.table}-${out.sys_id}.managed.json`,{table:spec.table,sys_id:out.sys_id,name:args.name},true);await managed(spec.table,out.sys_id);out.managed_access_authority=true;}
    }
    else if(spec.table==="sys_user_has_role"&&truth(after[0].inherited))throw new Error("Direct grant was not observed direct.");
   }
   if(args.user){
    out.access=await readAccess(args.user);
    if(spec.table==="sys_user_grmember")for(const roleId of groupInheritedRoles){
     const inherited=out.access.roles.filter(r=>r.role===roleId&&truth(r.inherited));
     if(spec.adding&&!inherited.length)throw new Error("Native group-inherited role not observed after membership add.");
     if(spec.removing&&!(out.access.origin_graph[roleId]||[]).length&&inherited.length)
      throw new Error("Native group-inherited role persists after membership removal.");
    }
   }
   if(args.group){
    const members=await rows("sys_user_grmember",`group=${args.group}`,"sys_id,user");
    out.member_access=[];for(const userId of new Set([...affectedMembers,...members.map(r=>r.user)])){
     const access=await readAccess(userId);out.member_access.push(access);
     if(spec.table==="sys_group_has_role"){
      const inherited=access.roles.filter(r=>r.role===args.role&&truth(r.inherited));
      if(spec.adding&&!inherited.length)throw new Error("Native group role inheritance not observed.");
      if(spec.removing&&!(access.origin_graph[args.role]||[]).length&&inherited.length)throw new Error("Native inherited group role persists.");
     }
    }
   }
  }catch(e){out.status="uncertain";out.reason=e.message;out.original_diagnostic=failure?.diagnostic;out.reconciliation_diagnostic=e.diagnostic;
   out.diagnostic=e.diagnostic||failure?.diagnostic;out.reconciled_after_transport_error=!!failure;
   save(args.operation_id+".operation.json",out);record(out);const error=new Error("Access mutation/native effect not fully qualified; no replay/compensation.");error.outcome=out;throw error;}
  out.status="confirmed";out.reconciled_after_transport_error=!!failure;out.original_diagnostic=failure?.diagnostic;
  save(args.operation_id+".operation.json",out);record(out);return out;
 }
 async function handle(name,args){
  try{return await handleCore(name,args);}
  catch(e){
   if(!e.outcome&&args?.operation_id&&isAttempted(args.operation_id)){
    const out=outcomes.get(args.operation_id)||{operation_id:args.operation_id,action:name};
    out.status="uncertain";out.reason="Access receipt/journal or post-write failure; retain known identity and reconcile without replay.";
    e.outcome=out;
    try{save(args.operation_id+".operation.json",out);}catch{out.receipt_recovery_failed=true;}
   }
   throw e;
  }finally{if(outcomes.get(args?.operation_id)?.status==="confirmed")outcomes.delete(args.operation_id);}
 }
 return {tools,handle,checkPolicy,inspectDefinition:async(table,id)=>{
  if(!["sys_user_group","sys_user_role"].includes(table))throw new Error("Unsupported definition table.");
  return managed(table,id);
 }};
}
module.exports={tools,createAccessOperations};
