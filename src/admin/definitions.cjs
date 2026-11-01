const fs=require("node:fs"),path=require("node:path");
const {assertResourceClear}=require("./resource-guard.cjs");
const ID=/^[a-f0-9]{32}$/,UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const definitions={local_admin_group_update:["sys_user_group",false],local_admin_group_delete:["sys_user_group",true],
 local_admin_role_update:["sys_user_role",false],local_admin_role_delete:["sys_user_role",true]};
const tools=Object.entries(definitions).map(([name,[table,deleting]])=>({name,annotations:{readOnlyHint:false,destructiveHint:deleting,idempotentHint:false},
 description:deleting?"Delete exact privately managed nonprivileged empty definition after current version/hooks/reference checks; source-native help/assessment/cache cleanup declared and read back. No reassignment or child deletes, privilege-role or unreviewed existing group deletion. Refuse unresolved/hidden evidence.":
 "Update only description of a supplied privately managed nonprivileged local role/inactive group after version/identity/policy checks. Name, privileges, parent, active, manager and memberships unchanged.",
 inputSchema:{type:"object",properties:{sys_id:{type:"string",pattern:ID.source},operation_id:{type:"string",pattern:UUID.source},
  expected_mod_count:{type:"string",pattern:"^\\d+$"},...(deleting?{confirm:{type:"boolean",const:true}}:{description:{type:"string",maxLength:200}})},
 required:["sys_id","operation_id","expected_mod_count",deleting?"confirm":"description"],additionalProperties:false}}));
tools.push({name:"local_admin_role_delete_assess",annotations:{readOnlyHint:true},
 description:"Read-only complete bounded assessment of the EXACT native user_roles-picker reference class for a supplied managed nonprivileged role, plus direct assignments. No source deletion, script execution or ignored caps/denials. Returns only role identity/version and candidate-specific class/reference coverage; not approval or effective deletion proof.",
 inputSchema:{type:"object",properties:{sys_id:{type:"string",pattern:ID.source}},required:["sys_id"],additionalProperties:false}});
function createDefinitionOperations({access,list,request,record,claim,isAttempted,directory}){
 const folder=path.join(directory,"definition-operation-receipts");
 const outcomes=new Map();
 function save(id,out){fs.mkdirSync(folder,{recursive:true});const fd=fs.openSync(path.join(folder,id+".json"),"w");try{fs.writeSync(fd,JSON.stringify(out));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
 async function rows(t,q,fields,limit=20){
  const filters=q.split("^").map(p=>p.match(/^([a-z_]+)=([^=]*)$/)).filter(Boolean);
  fields=[...new Set([...fields.split(","),...filters.map(f=>f[1])])].join(",");
  const r=await list(t,q,fields,limit);if(!Array.isArray(r)||r.length>=limit)throw new Error("Definition references incomplete:"+t);
  for(const row of r){if(typeof row.sys_id!=="string"||!ID.test(row.sys_id))throw new Error("Invalid definition reference ID.");
   for(const f of fields.split(","))if(!Object.hasOwn(row,f))throw new Error("Definition field omitted:"+f);
   for(const [,field,value]of filters)if(String(row[field])!==value)throw new Error("Definition queried endpoint mismatch:"+field);
  }return r;}
 async function rolePickers(){
  const all=[];let cursor="";
  for(let page=0;page<20;page++){
   const result=await list("sys_dictionary",`internal_type=user_roles${cursor?"^sys_id>"+cursor:""}^ORDERBYsys_id`,
    "sys_id,name,element,internal_type",200);
   if(!Array.isArray(result)||result.length>200)throw new Error("Native role-picker metadata response invalid.");
   for(const row of result){
    if(typeof row.sys_id!=="string"||!ID.test(row.sys_id)||row.sys_id<=cursor||row.internal_type!=="user_roles"||
     typeof row.name!=="string"||typeof row.element!=="string")throw new Error("Native role-picker cursor/identity coverage invalid.");
    cursor=row.sys_id;all.push(row);
   }
   if(result.length<200)return all;
  }
  throw new Error("Native role-picker reference class exceeds4000record bounded coverage; definition retained.");
 }
 async function pickerImpact(before){
  const pickers=await rolePickers(),references=[];
  for(const picker of pickers){
   if(!/^[a-zA-Z][a-zA-Z0-9_]{0,127}$/.test(picker.name)||!/^[a-zA-Z][a-zA-Z0-9_]{0,127}$/.test(picker.element))
    throw new Error("Native role-picker metadata unresolved; role retained.");
   const matches=await rows(picker.name,`${picker.element}LIKE${before.name}`,"sys_id",2);
   if(matches.length)references.push({table:picker.name,field:picker.element,count:matches.length});
  }
  return {class_count:pickers.length,references,complete_bounded_read_visible:true};
 }
 async function handleCore(name,args){
  if(name==="local_admin_role_delete_assess"){
   if(!args||Object.keys(args).length!==1||typeof args.sys_id!=="string"||!ID.test(args.sys_id))throw new Error("Invalid role impact assessment.");
   await access.checkPolicy();const before=await access.inspectDefinition("sys_user_role",args.sys_id);
   const users=await rows("sys_user_has_role",`role=${args.sys_id}`,"sys_id",2);
   const groups=await rows("sys_group_has_role",`role=${args.sys_id}`,"sys_id",2);
   const impact=await pickerImpact(before);
   return {sys_id:args.sys_id,name:before.name,sys_mod_count:before.sys_mod_count,...impact,
    direct_user_assignments:users.length,group_assignments:groups.length,
    candidate_references_clear:!users.length&&!groups.length&&!impact.references.length,
    meaning:"Current bounded source visibility only; unknown/denied evidence throws, not absence; no deletion authorization."};
  }
  const spec=definitions[name],tool=tools.find(t=>t.name===name);
  if(!spec||!args||Object.keys(args).some(k=>!tool.inputSchema.properties[k])||tool.inputSchema.required.some(k=>!Object.hasOwn(args,k))||
   typeof args.sys_id!=="string"||!ID.test(args.sys_id)||typeof args.operation_id!=="string"||!UUID.test(args.operation_id)||
   typeof args.expected_mod_count!=="string"||!/^\d+$/.test(args.expected_mod_count))throw new Error("Invalid definition arguments.");
  const [table,deleting]=spec;
  if(deleting?args.confirm!==true:typeof args.description!=="string"||args.description.length>200||/[\u0000-\u001f]/.test(args.description))throw new Error("Invalid definition value/confirmation.");
  if(isAttempted(args.operation_id))throw new Error("Definition operation consumed; no replay.");
  assertResourceClear(directory,args);
  if(fs.existsSync(folder))for(const f of fs.readdirSync(folder)){const p=JSON.parse(fs.readFileSync(path.join(folder,f)));
   if(p.sys_id===args.sys_id&&!["confirmed","rejected"].includes(p.status))throw new Error("Definition outcome unresolved; no cross-UUID replay.");}
  await access.checkPolicy();
  const before=await access.inspectDefinition(table,args.sys_id);
  if(before.sys_id!==args.sys_id||before.sys_mod_count!==args.expected_mod_count)throw new Error("Definition identity/version changed.");
  let children=[];
  if(deleting){
   const checks=table==="sys_user_role"?[["sys_user_has_role",`role=${args.sys_id}`],["sys_group_has_role",`role=${args.sys_id}`]]:
    [["sys_user_grmember",`group=${args.sys_id}`],["sys_group_has_role",`group=${args.sys_id}`],["task",`assignment_group=${args.sys_id}`],
     ["asmt_metric_result",`source_id=${args.sys_id}^source_table=sys_user_group`],["asmt_category_result",`source_id=${args.sys_id}^source_table=sys_user_group`]];
   for(const [t,q]of checks)if((await rows(t,q,"sys_id",2)).length)throw new Error("Definition still referenced:"+t);
   if(table==="sys_user_role"){
    const impact=await pickerImpact(before);
    if(impact.references.length)throw new Error("Native user_roles picker references this role; deletion could widen access:"+impact.references[0].table+"."+impact.references[0].field);
   }
   const childTable=table==="sys_user_role"?"sys_embedded_help_role":"asmt_assessable_record";
   const query=table==="sys_user_role"?`role=${args.sys_id}`:`source_id=${args.sys_id}^source_table=sys_user_group`;
   children=(await rows(childTable,query,"sys_id")).map(r=>({table:childTable,sys_id:r.sys_id}));
  }
  const out={operation_id:args.operation_id,action:name,table,sys_id:args.sys_id,status:"attempt",before_mod_count:args.expected_mod_count,
   native_children:children,native_effects_declared:deleting?["exact-role-name-picker-cleanup/cache","exact-group-assessment-cleanup","native-definition-cascades"]:[]};
  outcomes.set(args.operation_id,out);save(args.operation_id,out);claim(args.operation_id,{action:name,table,sys_id:args.sys_id,receipt:args.operation_id+".json"});
  let failure;
  try{await request(deleting?"DELETE":"PATCH",table,{sysparm_fields:"sys_id",sysparm_display_value:"false"},deleting?undefined:{description:args.description},args.sys_id);}catch(e){failure=e;}
  if(failure?.diagnostic?.status===401){out.status="uncertain";out.diagnostic=failure.diagnostic;save(args.operation_id,out);record(out);const e=new Error("Admin auth rejected; no further requests.");e.outcome=out;throw e;}
  try{
   const after=await rows(table,`sys_id=${args.sys_id}`,deleting?"sys_id":"sys_id,description,sys_mod_count",2);
   if(failure?.diagnostic?.status>=400&&failure.diagnostic.status<500)throw new Error("Source definition request rejected; no attribution from observed state.");
   if(deleting){
    if(after.length)throw new Error("Definition retained after delete.");
    out.absent=true;out.child_outcomes=[];
    for(const c of children)out.child_outcomes.push({...c,absent:!(await rows(c.table,`sys_id=${c.sys_id}`,"sys_id",2)).length});
    if(out.child_outcomes.some(c=>!c.absent))throw new Error("Native definition child remains; account partial effect.");
   }else{
    if(after.length!==1||after[0].sys_id!==args.sys_id||after[0].description!==args.description||after[0].sys_mod_count===args.expected_mod_count)
     throw new Error("Definition description/version not confirmed.");
    await access.inspectDefinition(table,args.sys_id);out.after_mod_count=after[0].sys_mod_count;out.description=after[0].description;
   }
  }catch(e){out.status="uncertain";out.reason=e.message;out.original_diagnostic=failure?.diagnostic;out.reconciliation_diagnostic=e.diagnostic;
   save(args.operation_id,out);record(out);const err=new Error("Definition mutation/native outcome unresolved; no replay.");err.outcome=out;throw err;}
  out.status="confirmed";out.reconciled_after_error=!!failure;save(args.operation_id,out);record(out);return out;
 }
 async function handle(name,args){
  try{return await handleCore(name,args);}catch(e){
   if(!e.outcome&&args?.operation_id&&isAttempted(args.operation_id)){
    const out=outcomes.get(args.operation_id)||{operation_id:args.operation_id,sys_id:args.sys_id,action:name};
    out.status="uncertain";out.reason="Definition receipt/journal failure; source effect must not be replayed.";
    e.outcome=out;try{save(args.operation_id,out);}catch{out.receipt_recovery_failed=true;}
   }
   throw e;
  }finally{if(outcomes.get(args?.operation_id)?.status==="confirmed")outcomes.delete(args.operation_id);}
 }
 return {tools,handle,assessRolePickerImpact:async name=>{
  if(typeof name!=="string"||!/^[a-zA-Z0-9_. -]{1,100}$/.test(name))throw new Error("Invalid literal role-name impact target.");
  return pickerImpact({name});
 }};
}
module.exports={tools,createDefinitionOperations};
