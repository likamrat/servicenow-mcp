const fs=require("node:fs"),path=require("node:path");
function assertResourceClear(directory,args){
 const current=["user","group","role","sys_id"].filter(k=>typeof args[k]==="string").map(k=>args[k]);
 for(const folder of ["access-operation-receipts","definition-operation-receipts","definition-adoption-receipts"]){
  const dir=path.join(directory,folder);if(!fs.existsSync(dir))continue;
  for(const name of fs.readdirSync(dir).filter(n=>n.endsWith(".json")&&!n.endsWith(".managed.json"))){
   if(folder==="definition-adoption-receipts"&&!name.endsWith(".operation.json"))continue;
   const prior=JSON.parse(fs.readFileSync(path.join(dir,name),"utf8"));
   if(["confirmed","rejected"].includes(prior.status))continue;
   const resources=["user","group","role","sys_id"].filter(k=>typeof prior[k]==="string").map(k=>prior[k]);
   if(current.some(id=>resources.includes(id))||typeof args.name==="string"&&typeof prior.name==="string"&&args.name===prior.name)
    throw new Error("Matching access/definition resource has a nonterminal receipt; reconcile without new-UUID replay.");
  }
 }
}
module.exports={assertResourceClear};
