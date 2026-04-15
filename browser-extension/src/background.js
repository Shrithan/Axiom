import {HOST,originOnly,validateReply} from './protocol.js';
let port=null;const pending=new Map();let lastDecision=null;
function native(op,payload=null,id=crypto.randomUUID()){
 if(pending.size>=4)return Promise.reject(Error('Local inspection queue is busy'));
 return new Promise((resolve,reject)=>{
  if(!port){try{port=chrome.runtime.connectNative(HOST);}catch{reject(Error('AGENT_UNAVAILABLE'));return;}
   port.onMessage.addListener(message=>{const item=pending.get(message.request_id);if(!item)return;pending.delete(message.request_id);clearTimeout(item.timer);try{item.resolve(validateReply(message,message.request_id));}catch(e){item.reject(e);}});
   port.onDisconnect.addListener(()=>{const reason=chrome.runtime.lastError?.message;port=null;for(const item of pending.values()){clearTimeout(item.timer);item.reject(Error('AGENT_UNAVAILABLE'));}pending.clear();void reason;});
  }
  const timer=setTimeout(()=>{pending.delete(id);reject(Error('Local inspection timed out; upload remains held'));},34000);
  pending.set(id,{resolve,reject,timer});try{port.postMessage({op,request_id:id,payload});}catch{pending.delete(id);clearTimeout(timer);reject(Error('AGENT_UNAVAILABLE'));}
 });
}
async function register(){const grants=await chrome.permissions.getAll();const origins=grants.origins||[];const existing=await chrome.scripting.getRegisteredContentScripts();if(existing.length)await chrome.scripting.unregisterContentScripts({ids:existing.map(s=>s.id)});if(origins.length)await chrome.scripting.registerContentScripts([{id:'axiom-upload-gate',matches:origins,js:['src/content.js'],runAt:'document_start',allFrames:true,world:'ISOLATED',persistAcrossSessions:true}]);}
chrome.runtime.onInstalled.addListener(()=>void register());chrome.runtime.onStartup.addListener(()=>void register());chrome.permissions.onAdded.addListener(()=>void register());chrome.permissions.onRemoved.addListener(()=>void register());
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
 const ours=sender.id===chrome.runtime.id;
 if(!ours||!message||typeof message.op!=='string'){reply({ok:false,error:'INVALID_MESSAGE'});return;}
 const content=!!sender.tab;
 const allowed=content?['evaluate','authorize','commit','open_app','hello']:['hello','classify','open_app','register'];
 if(!allowed.includes(message.op)){reply({ok:false,error:'UNKNOWN_OPERATION'});return;}
 if(content&&(!sender.url||!/^https?:/.test(sender.url))){reply({ok:false,error:'INVALID_SOURCE'});return;}
 if(message.op==='register'){register().then(()=>reply({ok:true,result:{registered:true}})).catch(()=>reply({ok:false,error:'REGISTRATION_FAILED'}));return true;}
 const id=message.request_id||crypto.randomUUID();
 if(message.op==='evaluate'){
  if(!message.payload||message.payload.request_id!==id){reply({ok:false,error:'MISMATCHED_REQUEST_ID'});return;}
  try{message.payload.origin=originOnly(message.payload.origin);}catch{reply({ok:false,error:'INVALID_DESTINATION'});return;}
 }
 native(message.op,message.payload,id).then(result=>{if(message.op==='evaluate')lastDecision={action:result.action,disposition:result.disposition,hostname:result.destination_hostname,policies:result.policies};reply({ok:true,result,lastDecision});}).catch(e=>reply({ok:false,error:e.message}));return true;
});
// Metadata-only heartbeat. No visited origins or page contents.
setInterval(()=>{if(port)void native('hello').catch(()=>{});},20000);
