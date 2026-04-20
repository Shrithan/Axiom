export const MAX_BYTES=20*1024*1024;
export const HOST='com.axiom.browser';
export function originOnly(value){const u=new URL(value);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw Error('Unsupported destination');u.hostname=u.hostname.replace(/\.$/,'');return u.origin;}
export function validateReply(message,id){if(!message||message.request_id!==id||typeof message.ok!=='boolean')throw Error('Mismatched or stale response');if(!message.ok)throw Error(message.error||'AGENT_UNAVAILABLE');return message.result;}
export function uploadOutcome(disposition){return ({ALLOW:'UPLOAD_ALLOWED',WARN:'UPLOAD_WARNED',REDACT:'UPLOAD_REDACTED',BLOCK:'UPLOAD_BLOCKED',REVIEW_REQUIRED:'UPLOAD_REVIEW_REQUIRED',UNASSESSED:'UPLOAD_UNASSESSED'})[disposition]||'UPLOAD_UNASSESSED';}
export function responseMatches(result,snapshot){return result.files?.length===snapshot.length&&result.files.every((f,i)=>f.sha256===snapshot[i].sha256&&f.size===snapshot[i].size);}
