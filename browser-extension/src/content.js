/* Isolated world, document_start, opt-in sites. No page-message bridge or detector code. */
(() => {
 'use strict';
 const MAX=20*1024*1024,held=new Map(),running=new WeakSet();let version=0,overlay=null,overlayResolve=null;
 const nativeSubmit=HTMLFormElement.prototype.submit,nativeCheck=HTMLFormElement.prototype.checkValidity;
 const send=async(op,payload=null,request_id=crypto.randomUUID())=>{const response=await chrome.runtime.sendMessage({op,payload,request_id});if(!response?.ok)throw Error(response?.error||'AGENT_UNAVAILABLE');return response.result;};
 const stop=e=>{e.preventDefault();e.stopImmediatePropagation();};
 const origin=value=>{const u=new URL(value,document.baseURI);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw Error('Unsupported destination');u.hostname=u.hostname.replace(/\.$/,'');return u.origin;};
 function show(title,message,decision=null,confirm=false){
  overlayResolve?.(false);overlayResolve=null;overlay?.remove();const host=document.createElement('div');host.style.cssText='position:fixed;inset:0;z-index:2147483647;background:#0009;display:grid;place-items:center';
  const root=host.attachShadow({mode:'closed'}),card=document.createElement('section');card.style.cssText='width:min(430px,85vw);padding:28px;background:#111522;color:#eef;border:1px solid #8670ca;border-radius:18px;font:15px/1.6 system-ui;box-shadow:0 24px 80px #0009';
  const add=(tag,text)=>{const node=document.createElement(tag);node.textContent=text;card.append(node);return node;};
  add('small','AXIOM · LOCAL BROWSER PROTECTION');add('h2',title);add('p',message);
  if(decision){add('p','Destination: '+decision.destination_hostname+' · '+decision.destination_class);add('p','Policies: '+(decision.policies?.map(p=>p.rule_name).join(', ')||'No matched policy'));}
  add('small','Sensitive matches stay hidden. Original files are unchanged.');
  const button=label=>{const b=add('button',label);b.style.cssText='padding:10px 16px;margin:18px 8px 0 0;border-radius:8px;border:1px solid #8f73d2;background:#312347;color:white;cursor:pointer';return b;};
  root.append(card);(document.documentElement||document).append(host);overlay=host;
  return new Promise(resolve=>{overlayResolve=resolve;button(confirm?'Cancel':'Close').onclick=()=>{host.remove();if(overlay===host){overlay=null;overlayResolve=null;}resolve(false);};if(confirm)button('Continue').onclick=()=>{host.remove();if(overlay===host){overlay=null;overlayResolve=null;}resolve(true);};button('Open Axiom').onclick=()=>void send('open_app').catch(()=>{});});
 }
 function inputEvent(e){const input=e.composedPath()[0];if(!(input instanceof HTMLInputElement)||input.type!=='file')return;
  const files=Array.from(input.files||[]);if(!files.length&&!held.has(input))return;stop(e);
  // Clear synchronously before page listeners or asynchronous inspection can run.
  if(files.length){held.set(input,{files,required:input.required,version:++version});input.value='';input.required=false;void show('Files held for local review','Close this notice, then click the form’s upload/submit button to evaluate its actual destination. Custom AJAX and drag-and-drop uploads are not supported.');}
 }
 const formInputs=form=>Array.from(form.elements).filter(input=>held.has(input));
 function context(form,submitter){
  const action=submitter?.hasAttribute('formaction')?submitter.formAction:form.action;
  const method=(submitter?.hasAttribute('formmethod')?submitter.formMethod:form.method).toLowerCase();
  const encoding=(submitter?.hasAttribute('formenctype')?submitter.formEnctype:form.enctype).toLowerCase();
  if(method!=='post'||encoding!=='multipart/form-data')throw Error('Only standard POST multipart upload forms are supported');
  const target=submitter?.hasAttribute('formtarget')?submitter.formTarget:form.target;
  return {action,method,encoding,target,origin:origin(action)};
 }
 const sameContext=(a,b)=>['action','method','encoding','target','origin'].every(key=>a[key]===b[key]);
 function toBase64(bytes){let text='';for(let offset=0;offset<bytes.length;offset+=8192)text+=String.fromCharCode(...bytes.subarray(offset,offset+8192));return btoa(text);}
 const digest=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),v=>v.toString(16).padStart(2,'0')).join('');
 function clear(form){for(const input of formInputs(form)){const entry=held.get(input);input.value='';input.required=entry.required;held.delete(input);}version++;}
 async function submit(form,submitter){
  if(running.has(form))return;running.add(form);let result=null;
  try{
   const inputs=formInputs(form);if(!inputs.length||!nativeCheck.call(form))return;
   const before=context(form,submitter),generation=version,snapshot=[];let total=0;
   for(const input of inputs){const entry=held.get(input);for(const file of entry.files){
    total+=file.size;if(!file.size||file.size>MAX||total>MAX||snapshot.length>=10)throw Error('File selection exceeds the 20 MiB combined / 10-file inspection limit');
    const bytes=new Uint8Array(await file.arrayBuffer());if(bytes.length!==file.size)throw Error('File changed while reading');
    snapshot.push({input,entry,file:new File([bytes],file.name,{type:file.type,lastModified:file.lastModified}),bytes,name:file.name,size:bytes.length,sha256:await digest(bytes)});
   }}
   const id=crypto.randomUUID();void show('Inspecting locally','The selected files remain held. No selected file bytes have been released to this form.');
   result=await send('evaluate',{request_id:id,origin:before.origin,files:snapshot.map(({name,size,sha256,bytes})=>({name,size,sha256,data:toBase64(bytes)}))},id);
   const stale=()=>version!==generation||!form.isConnected||!sameContext(before,context(form,submitter))||snapshot.some(s=>held.get(s.input)!==s.entry);
   if(stale())throw Error('Selection or destination changed. Retry the upload.');
   if(result.request_id!==id||result.origin!==before.origin||result.files?.length!==snapshot.length||result.files.some((f,i)=>f.sha256!==snapshot[i].sha256||f.size!==snapshot[i].size))throw Error('Mismatched local decision');
   const disposition=result.disposition;
   if(['BLOCK','UNASSESSED','REVIEW_REQUIRED'].includes(disposition)){
    clear(form);await send('commit',{decision_id:id,receipt:result.receipt,outcome:({BLOCK:'UPLOAD_BLOCKED',UNASSESSED:'UPLOAD_UNASSESSED',REVIEW_REQUIRED:'UPLOAD_REVIEW_REQUIRED'})[disposition]});
    void show(disposition==='BLOCK'?'Upload blocked by Axiom':disposition==='REVIEW_REQUIRED'?'Protected derivative review required':'Upload not assessed',disposition==='REVIEW_REQUIRED'?'This format cannot be safely sanitized for automatic upload. Open Axiom and review a protected derivative.':'The intercepted file upload has been prevented. No selected file bytes were released.',result);return;
   }
   if(!['ALLOW','WARN','REDACT'].includes(disposition))throw Error('Unknown policy decision');
   if(disposition==='WARN'||disposition==='REDACT'){
    const accepted=await show(disposition==='WARN'?'Policy warning':'Send a protected text derivative?',disposition==='WARN'?'Review these policies before allowing this upload.':'Axiom will upload a protected TXT derivative. It will not modify your original file.',result,true);
    if(!accepted){clear(form);await send('commit',{decision_id:id,receipt:result.receipt,outcome:'UPLOAD_CANCELED'});return;}
   }
   if(stale())throw Error('Selection or destination changed. Retry the upload.');
   const authorization=await send('authorize',{decision_id:id,receipt:result.receipt});if(!authorization.authorized)throw Error('Stale authorization');
   // No await between this context check and native form serialization.
   if(stale())throw Error('Selection or destination changed. Retry the upload.');
   const replacements=snapshot.map((s,i)=>{const d=result.files[i];if(!d.derivative)return s.file;return new File([Uint8Array.from(atob(d.derivative),c=>c.charCodeAt(0))],d.derivative_name,{type:'text/plain'});});
   for(const input of inputs){const transfer=new DataTransfer();snapshot.forEach((s,i)=>{if(s.input===input)transfer.items.add(replacements[i]);});input.files=transfer.files;input.required=held.get(input).required;}
   form.action=before.action;form.method=before.method;form.enctype=before.encoding;form.target=before.target;
   let extra;if(submitter?.name){extra=document.createElement('input');extra.type='hidden';extra.name=submitter.name;extra.value=submitter.value;form.append(extra);}
   nativeSubmit.call(form);extra?.remove();clear(form);overlay?.remove();overlay=null;
   void send('commit',{decision_id:id,receipt:result.receipt,outcome:({ALLOW:'UPLOAD_ALLOWED',WARN:'UPLOAD_WARNED',REDACT:'UPLOAD_REDACTED'})[disposition]}).catch(()=>{});
  }catch(error){if(result)void send('commit',{decision_id:result.request_id,receipt:result.receipt,outcome:'UPLOAD_CANCELED'}).catch(()=>{});clear(form);void show('Upload held — protection unavailable',String(error.message||'Local inspection failed')+'. The intercepted upload was not released.');}
  finally{running.delete(form);}
 }
 // Gmail custom uploads have no proven safe release path. Withhold every file drop.
 // This is a conservative UI boundary, not a detector-backed Gmail adapter.
 if(location.hostname==='mail.google.com'){
  const fileDrag=e=>Array.from(e.dataTransfer?.items||[]).some(item=>item.kind==='file')||!!e.dataTransfer?.files?.length;
  for(const type of ['dragenter','dragover'])window.addEventListener(type,e=>{if(fileDrag(e))stop(e);},true);
  window.addEventListener('drop',e=>{if(!fileDrag(e))return;stop(e);void show('Gmail file drop blocked','Axiom blocks all file drops on Gmail because selective attachment inspection is not implemented. No file from this drop was released through the page event. Paperclip attachments, Google Drive attachments and email sending are not protected.');},true);
  void send('hello').catch(()=>{});return;
 }
 window.addEventListener('input',inputEvent,true);window.addEventListener('change',inputEvent,true);
 window.addEventListener('reset',e=>{if(e.target instanceof HTMLFormElement){clear(e.target);overlayResolve?.(false);overlayResolve=null;overlay?.remove();overlay=null;}},true);
 window.addEventListener('submit',e=>{const form=e.target;if(form instanceof HTMLFormElement&&formInputs(form).length){stop(e);void submit(form,e.submitter);}},true);
 window.addEventListener('click',e=>{const target=e.composedPath().find(node=>node instanceof HTMLButtonElement||node instanceof HTMLInputElement);if(!target||!['submit','image'].includes(target.type)||!target.form||!formInputs(target.form).length)return;stop(e);void submit(target.form,target);},true);
 window.addEventListener('keydown',e=>{if(e.key!=='Enter'||e.target instanceof HTMLTextAreaElement)return;const form=e.target.form;if(form&&formInputs(form).length){stop(e);void submit(form,null);}},true);
 void send('hello').catch(()=>{});
})();
