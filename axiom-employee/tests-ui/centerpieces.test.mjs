import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
const require=createRequire(import.meta.url);
const result=await build({stdin:{contents:"export * from './src/design/Centerpieces';export * from './src/design/DocumentWorkbench';",resolveDir:fileURLToPath(new URL('..',import.meta.url)),loader:'ts'},bundle:true,write:false,platform:'node',format:'esm',external:['react','react/jsx-runtime']});
const moduleCode=result.outputFiles[0].text.replace(/from "(react(?:\/jsx-runtime)?)"/g,(_,name)=>`from ${JSON.stringify(pathToFileURL(require.resolve(name)).href)}`);
const {BrowserBoundary,ClipboardTransformation,DocumentFlow,RuleNetwork,EventStream,DocumentWorkbench}=await import(`data:text/javascript;base64,${Buffer.from(moduleCode).toString('base64')}`);
const render=(Component,props)=>renderToStaticMarkup(createElement(Component,props));
const agent={status:{settings:{protection:true},sources:{clipboard:{status:'active'}},browser:{status:'connected'}},activity:[]};
const event={id:'fictional-event',source:'browser',timestamp:1700000000,action:'BLOCK',outcome:'UPLOAD_UNASSESSED',policies:[],event:'UPLOAD',detection_count:0,destination_hostname:'example.com',destination_class:'EXTERNAL',matched_text:'PRIVATE_SENTINEL_VALUE'};
test('connected browser with no events renders an idle boundary without invented packets',()=>{
 const html=render(BrowserBoundary,{agent});assert.match(html,/No browser records yet/);assert.doesNotMatch(html,/class="boundary-packet"|class="released-packet"/);
});
test('a BLOCK decision with unassessed outcome does not visually claim enforcement or release',()=>{
 const html=render(BrowserBoundary,{agent:{...agent,activity:[event]}});assert.match(html,/boundary-held/);assert.doesNotMatch(html,/result-blocked|result-lit|released-packet/);
});
test('browser visualization follows actual recorded redacted release rather than policy alone',()=>{
 const html=render(BrowserBoundary,{agent:{...agent,activity:[{...event,action:'REDACT',outcome:'UPLOAD_REDACTED'}]}});assert.match(html,/boundary-redacted/);assert.match(html,/released-packet/);assert.match(html,/Latest recorded outcome/);assert.doesNotMatch(html,/PRIVATE_SENTINEL_VALUE/);
});
test('clipboard decoration uses a labeled sample and never renders raw values from event metadata',()=>{
 const html=render(ClipboardTransformation,{agent:{...agent,activity:[{...event,source:'clipboard',outcome:'CLIPBOARD_REPLACED'}]}});assert.match(html,/Synthetic illustration only/);assert.match(html,/Project/);assert.doesNotMatch(html,/PRIVATE_SENTINEL_VALUE/);
});
test('document engine processing does not invent completed stages or expose extracted text',()=>{
 const html=render(DocumentFlow,{phase:'processing',result:{document:{sections:[{text:'PRIVATE_SENTINEL_VALUE'}]},detections:[],status:'SCANNING'}});assert.match(html,/Individual extraction\/detection\/policy progress is not reported/);assert.doesNotMatch(html,/stage-complete|PRIVATE_SENTINEL_VALUE/);
});
test('disabled custom rule network keeps its real conditions but does not print match patterns',()=>{
 const rule={id:'test',name:'Fictional rule',enabled:false,kind:'keyword',pattern:'PRIVATE_SENTINEL_VALUE',events:['UPLOAD'],destinations:['EXTERNAL'],severity:'HIGH',action:'BLOCK'};
 const html=render(RuleNetwork,{rules:[rule]});assert.match(html,/rule-disabled/);assert.match(html,/Disabled — excluded from evaluation/);assert.match(html,/UPLOAD/);assert.match(html,/EXTERNAL/);assert.doesNotMatch(html,/PRIVATE_SENTINEL_VALUE/);
});
test('empty activity stream is an explicitly idle state with no fabricated nodes',()=>{
 const html=render(EventStream,{events:[]});assert.match(html,/without simulated events/);assert.doesNotMatch(html,/class="flow-node/);
});

test('a completed BLOCK scan visualizes withheld output rather than protected release',()=>{
 const html=render(DocumentFlow,{phase:'complete',result:{detections:[{id:'fake'}],status:'BLOCKED',action:'BLOCK'}});
 assert.match(html,/stage-withheld/);assert.match(html,/Output withheld/);assert.match(html,/Output withheld by BLOCK policy/);
});

test('large scan results render a bounded finding page while preserving the real total',()=>{
 const detections=Array.from({length:121},(_,i)=>({id:String(i),type:'EMAIL',matched_text:'fictional@example.com',detector:'privacy',confidence:.99,location:{offset:0},start:i,end:i+1}));
 const result={status:'REDACTED',action:'REDACT',document:{name:'fictional.txt',type:'txt',metadata:{coverage:'Text only'},sections:[]},detections,decisions:detections.map(d=>({detection_id:d.id,rule_name:'Email privacy',severity:'MEDIUM',action:'REDACT',transformation:'MASK',reason:'Test'})),protected_sections:[]};
 const html=render(DocumentWorkbench,{result,file:null,context:{action:'OPEN',destination:'EXTERNAL'},busy:false,loaded:true,compare:false});
 assert.equal((html.match(/<summary>Reveal locally<\/summary>/g)||[]).length,50);
 assert.match(html,/of .*121.* findings/);assert.match(html,/Next findings/);
});
