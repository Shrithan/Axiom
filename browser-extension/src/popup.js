import {originOnly} from './protocol.js';
import {siteCoverage} from './coverage.js';
const $=id=>document.getElementById(id);let origin;
try{const [tab]=await chrome.tabs.query({active:true,currentWindow:true});origin=originOnly(tab.url);$('site').textContent=new URL(origin).hostname;const coverage=siteCoverage(origin);$('coverage').textContent=coverage.message;$('enable').textContent=coverage.label;if(coverage.mode==='gmail-drop-guard')$('coverage').setAttribute('role','alert');}catch{$('site').textContent='Unsupported page';$('enable').disabled=true;}
const result=await chrome.runtime.sendMessage({op:'hello'});
$('status').textContent=result.ok&&result.result.status==='connected'?'● Connected to local Axiom Agent':'○ Agent unavailable or protection paused';
if(origin&&result.ok){const classification=await chrome.runtime.sendMessage({op:'classify',payload:{origin}});if(classification.ok)$('classification').textContent=classification.result.classification;}
$('enable').onclick=async()=>{const pattern=origin+'/*';const granted=await chrome.permissions.request({origins:[pattern]});if(granted){await chrome.runtime.sendMessage({op:'register'});$('feedback').textContent=(siteCoverage(origin).mode==='gmail-drop-guard'?'Gmail drop guard enabled. Reload Gmail. All file drops will be blocked; other attachment paths remain unprotected.':'Site access granted. Reload before selecting files. Only standard multipart forms are covered; custom upload flows remain unprotected.');}else $('feedback').textContent='Site access was not granted.';};
$('open').onclick=()=>chrome.runtime.sendMessage({op:'open_app'});
