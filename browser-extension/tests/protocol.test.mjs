import test from 'node:test';import assert from 'node:assert/strict';
import {originOnly,validateReply,uploadOutcome,responseMatches} from '../src/protocol.js';
import {readFile} from 'node:fs/promises';
test('destination drops paths, credentials are rejected',()=>{assert.equal(originOnly('https://example.com/private?token=secret'),'https://example.com');assert.throws(()=>originOnly('https://user:pass@example.com'));assert.throws(()=>originOnly('file:///etc/passwd'));});
test('matching correlation accepted',()=>assert.deepEqual(validateReply({request_id:'one',ok:true,result:{action:'BLOCK'}},'one'),{action:'BLOCK'}));
test('stale and mismatched replies rejected',()=>{assert.throws(()=>validateReply({request_id:'old',ok:true,result:{}},'new'));assert.throws(()=>validateReply({request_id:'one',ok:'true'},'one'));});
test('disconnected agent is not protected',()=>assert.throws(()=>validateReply({request_id:'one',ok:false,error:'AGENT_UNAVAILABLE'},'one')));
test('actual outcomes stay distinct',()=>{assert.equal(uploadOutcome('BLOCK'),'UPLOAD_BLOCKED');assert.equal(uploadOutcome('REVIEW_REQUIRED'),'UPLOAD_REVIEW_REQUIRED');assert.equal(uploadOutcome('UNASSESSED'),'UPLOAD_UNASSESSED');});
test('content hashes and counts bind response',()=>{assert(responseMatches({files:[{sha256:'hash',size:5}]},[{sha256:'hash',size:5}]));assert(!responseMatches({files:[{sha256:'other',size:5}]},[{sha256:'hash',size:5}]));assert(!responseMatches({files:[]},[{sha256:'hash',size:5}]));});
test('manifest has no automatic host grant or collection permissions',async()=>{const m=JSON.parse(await readFile(new URL('../manifest.json',import.meta.url)));assert.equal(m.manifest_version,3);assert(!m.host_permissions);for(const permission of ['history','bookmarks','downloads','cookies','tabs','webRequest'])assert(!m.permissions.includes(permission));assert(!m.externally_connectable);});
test('no page-native spoof bridge or direct network API',async()=>{const s=await readFile(new URL('../src/content.js',import.meta.url),'utf8');assert(!/window\.postMessage|fetch\(|XMLHttpRequest|localStorage|sessionStorage/.test(s));assert(s.includes("input.value='';"));assert(s.includes('nativeSubmit.call(form)'));});

test("hostname normalization keeps trailing-dot destinations bindable",()=>assert.equal(originOnly("https://Company.COM.:443/path"),"https://company.com"));
