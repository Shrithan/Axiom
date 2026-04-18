import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import ts from 'typescript';
const source=await readFile(new URL('../src/design/scrollController.ts',import.meta.url),'utf8');
const code=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.ESNext}}).outputText;
const {navigateChapter,observeChapters,scrollTarget}=await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
function fixture(){
 const sections=['overview','activity','documents','browser','clipboard','policies','settings'].map(id=>({id,dataset:{},focusCalls:[],scrollCalls:[],focus(value){this.focusCalls.push(value);},scrollIntoView(value){this.scrollCalls.push(value);}}));
 const anchors=['document-workbench','local-audit'].map(id=>({id,focus(){},scrollCalls:[],scrollIntoView(value){this.scrollCalls.push(value);}}));
 const frames=Array.from({length:3},(_,i)=>({id:'frame-'+i,dataset:{motion:'true'}}));
 const root={clientHeight:1000,querySelectorAll(selector){return selector==='[data-chapter]'?sections:frames;},querySelector(selector){return [...sections,...anchors].find(s=>`#${s.id}`===selector);}};
 const observers=[];
 class Observer{constructor(callback,options){this.callback=callback;this.options=options;this.observed=[];this.disconnected=false;observers.push(this);}observe(target){this.observed.push(target);}disconnect(){this.disconnected=true;}emit(...entries){this.callback(entries.map(([index,isIntersecting])=>({target:sections[index],isIntersecting})));}emitTarget(target,isIntersecting){this.callback([{target,isIntersecting}]);}}
 const resizers=[];class Resize{constructor(callback){this.callback=callback;this.disconnected=false;resizers.push(this);}observe(){}disconnect(){this.disconnected=true;}}
 return {root,sections,frames,anchors,observers,Observer,Resize,resizers};
}
test('native legacy links and document-review links resolve to mounted sections',()=>{
 assert.equal(scrollTarget('dashboard'),'overview');assert.equal(scrollTarget('rules'),'policies');assert.equal(scrollTarget('scan'),'document-workbench');assert.equal(scrollTarget('audit'),'local-audit');
 const f=fixture();navigateChapter(f.root,'scan',false);assert.equal(f.anchors[0].scrollCalls.length,1);
});
test('navigation focuses without jumping first, then delegates smooth scrolling to the browser',()=>{
 const f=fixture();assert.equal(navigateChapter(f.root,'clipboard',false),true);assert.deepEqual(f.sections[4].focusCalls,[{preventScroll:true}]);assert.deepEqual(f.sections[4].scrollCalls,[{behavior:'smooth',block:'start'}]);
});
test('reduced-motion navigation never requests smooth scrolling',()=>{
 const f=fixture();navigateChapter(f.root,'policies',true);assert.equal(f.sections[5].scrollCalls[0].behavior,'instant');
});
test('unknown or malformed native navigation requests are safe no-ops',()=>{
 const f=fixture();for(const id of ['missing','toString','#bad['])assert.equal(navigateChapter(f.root,id,false),false);assert.equal(navigateChapter(null,'overview',false),false);
});
test('scroll tracking follows forward and reverse boundary crossings without requiring clicks',()=>{
 const f=fixture();const active=[];observeChapters(f.root,id=>active.push(id),f.Observer,f.Resize);
 const map=f.observers[0];map.emit([0,true]);map.emit([0,false],[1,true]);map.emit([1,false],[3,true]);map.emit([3,false],[2,true]);assert.deepEqual(active,['overview','activity','browser','documents']);
});
test('overlapping chapter entries retain document order, independent of callback order',()=>{
 const f=fixture();const active=[];observeChapters(f.root,id=>active.push(id),f.Observer,f.Resize);f.observers[0].emit([3,true],[2,true]);assert.equal(active.at(-1),'documents');f.observers[0].emit([2,false]);assert.equal(active.at(-1),'browser');
});
test('offscreen motion pauses, entrances stay marked, and observer cleanup disconnects both lanes',()=>{
 const f=fixture();const stop=observeChapters(f.root,()=>{},f.Observer,f.Resize);const motion=f.observers[1];motion.emit([2,true]);assert.deepEqual(f.sections[2].dataset,{visible:'true',entered:'true'});motion.emit([2,false]);assert.deepEqual(f.sections[2].dataset,{visible:'false',entered:'true'});stop();assert.ok(f.observers.every(o=>o.disconnected));assert.equal(f.observers[0].observed.length,7);assert.equal(f.observers[1].observed.length,10);
});

test('resizing recomputes a height-based active band and disconnects the old observer',()=>{
 const f=fixture();const stop=observeChapters(f.root,()=>{},f.Observer,f.Resize);
 assert.equal(f.observers[0].options.rootMargin,'-220px 0px -778px 0px');
 f.root.clientHeight=560;f.resizers[0].callback();assert.ok(f.observers[0].disconnected);
 assert.equal(f.observers[2].options.rootMargin,'-123px 0px -435px 0px');
 stop();assert.ok(f.resizers[0].disconnected);
});

test('a centerpiece can pause independently while its long chapter remains visible',()=>{
 const f=fixture();observeChapters(f.root,()=>{},f.Observer,f.Resize);const motion=f.observers[1];
 motion.emit([2,true]);motion.emitTarget(f.frames[0],true);motion.emitTarget(f.frames[0],false);
 assert.equal(f.sections[2].dataset.visible,'true');assert.equal(f.frames[0].dataset.motionVisible,'false');
});
