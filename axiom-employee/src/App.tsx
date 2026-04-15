import { useCallback, useEffect, useState } from 'react';
import { request, encodeFile, saveNative } from './agent/client';
import { Context, Result, Rule } from './agent/types';
import { RuleEditor } from './agent/RuleEditor';
import { Background } from './agent/Background';
import {useAgent} from './agent/useAgent';
import {Overview} from './design/Overview';
import {Icon,useAmbient} from './design/Visuals';
import {Chapter} from './design/Chapter';
import {FixedSidebar} from './design/FixedSidebar';
import {useScrollNavigation,chapters} from './design/useScrollNavigation';
import {BrowserBoundary,ClipboardTransformation,DocumentFlow,RuleNetwork,SystemHealth,ScanPhase} from './design/Centerpieces';
import {DocumentWorkbench} from './design/DocumentWorkbench';
import './App.css';
import './agent/agent.css';
import './design/design.css';
import './design/motion.css';
export default function App() {
  const {viewport,active,navigate}=useScrollNavigation();
  const agent=useAgent(navigate);
  const ambient=useAmbient();
  const [compare,setCompare]=useState(false);
  const [phase,setPhase]=useState<ScanPhase>('idle');
  const [showAudit,setShowAudit]=useState(false);
  const [ruleError,setRuleError]=useState(''),[ruleNotice,setRuleNotice]=useState(''),[auditError,setAuditError]=useState('');
  const [rules,setRules]=useState<Rule[]>([]);
  const [loaded,setLoaded]=useState(false);
  const [file,setFile]=useState<File|null>(null);
  const [data,setData]=useState('');
  const [result,setResult]=useState<Result|null>(null);
  const [context,setContext]=useState<Context>({action:'OPEN',destination:'EXTERNAL'});
  const [error,setError]=useState('');
  const [notice,setNotice]=useState('');
  const [busy,setBusy]=useState(false);
  const [audit,setAudit]=useState<Record<string,string|number>[]>([]);
  useEffect(()=>{request<Rule[]>({op:'rules'}).then(r=>{setRules(r);setLoaded(true);}).catch(e=>setRuleError(String(e)));},[]);
  async function saveRules(next:Rule[]) {
    setBusy(true);setRuleError('');setRuleNotice('');
    try {setRules(await request<Rule[]>({op:'save_rules',rules:next}));setResult(null);setPhase('idle');setRuleNotice('Policies saved locally. Scan again to apply them.');}
    catch(e){setRuleError(String(e));throw e;} finally {setBusy(false);}
  }
  async function scan() {
    if (!file)return;
    setBusy(true);setError('');setNotice('');setResult(null);setPhase('reading');
    try {const encoded=await encodeFile(file);setData(encoded);setPhase('processing');setResult(await request<Result>({op:'scan',name:file.name,data:encoded,context}));setPhase('complete');}
    catch(e){setError(String(e));setPhase('error');}finally{setBusy(false);}
  }
  async function exportFile() {
    if(!file||!result)return;
    setBusy(true);setError('');
    try {
      const saved=await saveNative({name:file.name,data,context});
      if(saved!==null){setNotice(saved.saved?'Protected derivative saved locally. '+saved.warnings.join(' '):'Save canceled.');return;}
      const output=await request<{text:string;extension:string;action:string;warnings:string[]}>({op:'export',name:file.name,data,context});
      const url=URL.createObjectURL(new Blob([output.text],{type:output.extension==='csv'?'text/csv;charset=utf-8':'text/plain;charset=utf-8'}));
      const anchor=document.createElement('a');anchor.href=url;anchor.download=file.name.replace(/\.[^.]+$/,'')+'.protected.'+output.extension;anchor.click();
      setTimeout(()=>URL.revokeObjectURL(url),1000);setNotice('Protected derivative download requested. '+output.warnings.join(' '));
    }catch(e){setError(String(e));}finally{setBusy(false);}
  }
  async function openAudit(){setShowAudit(true);setAuditError('');try{setAudit(await request({op:'audit'}));navigate('audit');}catch(e){setAuditError(String(e));}}
  const onReview=useCallback((review:{result:Result;name:string;data:string})=>{setFile(new File([Uint8Array.from(atob(review.data),c=>c.charCodeAt(0))],review.name));setData(review.data);setContext({action:'OPEN',destination:'UNSPECIFIED'});setResult(review.result);setPhase('complete');setCompare(false);navigate('scan');},[navigate]);
  return <div className={`app continuous-app ${ambient?'':'ambient-inactive'}`}><div className="scenery" aria-hidden="true"/><FixedSidebar agent={agent} active={active} navigate={navigate}/>
    <main ref={viewport} className="agent-main scroll-viewport" aria-label="Axiom privacy chapters"><div className="topbar"><span>YOUR PRIVATE WORKSPACE <i> / </i> {chapters.find(([id])=>id===active)?.[1]}</span><button className="text-button" onClick={()=>void agent.refresh()}><Icon name="activity" size={16}/> Refresh status</button></div><div className="continuous-content">
      <Chapter id="overview"><Overview agent={agent} rules={rules} navigate={navigate}/>{agent.error&&<p role="alert" className="agent-error">{agent.error}</p>}<button className="next-chapter text-button" onClick={()=>navigate('activity')}>Explore your privacy system <Icon name="arrow" size={18}/></button></Chapter>
      <Chapter id="activity" title="A private record, in motion." description="Real events flow through your local privacy system. Only metadata appears here."><Background interactionBusy={busy} agent={agent} page="activity" navigate={navigate} onReview={onReview}/></Chapter>
      <Chapter id="documents" title="A little more peace of mind." description="From a local document to a protected derivative, with you in control."><DocumentFlow phase={phase} result={result} fileName={file?.name}/><div id="document-workbench" tabIndex={-1} className="focus-anchor">{error&&<div role="alert" className="agent-error">{error}</div>}{notice&&<div role="status" className="agent-notice">{notice}</div>}<DocumentWorkbench file={file} result={result} context={context} busy={busy||agent.busy} loaded={loaded} compare={compare} onFile={next=>{setFile(next);setResult(null);setData('');setNotice('');setError('');setPhase('idle');setCompare(false);}} onContext={next=>{setContext(next);setResult(null);setPhase('idle');}} onScan={()=>void scan()} onExport={()=>void exportFile()} onCompare={()=>setCompare(!compare)}/></div><Background interactionBusy={busy} agent={agent} page="documents" navigate={navigate} onReview={onReview}/></Chapter>
      <Chapter id="browser" title="A considered boundary." description="Destination-aware enforcement for supported, opted-in upload workflows."><BrowserBoundary agent={agent}/><Background interactionBusy={busy} agent={agent} page="browser" navigate={navigate} onReview={onReview}/></Chapter>
      <Chapter id="clipboard" title="Protect what you copy." description="A synthetic transformation illustrates masking. Your clipboard stays out of the visualization."><ClipboardTransformation agent={agent}/><Background interactionBusy={busy} agent={agent} page="clipboard" navigate={navigate} onReview={onReview}/></Chapter>
      <Chapter id="policies" title="Privacy, on your terms." description="See the actual match constraints of a configured rule, then shape your local policies."><RuleNetwork rules={rules}/>{ruleError&&<p className="agent-error" role="alert">{ruleError}</p>}{ruleNotice&&<p className="agent-notice" role="status">{ruleNotice}</p>}{loaded?<RuleEditor rules={rules} busy={busy} onSave={async next=>{try{await saveRules(next);return true;}catch{return false;}}}/>:<p>Loading local policies…</p>}</Chapter>
      <Chapter id="settings" title="Make yourself at home." description="Your device, your sources, your privacy. Real controls for the connected local system."><SystemHealth agent={agent}/><Background interactionBusy={busy} agent={agent} page="settings" navigate={navigate} onReview={onReview}/><section className="agent-card"><h2>Privacy & diagnostics</h2><p>Activity keeps bounded decision metadata, not clipboard contents or matched values. Policy patterns are stored locally as configuration.</p><p>Queue: {agent.status?.queued??'unavailable'} / 64 · worker: {agent.status?.worker_busy?'processing':'idle'} · dropped events: {agent.status?.dropped??'unavailable'}</p>{agent.status?.last_error&&<p role="alert">{agent.status.last_error}</p>}<button onClick={()=>void openAudit()}>Inspect local audit</button></section><section id="local-audit" tabIndex={-1} className="focus-anchor">{showAudit&&<div className="agent-card"><h2>Local audit</h2>{auditError&&<p role="alert">{auditError}</p>}<p>Metadata only; no sensitive matches, filenames, paths or document content. Latest 200 events.</p>{audit.map((event,index)=><pre key={index}>{JSON.stringify(event)}</pre>)}{!audit.length&&<p>No audit events yet.</p>}</div>}</section></Chapter>
    </div></main></div>;
}
