import { useState } from 'react';
import { Rule } from './types';
const blank = (): Rule => ({id:crypto.randomUUID(),name:'',kind:'keyword',pattern:'',case_sensitive:false,severity:'HIGH',action:'REDACT',transformation:'REDACT',replacement:'[PROTECTED]',enabled:true,destinations:[],events:[]});
export function RuleEditor({rules,onSave,busy}:{rules:Rule[];onSave:(rules:Rule[])=>Promise<boolean>;busy:boolean}) {
  const [draft,setDraft] = useState<Rule>(blank);
  const update = (change:Partial<Rule>) => setDraft({...draft,...change});
  return <section className="agent-card"><h2>Local organization rules</h2><p>Rules apply to this device. Built-in detection and organizational decisions are configured separately.</p>
    <form onSubmit={async e=>{e.preventDefault();if(await onSave([...rules.filter(r=>r.id!==draft.id),draft]))setDraft(blank());}}>
      <div className="agent-fields">
        <label>Rule name<input required maxLength={100} value={draft.name} onChange={e=>update({name:e.target.value})}/></label>
        <label>Detector<select value={draft.kind} onChange={e=>update({kind:e.target.value as Rule['kind']})}><option value="keyword">Keyword</option><option value="regex">Regex</option><option value="builtin">Built-in category</option></select></label>
        <label>Match{draft.kind==='builtin'?<select value={draft.pattern} onChange={e=>update({pattern:e.target.value})}><option value="">Choose category</option>{['SSN','EMAIL','PHONE','CARD','IP_ADDRESS','API_KEY','PRIVATE_KEY','BEARER_TOKEN','CONNECTION_STRING','URL_CREDENTIALS'].map(v=><option key={v}>{v}</option>)}</select>:<input required maxLength={512} value={draft.pattern} onChange={e=>update({pattern:e.target.value})} placeholder="penguin"/>}</label>
        <label>Severity<select value={draft.severity} onChange={e=>update({severity:e.target.value})}>{['LOW','MEDIUM','HIGH','CRITICAL'].map(v=><option key={v}>{v}</option>)}</select></label>
        <label>Action<select value={draft.action} onChange={e=>update({action:e.target.value})}>{['ALLOW','WARN','REDACT','BLOCK'].map(v=><option key={v}>{v}</option>)}</select></label>
        <label>Transformation<select value={draft.transformation} onChange={e=>update({transformation:e.target.value})}>{['REDACT','MASK','REMOVE','REPLACE'].map(v=><option key={v}>{v}</option>)}</select></label>
        {draft.transformation==='REPLACE'&&<label>Replacement<input maxLength={200} value={draft.replacement} onChange={e=>update({replacement:e.target.value})}/></label>}
        <label>Destination<select value={draft.destinations[0]||''} onChange={e=>update({destinations:e.target.value?[e.target.value]:[]})}><option value="">Any</option>{['UNSPECIFIED','INTERNAL','PARTNER','EXTERNAL','PUBLIC'].map(v=><option key={v}>{v}</option>)}</select></label>
        <label>Event<select value={draft.events[0]||''} onChange={e=>update({events:e.target.value?[e.target.value]:[]})}><option value="">Any</option>{['FILE_CREATED','FILE_MODIFIED','OPEN','COPY','PASTE','ATTACH','UPLOAD','EXPORT','PRINT','SEND','SCREEN_SHARE'].map(v=><option key={v}>{v}</option>)}</select></label>
      </div>
      <label><input type="checkbox" checked={draft.case_sensitive} onChange={e=>update({case_sensitive:e.target.checked})}/> Case sensitive</label>
      <label><input type="checkbox" checked={draft.enabled} onChange={e=>update({enabled:e.target.checked})}/> Enabled</label>
      <button disabled={busy}>Save rule</button><button type="button" onClick={()=>setDraft(blank())}>Clear</button>
    </form>
    <div className="agent-table"><table><thead><tr><th>Rule</th><th>Match</th><th>Action</th><th>Enabled</th><th>Edit</th></tr></thead><tbody>{rules.map(r=><tr key={r.id}><td data-label="Rule">{r.name}<small>{r.severity} · {r.destinations.join(', ')||'Any destination'} · {r.events.join(', ')||'Any event'}</small></td><td data-label="Match">{r.pattern}</td><td data-label="Action">{r.action}{r.action==='REDACT'&&` / ${r.transformation}`}</td><td data-label="Enabled"><input aria-label={`Enable ${r.name}`} type="checkbox" checked={r.enabled} disabled={busy} onChange={()=>void onSave(rules.map(v=>v.id===r.id?{...v,enabled:!v.enabled}:v))}/></td><td data-label="Edit"><button disabled={busy} onClick={()=>setDraft({...r})}>Edit</button><button disabled={busy} onClick={()=>void onSave(rules.filter(v=>v.id!==r.id))}>Delete</button></td></tr>)}</tbody></table></div>
  </section>;
}
