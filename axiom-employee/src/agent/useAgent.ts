import {useCallback,useEffect,useState} from 'react';
import {invoke,isTauri} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import {request} from './client';
import {BrowserState} from './BrowserPanel';
export type Settings={protection:boolean;clipboard:boolean;files:boolean;notifications:boolean;folders:string[]};
export type Status={browser?:BrowserState;native:boolean;settings:Settings;sources:Record<string,{status:string;error?:string}>;queued:number;worker_busy:boolean;dropped:number;last_error?:string};
export type Activity={destination_hostname?:string;destination_class?:string;id:string;timestamp:number;source:string;event:string;action:string;outcome:string;document_type:string;detection_count:number;policies:{rule_name:string;severity:string;action:string}[]};
export function useAgent(navigate:(page:string)=>void){
 const [status,setStatus]=useState<Status|null>(null),[activity,setActivity]=useState<Activity[]>([]),[stats,setStats]=useState<Record<string,number>>({}),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const acceptStatus=useCallback((value:Status)=>setStatus(previous=>JSON.stringify(previous)===JSON.stringify(value)?previous:value),[]);
 const refresh=useCallback(async()=>{try{const [events,counts]=await Promise.all([request<Activity[]>({op:'activity'}),request<Record<string,number>>({op:'activity_stats'})]);setActivity(events);setStats(counts);if(isTauri())acceptStatus(await invoke('agent_status'));setError('');}catch(e){setError(String(e));}},[acceptStatus]);
 useEffect(()=>{let disposed=false;const cleanup:(()=>void)[]=[];void refresh();if(isTauri())Promise.all([listen('axiom-status',()=>{void invoke<Status>('agent_status').then(value=>{if(!disposed)acceptStatus(value);}).catch(()=>{});}),listen<BrowserState>('axiom-browser-status',e=>{if(!disposed)setStatus(previous=>previous&&JSON.stringify(previous.browser)!==JSON.stringify(e.payload)?{...previous,browser:e.payload}:previous);}),listen('axiom-activity',()=>{if(!disposed)void refresh();}),listen<string>('axiom-navigate',e=>navigate(e.payload))]).then(list=>{if(disposed)list.forEach(f=>f());else cleanup.push(...list);}).catch(e=>{if(!disposed)setError(String(e));});return()=>{disposed=true;cleanup.forEach(f=>f());};},[refresh,navigate,acceptStatus]);
 async function configure(next:Settings){setBusy(true);setError('');try{await invoke('agent_configure',{settings:next});acceptStatus(await invoke('agent_status'));}catch(e){setError(String(e));}finally{setBusy(false);}}
 return {status,setStatus,activity,stats,error,setError,busy,setBusy,refresh,configure};
}
export type Agent=ReturnType<typeof useAgent>;
