import { invoke, isTauri } from '@tauri-apps/api/core';
let token = '';
export async function request<T>(payload: Record<string, unknown>): Promise<T> {
  if (isTauri()) return invoke<T>('agent_request', { request:payload });
  if (!token) {
    const session = await fetch('/api/session', {cache:'no-store'});
    if (!session.ok || !session.headers.get('content-type')?.includes('application/json')) throw new Error('Use npm run build followed by npm run local, or start the Tauri desktop app.');
    token = (await session.json()).token;
  }
  const response = await fetch('/api/agent', {method:'POST',headers:{'Content-Type':'application/json','X-Axiom-Token':token},body:JSON.stringify(payload)});
  const body = await response.json();
  if (!response.ok || body.error) throw new Error(body.error || 'Local operation failed');
  return body.result as T;
}
export async function encodeFile(file: File): Promise<string> {
  if (!file.size || file.size > 20*1024*1024) throw new Error('Select a nonempty file smaller than 20 MiB.');
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset,offset+8192));
  return btoa(binary);
}

export async function saveNative(payload: Record<string, unknown>): Promise<{saved:boolean;warnings:string[]}|null> {
  if (!isTauri()) return null;
  return invoke<{saved:boolean;warnings:string[]}>('save_protected', {request:payload});
}
