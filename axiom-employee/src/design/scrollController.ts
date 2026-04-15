export const chapters=[['overview','Overview'],['activity','Activity'],['documents','Documents'],['browser','Browser'],['clipboard','Clipboard'],['policies','Policies'],['settings','Settings']] as const;
const aliases:Record<string,string>={dashboard:'overview',scan:'documents',rules:'policies',audit:'settings'};
export function scrollTarget(requested:string){
 if(requested==='scan')return 'document-workbench';if(requested==='audit')return 'local-audit';
 if(Object.prototype.hasOwnProperty.call(aliases,requested))return aliases[requested];
 return chapters.some(([id])=>id===requested)?requested:null;
}
export function navigateChapter(root:HTMLElement|null,requested:string,reduced:boolean){
 const id=scrollTarget(requested);if(!id)return false;
 const target=root?.querySelector<HTMLElement>(`#${id}`);
 if(!target)return false;
 target.focus({preventScroll:true});
 target.scrollIntoView({behavior:reduced?'instant':'smooth',block:'start'});
 return true;
}
export function observeChapters(root:HTMLElement,onActive:(id:string)=>void,Observer:typeof IntersectionObserver=IntersectionObserver,Resize:typeof ResizeObserver=ResizeObserver){
 const sections=Array.from(root.querySelectorAll<HTMLElement>('[data-chapter]'));
 const visible=new Set<Element>();
 let position:IntersectionObserver|undefined;let previousHeight=-1;
 const trackPosition=()=>{
  const height=root.clientHeight;if(height===previousHeight)return;previousHeight=height;
  position?.disconnect();visible.clear();
  position=new Observer(entries=>{
  for(const entry of entries){if(entry.isIntersecting)visible.add(entry.target);else visible.delete(entry.target);}
  const first=sections.find(section=>visible.has(section));
  if(first)onActive(first.id);
  // A narrow reading line avoids two neighboring chapters competing while a
  // heading sits below the sticky toolbar. Percentage margins are width based,
  // so derive these pixel margins from the viewport height and refresh on resize.
  },{root,rootMargin:`-${Math.max(84,Math.round(height*.22))}px 0px -${Math.max(0,height-Math.max(84,Math.round(height*.22))-2)}px 0px`,threshold:0});
  for(const section of sections)position.observe(section);
 };
 trackPosition();
 const motion=new Observer(entries=>{
  for(const entry of entries){const element=entry.target as HTMLElement;if(element.dataset.motion!==undefined){element.dataset.motionVisible=String(entry.isIntersecting);}else{element.dataset.visible=String(entry.isIntersecting);if(entry.isIntersecting)element.dataset.entered='true';}}
 },{root,rootMargin:'0px',threshold:0});
 for(const element of [...sections,...root.querySelectorAll<HTMLElement>('[data-motion]')])motion.observe(element);
 const resize=new Resize(trackPosition);resize.observe(root);
 return()=>{position?.disconnect();motion.disconnect();resize.disconnect();visible.clear();};
}
