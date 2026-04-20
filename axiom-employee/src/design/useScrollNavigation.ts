import {useCallback,useEffect,useRef,useState} from 'react';
import {navigateChapter,observeChapters} from './scrollController';
export {chapters} from './scrollController';
export function useScrollNavigation(){
 const viewport=useRef<HTMLElement>(null);
 const [active,setActive]=useState('overview');
 const navigate=useCallback((requested:string)=>{
  // A new native scroll request replaces a previous smooth request. Wheel/trackpad
  // scrolling remains native; no scroll listener intercepts input or momentum.
  navigateChapter(viewport.current,requested,window.matchMedia('(prefers-reduced-motion: reduce)').matches);
 },[]);
 useEffect(()=>{
  const root=viewport.current;if(!root)return;
  return observeChapters(root,setActive);
 },[]);
 return {viewport,active,navigate};
}
