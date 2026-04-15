import {useEffect,useId,useState} from 'react';
export function Icon({name,size=20}:{name:string;size?:number}){
 const paths:Record<string,string>={dashboard:'M3 10 12 3l9 7M5 9v12h5v-7h4v7h5V9',activity:'M3 12h4l3-8 4 16 3-8h4',documents:'M6 3h8l4 4v14H6V3Zm8 0v5h4M9 12h6M9 16h6',scan:'M4 8V4h4m8 0h4v4m0 8v4h-4M8 20H4v-4M8 12h8',browser:'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z',clipboard:'M8 5H5v16h14V5h-3M8 3h8v4H8V3Zm0 9h8m-8 4h6',rules:'M12 3 3 7v6c0 4 5 7 9 9 4-2 9-5 9-9V7l-9-4Zm-4 9 3 3 5-6',settings:'M9 3h6l1 4 4 1 1 6-4 2-1 5h-6l-1-4-5-2V9l4-2 1-4Zm6 9a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',arrow:'M4 12h16m-6-6 6 6-6 6',lock:'M6 10h12v11H6V10Zm3 0V6a3 3 0 0 1 6 0v4',search:'M16 16l5 5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Z',pause:'M8 5v14M16 5v14'};
 return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]||paths.documents}/></svg>;
}
export function useAmbient(){
 const [active,setActive]=useState(!document.hidden&&document.hasFocus());
 useEffect(()=>{const update=()=>setActive(!document.hidden&&document.hasFocus());document.addEventListener('visibilitychange',update);window.addEventListener('focus',update);window.addEventListener('blur',update);return()=>{document.removeEventListener('visibilitychange',update);window.removeEventListener('focus',update);window.removeEventListener('blur',update);};},[]);return active;
}
export function Orb({enabled,event}:{enabled:boolean;event?:string}){
 const id=useId().replace(/:/g,'');
 return <div className={`orb ${enabled?'orb-active':'orb-paused'}`} aria-hidden="true"><svg className="orb-sculpture" viewBox="0 0 460 460"><defs>
 <radialGradient id={`${id}body`} cx="65%" cy="30%" r="75%"><stop stopColor="#c1d9ea" stopOpacity=".65"/><stop offset=".32" stopColor="#7e8ba9" stopOpacity=".32"/><stop offset=".65" stopColor="#102630" stopOpacity=".6"/><stop offset=".88" stopColor="#7975aa" stopOpacity=".7"/><stop offset="1" stopColor="#e3c9e6" stopOpacity=".9"/></radialGradient>
 <linearGradient id={`${id}ribbon`} x1="0" y1="0" x2="1" y2="1"><stop stopColor="#ffd4b6" stopOpacity=".95"/><stop offset=".3" stopColor="#b3accf" stopOpacity=".65"/><stop offset=".55" stopColor="#283344" stopOpacity=".2"/><stop offset=".8" stopColor="#94d6f4" stopOpacity=".7"/><stop offset="1" stopColor="#d7c1ee" stopOpacity=".9"/></linearGradient>
 <linearGradient id={`${id}edge`}><stop stopColor="#e6b5a2"/><stop offset=".5" stopColor="#a8d3e2" stopOpacity=".3"/><stop offset="1" stopColor="#b8aad7"/></linearGradient>
 <radialGradient id={`${id}shine`}><stop stopColor="#edf7ff" stopOpacity=".7"/><stop offset="1" stopColor="#d2c5e8" stopOpacity="0"/></radialGradient>
 </defs><g className="orb-orbits" fill="none" stroke={`url(#${id}edge)`} strokeWidth=".65"><ellipse cx="230" cy="230" rx="198" ry="185" transform="rotate(-28 230 230)"/><ellipse cx="230" cy="230" rx="212" ry="116" transform="rotate(-35 230 230)"/></g>
 <g className="orb-body"><path d="M231 66C312 56 360 125 378 206c19 86-20 155-91 185-74 31-157 0-192-70-31-62-26-140 12-193 34-47 67-49 124-62Z" fill={`url(#${id}body)`} stroke={`url(#${id}edge)`} strokeWidth="1.1"/>
 <path className="orb-fold" d="M102 239C80 208 136 106 202 79c66-26 95 18 116 67 17 42 57 43 55 78-1 45-70 20-98-22-25-38-72 9-112 38-36 26-50 21-61-1Z" fill={`url(#${id}ribbon)`} stroke={`url(#${id}edge)`} strokeWidth=".8"/>
 <path d="M96 245c28 89 115 142 181 131 68-11 90-72 99-132-33 59-54 53-111 72-79 26-124-27-169-71Z" fill={`url(#${id}ribbon)`} opacity=".45" stroke={`url(#${id}edge)`} strokeWidth=".8"/>
 <ellipse className="orb-light" cx="295" cy="170" rx="68" ry="49" transform="rotate(38 295 170)" fill={`url(#${id}shine)`} opacity=".6"/>
 <path d="M121 301c81 67 184 65 229-11M117 199c-34 78 56 181 131 187" fill="none" stroke={`url(#${id}edge)`} strokeWidth=".7" opacity=".7"/>
 </g></svg><span key={event} className={event?'event-ripple':''}/></div>;
}
