import {ReactNode} from 'react';
import {chapters} from './useScrollNavigation';
export function Chapter({id,title,description,children}:{id:string;title?:string;description?:string;children:ReactNode}){
 const index=chapters.findIndex(([key])=>key===id);
 return <section id={id} tabIndex={-1} data-chapter data-visible="false" aria-labelledby={id==='overview'?'overview-title':`${id}-title`} className={`chapter chapter-${id}`}>
 {title&&<header className="chapter-heading"><p className="eyebrow">{String(index+1).padStart(2,'0')} / {chapters[index]?.[1]}</p><h1 id={`${id}-title`}>{title}</h1><p>{description}</p></header>}
 {children}
 <div data-motion data-motion-visible="false" className="chapter-connector" aria-hidden="true"><span/><i/><span/></div>
 </section>;
}
