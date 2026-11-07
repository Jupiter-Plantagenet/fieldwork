import React, { useEffect, useRef, useState } from 'react';

/** Honest read states: loading, ready, stale (last data kept after a failed refresh), and typed errors. */
export type ErrorKind='offline'|'session'|'denied'|'not_found'|'blocked'|'rate_limited'|'unavailable';
export class ApiError extends Error{
 status:number;code:string;kind:ErrorKind;
 constructor(status:number,code:string,kind:ErrorKind){super(`${status||'network'} · ${code}`);this.status=status;this.code=code;this.kind=kind}
}
export function classify(status:number):ErrorKind{
 if(status===0||status===502||status===503||status===504)return 'offline';
 if(status===401)return 'session';
 if(status===403)return 'denied';
 if(status===404)return 'not_found';
 if(status===429)return 'rate_limited';
 if([409,410,412,422,423].includes(status))return 'blocked';
 return 'unavailable';
}
export async function getJson<T>(url:string,init:RequestInit={}):Promise<T>{
 let r:Response;
 try{r=await fetch(url,{credentials:'same-origin',...init})}catch{throw new ApiError(0,'NETWORK_UNREACHABLE','offline')}
 if(!r.ok){
  const body=await r.json().catch(()=>({})) as {code?:string;detail?:string;message?:string};
  throw new ApiError(r.status,String(body.code||body.detail||body.message||r.statusText||'ERROR'),classify(r.status));
 }
 return r.json() as Promise<T>;
}
export type Resource<T>={status:'idle'|'loading'|'ready'|'error';data:T|null;error:ApiError|null;stale:boolean;reload:()=>void};
/** Reads `url`; refetches when deps change or every pollMs. A new url discards the old data. */
export function useResource<T>(url:string|null,deps:unknown[]=[],pollMs=0):Resource<T>{
 const [state,setState]=useState<{status:Resource<T>['status'];data:T|null;error:ApiError|null}>({status:url?'loading':'idle',data:null,error:null});
 const [tick,setTick]=useState(0);const last=useRef<string|null>(null);
 useEffect(()=>{
  if(!url){last.current=null;setState({status:'idle',data:null,error:null});return}
  let active=true;
  if(last.current!==url){last.current=url;setState({status:'loading',data:null,error:null})}
  getJson<T>(url).then(d=>{if(active)setState({status:'ready',data:d,error:null})})
   .catch(e=>{if(active)setState(s=>({status:'error',data:s.data,error:e instanceof ApiError?e:new ApiError(0,String(e),'offline')}))});
  return()=>{active=false};
  // eslint-disable-next-line react-hooks/exhaustive-deps
 },[url,tick,...deps]);
 useEffect(()=>{if(!url||!pollMs)return;const id=setInterval(()=>setTick(t=>t+1),pollMs);return()=>clearInterval(id)},[url,pollMs]);
 return {...state,stale:state.status==='error'&&state.data!==null,reload:()=>setTick(t=>t+1)};
}
const STATE_ATTR:Record<ErrorKind,string>={offline:'offline',session:'session_expired',denied:'permission_denied',not_found:'not_found',blocked:'blocked',rate_limited:'rate_limited',unavailable:'error'};
export function ErrorState({label,error,retry,blockedText}:{label:string;error:ApiError;retry?:()=>void;blockedText?:string}){
 const text:Record<ErrorKind,string>={
  offline:`Offline or service unavailable: ${label} could not be loaded.`,
  session:'Your session expired or was revoked. Sign in again to continue.',
  denied:`Permission denied: your server role cannot read ${label}.`,
  not_found:`${label} was not found in this workspace.`,
  blocked:blockedText||`${label} is blocked by a server gate.`,
  rate_limited:'Too many requests. Retry shortly.',
  unavailable:`${label} is unavailable because of a server error.`,
 };
 return <div className="callout warn state-error" role="alert" data-resource={label} data-state={STATE_ATTR[error.kind]}><b>{text[error.kind]}</b> <span className="hash">{error.message}</span>{retry&&<> <button type="button" onClick={retry}>Retry</button></>}</div>;
}
export function Loading({label}:{label:string}){return <div className="state-loading" role="status" aria-busy="true" data-resource={label} data-state="loading">Loading {label}…</div>}
export function Empty({label,children}:{label:string;children:React.ReactNode}){return <div className="empty" data-resource={label} data-state="empty">{children}</div>}
/** Renders loading / error / stale / ready for a resource. */
export function Status<T>({r,label,children,blockedText}:{r:Resource<T>;label:string;children:(data:T)=>React.ReactNode;blockedText?:string}){
 if(r.status==='idle')return null;
 if(r.data===null&&r.error)return <ErrorState label={label} error={r.error} retry={r.reload} blockedText={blockedText}/>;
 if(r.data===null)return <Loading label={label}/>;
 return <div data-resource={label} data-state={r.stale?'stale':'ready'}>
  {r.stale&&r.error&&<div className="callout warn" role="alert">Showing the last loaded {label}; refresh failed ({r.error.message}). These records may be stale. <button type="button" onClick={r.reload}>Retry</button></div>}
  {children(r.data)}
 </div>;
}
export function MediaImg({src,alt,className}:{src:string;alt:string;className?:string}){
 const [failed,setFailed]=useState(false);
 useEffect(()=>setFailed(false),[src]);
 return failed?<div className={`${className||''} media-error`} role="img" aria-label={`${alt} (media unavailable)`} data-state="media_error">Media unavailable</div>
  :<img className={className} src={src} alt={alt} loading="lazy" onError={()=>setFailed(true)}/>;
}
export const STATE_HELP:Record<string,string>={
 queued:'Queued: durable, waiting for a worker claim',queued_no_worker:'Queued: no fresh worker heartbeat, so it stays queued',
 leased:'Leased: claimed by a worker; ML-Start not yet confirmed',running:'Running: worker lease live',
 stale_heartbeat:'Lease expired: worker heartbeat is stale',cancel_requested:'Cancel requested: awaiting worker exit',
 interrupted:'Interrupted: resumable only from a committed checkpoint',succeeded:'Succeeded: training complete; artifact verification is separate',
 failed:'Failed',cancelled:'Cancelled',
};
export function StateTag({state}:{state:string}){return <span className={`tag state-${state}`} title={STATE_HELP[state]||state} data-run-state={state}>{state.replace(/_/g,' ')}</span>}
export const gib=(n:number)=>`${(n/1024**3).toFixed(2)} GiB`;
export const short=(id:string|null|undefined)=>id?id.slice(0,8):'—';
