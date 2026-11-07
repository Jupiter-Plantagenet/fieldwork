import React, { useEffect, useState } from 'react';

type Predicate = { actual:number; predicted:number|null; bucket:'cell'|'missing' };
type Slice = {sample_ids:string[];total:number;membership_digest:string;next_cursor:string|null;predicate:Predicate;evaluation_digest:string};
type Flag = {id:string;actor:string;reason:string;sample_ids:string[];slice_digest:string;evaluation_digest:string;predicate:Predicate};
type Command = Predicate & {expected_revision:number;slice_digest:string;evaluation_digest:string;reason:string};
type Pending = {key:string;body:Command;inFlight:boolean;message:string};
export type FlagSession = Map<string,Pending>;
type Props = {base:string;run:{id:string;revision:number}|undefined;user:{name:string;role:string;csrf:string};classes:string[];cell:number[];setCell:(cell:number[])=>void;enabled:boolean;session:FlagSession;refresh:()=>Promise<void>;renderSample:(id:string)=>React.ReactNode};

export function ErrorInvestigation({base,run,user,classes,cell,setCell,enabled,session,refresh,renderSample}:Props) {
 const [bucket,setBucket]=useState<'cell'|'missing'>('cell');
 const [slice,setSlice]=useState<Slice|null>(null),[ids,setIds]=useState<string[]>([]),[history,setHistory]=useState<Flag[]>([]);
 const [reason,setReason]=useState(session.get(run?.id||'')?.body.reason||''),[message,setMessage]=useState(''),[readError,setReadError]=useState(''),[busy,setBusy]=useState(false);
 const pending=run?session.get(run.id):undefined;
 const mayFlag=['owner','researcher','reviewer'].includes(user.role);
 const query=`actual=${cell[0]}&predicted=${cell[1]}&bucket=${bucket}`;
 async function read<T>(path:string):Promise<T>{const r=await fetch(base+path,{credentials:'same-origin'});const data=await r.json();if(!r.ok)throw Error(`${r.status} · ${data.code||data.detail||'Read unavailable'}`);return data}
 useEffect(()=>{
  let active=true;setSlice(null);setIds([]);setReadError('');
  if(run)read<Slice>(`/runs/${run.id}/slices?${query}`).then(s=>{if(active){setSlice(s);setIds(s.sample_ids)}}).catch(e=>{if(active)setReadError(e instanceof Error?e.message:String(e))});
  return()=>{active=false};
 },[base,run?.id,query]);
 useEffect(()=>{let active=true;setHistory([]);if(enabled&&run)read<{items:Flag[]}>(`/runs/${run.id}/flags`).then(x=>{if(active)setHistory(x.items)}).catch(e=>{if(active)setMessage(`Flag history unavailable · ${String(e)}`)});return()=>{active=false}},[base,run?.id,enabled]);
 async function loadMore(){
  if(!run||!slice?.next_cursor||busy)return;
  const prior=slice;setBusy(true);
  try{const s=await read<Slice>(`/runs/${run.id}/slices?${query}&cursor=${encodeURIComponent(prior.next_cursor!)}`);
   if(s.membership_digest!==prior.membership_digest||s.evaluation_digest!==prior.evaluation_digest||s.total!==prior.total)throw Error('SLICE_CHANGED');
   setSlice(s);setIds(old=>[...old,...s.sample_ids]);
  }catch(e){setReadError(e instanceof Error?e.message:String(e));setSlice(null);setIds([])}finally{setBusy(false)}
 }
 async function submit(e:React.FormEvent){
  e.preventDefault();if(!run||!enabled||!mayFlag)return;
  let action=session.get(run.id);
  if(action?.inFlight)return;
  if(!action){if(!slice||slice.total===0||readError||Array.from(reason.trim()).length<10)return;
   action={key:crypto.randomUUID(),body:{expected_revision:run.revision,...slice.predicate,slice_digest:slice.membership_digest,evaluation_digest:slice.evaluation_digest,reason},inFlight:false,message:''};session.set(run.id,action);
  }
  action.inFlight=true;setBusy(true);setMessage('Saving exact follow-up flag…');
  try{
   const r=await fetch(`${base}/runs/${run.id}/flags`,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':user.csrf,'Idempotency-Key':action.key,'If-Match':`"${action.body.expected_revision}"`},body:JSON.stringify(action.body)});
   const value=await r.json();
   if(!r.ok){
    // Access guards run before durable receipt lookup: refusal cannot settle
    // an earlier lost response. Keep the original command above snapshots.
    if(r.status===401||r.status===403)throw Error(`${r.status} · Access refused; outcome unconfirmed`);
    if(r.status>=400&&r.status<500){session.delete(run.id);setMessage(`${r.status} · ${value.code||value.detail||'Flag refused'} · Not saved. Refresh and explicitly inspect again before another submission.`);await refresh();return}
    throw Error(`${r.status} · Flag outcome unconfirmed`);
   }
   if(r.status!==201||value.evaluation_mutated!==false||typeof value.flag_id!=='string'||value.flag?.slice_digest!==action.body.slice_digest||value.flag?.evaluation_digest!==action.body.evaluation_digest)throw Error('Unrecognized flag acknowledgement');
   session.delete(run.id);setReason('');setMessage('Flag saved · evaluation unchanged.');
   try{const x=await read<{items:Flag[]}>(`/runs/${run.id}/flags`);setHistory(x.items)}catch(e){setMessage(`Flag saved · evaluation unchanged. History refresh unavailable · ${String(e)}`)}
  }catch(e){
   if(session.has(run.id)){action.message=`Flag outcome unconfirmed · ${String(e)}. Retry the exact original flag; no new reason or revision will be substituted.`;setMessage(action.message)}
   else setMessage(old=>`${old} Workspace refresh unavailable · ${String(e)}`);
  }finally{action.inFlight=false;setBusy(false)}
 }
 return <div className="stack">
  <div className="tools"><label>Reference label<select disabled={busy} value={cell[0]} onChange={e=>setCell([Number(e.target.value),cell[1]])}>{classes.map((c,i)=><option value={i} key={c}>{c}</option>)}</select></label>
   <label>Prediction disposition<select disabled={busy} value={bucket} onChange={e=>setBucket(e.target.value as 'cell'|'missing')}><option value="cell">Confusion cell</option><option value="missing">Missing / failed</option></select></label>
   {bucket==='cell'&&<label>Predicted label<select disabled={busy} value={cell[1]} onChange={e=>setCell([cell[0],Number(e.target.value)])}>{classes.map((c,i)=><option value={i} key={c}>{c}</option>)}</select></label>}
  </div>
  <div className="cols"><section className="panel"><h2>{classes[cell[0]]} → {bucket==='missing'?'Missing / failed':classes[cell[1]]}</h2>
   {readError?<p role="alert">Slice unavailable · {readError}. No stale slice can be flagged.</p>:!slice?<p>{run?'Loading exact slice…':'Choose an evaluated run.'}</p>:<><p>{slice.total} exact matching records · {ids.length} loaded</p>{ids.length?<div className="gallery">{ids.map(id=><React.Fragment key={id}>{renderSample(id)}</React.Fragment>)}</div>:<p>No records in this slice</p>}{slice.next_cursor&&<button disabled={busy} onClick={loadMore}>Load next exact members</button>}<p className="hash">Membership SHA256 · {slice.membership_digest}</p><p className="hash">Evaluation SHA256 · {slice.evaluation_digest}</p></>}
  </section>
  <section className="panel"><h2>Follow-up, not relabelling</h2><p>Flags bind the entire exact slice, including pages not loaded. Frozen evaluation labels, predictions and metrics never change. A flag requests review in a future data plan.</p>
   {!enabled?<p>A compatible backend is required for follow-up flags; service unavailable or older metadata.</p>:!mayFlag?<p>Your role can inspect flags but cannot create them.</p>:<form className="stack" onSubmit={submit}><label htmlFor="follow-up-reason">Follow-up reason</label><textarea id="follow-up-reason" required minLength={10} maxLength={4000} disabled={busy||!!pending} value={pending?.body.reason||reason} onChange={e=>setReason(e.target.value)}/>
    {pending&&<p>Outstanding flag: class {pending.body.actual}, {pending.body.bucket}, revision {pending.body.expected_revision}. Retry stays on this original slice even if filters changed.</p>}
    <button className="primary" disabled={busy||(!pending&&(!slice||slice.total===0||!!readError||Array.from(reason.trim()).length<10||Array.from(reason).length>2000))}>{pending?'Retry exact flag':'Flag exact slice'}</button></form>}
   <p role="status" aria-live="polite">{message||pending?.message}</p>
  </section></div>
  {enabled&&<section className="panel"><h2>Saved follow-up flags</h2>{history.length?<ul>{history.map(f=><li key={f.id}><b>{f.id}</b><p>{f.reason}</p><p>{f.actor} · {f.sample_ids.length} members · {f.predicate.bucket}</p><p className="hash">{f.slice_digest}</p></li>)}</ul>:<p>No saved flags loaded.</p>}</section>}
 </div>;
}
