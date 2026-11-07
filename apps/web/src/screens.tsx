import React, { useMemo, useState } from 'react';
import { Empty, ErrorState, MediaImg, Status, StateTag, gib, getJson, short, useResource, ApiError } from './resource';
import { downloadSupportDiagnostics } from './real-data-client';
import { GettingStarted } from './getting-started.ts';
import { isRealRun, type Access, type Artifacts, type ConfigureData, type DomainEvent, type Evaluation, type InferenceData, type Lineage, type Operations, type Run, type Sample, type Snapshot, type SplitReport, type User, type VersionRow } from './types';

export type Ctx={base:string;user:User;snap:Snapshot;run:Run|undefined;runId:string;setRunId:(id:string)=>void;go:(id:string)=>void;
 runPicker:()=>React.ReactNode;renderCard:(s:Sample)=>React.ReactNode;setStatus:(s:string)=>void;refresh:()=>Promise<void>;setCell:(c:number[])=>void};
const WRITERS=['owner','researcher'];
const Tag=({children}:{children:React.ReactNode})=><span className="tag">{children}</span>;
const Detail=({rows}:{rows:[string,React.ReactNode][]})=><dl className="detail">{rows.map(([a,b])=><React.Fragment key={a}><dt>{a}</dt><dd>{b}</dd></React.Fragment>)}</dl>;
const Table=({head,rows,label}:{head:string[];rows:React.ReactNode[][];label?:string})=><div className="tablewrap" tabIndex={0} role="region" aria-label={label?`${label} (scrollable)`:'Table (scrollable)'}><table aria-label={label}><thead><tr>{head.map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{rows.map((r,i)=><tr key={i}>{r.map((c,j)=><td key={j}>{c}</td>)}</tr>)}</tbody></table></div>;
const Gate=({children}:{children:React.ReactNode})=><div className="callout warn">{children}</div>;
const when=(iso:string|null|undefined)=>iso?new Date(iso).toLocaleString():'—';
function inputLabel(snap:Snapshot,r:Run){const d=r.config.dataset_digest;return d?(d===snap.dataset_digest?`current manifest ${short(d)}`:`manifest ${short(d)} (not current)`):'no dataset digest recorded'}
function sumCounts(snap:Snapshot){return Object.values(snap.counts).reduce((a,b)=>a+b,0)}

function WorkerPanel({o}:{o:Operations}){
 const w=o.worker;
 return <div data-worker-status={w.status}>
  <Detail rows={[["Heartbeat",w.status==='none'?'No worker heartbeat recorded':w.status==='unreadable'?'Heartbeat record unreadable':`${w.status} · ${w.age_seconds}s old (stale after ${w.stale_after_seconds}s)`],
   ["Worker",w.heartbeat?`PID ${w.heartbeat.pid} · ${w.heartbeat.profile||'profile not reported'}`:'—'],["Isolation",w.heartbeat?.hard_isolation||'—'],["Queue length",o.queue_length],["Checked",when(o.as_of)]]}/>
  {w.status!=='fresh'&&<Gate>No fresh worker heartbeat. Queued runs stay queued; no progress is shown until a worker commits it.</Gate>}
 </div>;
}
function PreflightGate({p}:{p:Operations['preflight']}){
 return p.admitted?<p data-preflight="admitted">Resource preflight passes: {gib(p.free_ram_bytes)} RAM, {gib(p.free_disk_bytes)} disk free.</p>
  :<Gate><span data-preflight="blocked">Resource preflight blocks new work ({p.code}):</span> {gib(p.free_ram_bytes)} free RAM {p.ram_ok?'≥':'<'} {gib(p.required_ram_bytes)}; {gib(p.free_disk_bytes)} free disk {p.disk_ok?'≥':'<'} {gib(p.required_disk_bytes)}. Checked {when(p.checked_at)}.</Gate>;
}

export function Overview({ctx}:{ctx:Ctx}){
 const {snap,base,go,setRunId}=ctx;
 const legacyRuns=snap.runs.filter(r=>!isRealRun(r));
 const ops=useResource<Operations>(`${base}/screens/operations`,[snap.last_sequence],10000);
 const versions=useResource<{items:VersionRow[]}>(`${base}/versions`,[snap.last_sequence]);
 const byState=legacyRuns.reduce<Record<string,number>>((a,r)=>({...a,[r.state]:(a[r.state]||0)+1}),{});
 const cover=snap.samples[0];
 return <div className="cols"><div className="stack">
  <GettingStarted go={go}/>
  <section className="panel" data-screen-data="overview-counters"><div className="eyebrow">Active workspace · {snap.scope}</div><h2 style={{fontSize:23}}>Current workspace records</h2>
   <p className="muted">Counters come from the current authorized snapshot (event sequence {snap.last_sequence||'unknown'}).</p>
   <div className="stats"><div><b>{sumCounts(snap)}</b><span>manifest images ({snap.counts.holdout||0} sealed)</span></div><div><b>{snap.classes.length}</b><span>classes</span></div><div><b data-count="runs">{legacyRuns.length}</b><span>fixture run records</span></div>
    <div><b>{versions.data?versions.data.items.length:versions.error?'—':'…'}</b><span>persisted versions</span></div></div>
   {legacyRuns.length?<p>{Object.entries(byState).map(([s,n])=><span key={s} style={{marginRight:12}}><StateTag state={s}/> {n}</span>)}</p>:<Empty label="runs"><p>No fixture runs are recorded. Real runs appear in the real-run panel.</p><button onClick={()=>go('configure')}>Configure training</button></Empty>}
   {versions.error&&!versions.data&&<ErrorState label="dataset versions" error={versions.error} retry={versions.reload}/>}
  </section>
  <section className="panel"><h2>Queue, worker and preflight</h2><Status r={ops} label="operations">{o=><><WorkerPanel o={o}/><PreflightGate p={o.preflight}/></>}</Status></section>
  <section className="panel"><div className="row between"><h2>Research trail</h2><button onClick={()=>go('runs')}>All runs</button></div>
   {legacyRuns.length?<Table label="Research trail" head={['Run','Input','State','Epochs']} rows={legacyRuns.map(r=>[<button onClick={()=>{setRunId(r.id);go('training')}}>{short(r.id)}</button>,inputLabel(snap,r),<StateTag state={r.state}/>,`${r.epoch}/${r.config.epochs}`])}/>:<Empty label="research trail"><p>No fixture runs recorded.</p></Empty>}
  </section></div>
  <div className="stack">
   {cover&&<div className="cover"><MediaImg className="art" src={`${base}/samples/${cover.id}/media`} alt={`Workspace sample ${cover.id}`}/></div>}
   <section className="panel"><h2>Interruption evidence</h2><Status r={ops} label="interruptions">{o=>o.interruptions.length?<ul>{o.interruptions.map(i=><li key={i.seq}>Run <b>{short(i.run)}</b> became {i.state} at event {i.seq} ({when(i.created)}) after committed epoch {i.committed_epoch??0}{i.replay_epoch?`; resume requested replay of epoch ${i.replay_epoch}`:'; no resume requested'}. <button onClick={()=>{setRunId(i.run);go('recovery')}}>Inspect</button></li>)}</ul>:<Empty label="interruptions"><p>No lease expiry or interruption is recorded in this workspace.</p></Empty>}</Status></section>
   <section className="panel"><h2>Workspace boundaries</h2><Detail rows={[["Scope",snap.scope],["Classes",snap.classes.join(', ')],["Validation",`${snap.counts.validation||0} exact members`],["Holdout",`${snap.counts.holdout||0} sealed members`],["Rights",snap.rights],["Release",snap.release]]}/></section>
  </div></div>;
}

export function Dataset({ctx,search,setSearch,label,setLabel,split,setSplit}:{ctx:Ctx;search:string;setSearch:(v:string)=>void;label:string;setLabel:(v:string)=>void;split:string;setSplit:(v:string)=>void}){
 const {snap,base,renderCard}=ctx;
 const versions=useResource<{items:VersionRow[]}>(`${base}/versions`,[snap.last_sequence]);
 const [version,setVersion]=useState('');
 const chosen=versions.data?.items.find(v=>v.id===version);
 const population:Sample[]=chosen?chosen.manifest.samples.map(s=>({id:s.id,label:s.label,split:s.split,group:s.group||s.id,sha256:s.sha256||'',pixel_sha256:s.pixel_sha256||'',media_scope:chosen.manifest.scope==='real-rights-cleared'?'real':'fixture',classes:chosen.manifest.classes||snap.classes,version_id:chosen.id})):snap.samples;
 const filtered=population.filter(s=>s.id.toLowerCase().includes(search.toLowerCase())&&(label==='all'||(s.label??-1)===Number(label))&&(split==='all'||s.split===split));
 return <>
  <div className="tools"><label>Dataset version<select aria-label="Dataset version" value={version} onChange={e=>setVersion(e.target.value)}><option value="">Pinned manifest {short(snap.dataset_digest)}</option>{versions.data?.items.map(v=><option key={v.id} value={v.id}>{short(v.id)} · {v.state} · rev {v.revision}</option>)}</select></label>
   <input aria-label="Search sample ID" placeholder="Search sample ID…" value={search} onChange={e=>setSearch(e.target.value)}/><select aria-label="Filter label" value={label} onChange={e=>setLabel(e.target.value)}><option value="all">All labels</option><option value="-1">Unlabelled</option>{(chosen?.manifest.classes||snap.classes).map((c,i)=><option value={i} key={c}>{c}</option>)}</select><select aria-label="Filter split" value={split} onChange={e=>setSplit(e.target.value)}><option value="all">All permitted splits</option><option>train</option><option>validation</option><option>pool</option></select><span className="count" data-count="samples">{filtered.length} permitted samples · {snap.counts.holdout||0} sealed</span></div>
  {versions.status==='loading'&&<p className="inline-note" role="status" data-resource="dataset versions" data-state="loading">Loading persisted dataset versions…</p>}
  {versions.error&&<ErrorState label="dataset versions" error={versions.error} retry={versions.reload}/>}
  {versions.data&&!versions.data.items.length&&<p className="inline-note" data-resource="dataset versions" data-state="empty">No persisted child versions; showing the pinned manifest.</p>}
  <div className="callout">Scope {chosen?.manifest.scope||snap.scope}. Holdout media and per-item holdout labels are sealed and are not returned by this API. Import is not exposed in the browser by this API.</div>
  <div className="gallery" style={{marginTop:18}} data-resource="samples" data-state={filtered.length?'ready':'empty'}>{filtered.map(s=><React.Fragment key={s.id}>{renderCard(s)}</React.Fragment>)}</div>
  {!filtered.length&&<section className="panel empty" data-state="filtered_empty"><h2>{population.length?'No matching samples':'No permitted samples in this version'}</h2>{population.length>0&&<button onClick={()=>{setSearch('');setLabel('all');setSplit('all')}}>Clear filters</button>}</section>}
 </>;
}

export function Versions({ctx,panel}:{ctx:Ctx;panel:React.ReactNode}){
 const {snap,base,go}=ctx;
 const vs=useResource<{items:VersionRow[]}>(`${base}/versions`,[snap.last_sequence]);
 function derived(v:VersionRow){
  const latest=new Map<string,VersionRow['proposals'][number]>();v.proposals.forEach(p=>latest.set(p.sample,p));
  const pending=[...latest.values()].filter(p=>!p.decision).length;
  if(v.state==='frozen')return 'frozen';
  if(pending)return `review pending (${pending})`;
  if(v.state==='reviewed'&&v.manifest.scope&&v.manifest.scope!=='synthetic-execution-only')return 'prerequisite blocked: rights & split gates';
  return v.state;
 }
 return <div className="cols"><div className="stack">
  <section className="panel"><h2>Pinned input manifest</h2><div className="version"><strong>base</strong><div><b>{snap.scope}</b><p>{sumCounts(snap)} images · {snap.classes.length} classes · {snap.counts.holdout||0} sealed holdout</p><Tag>Content-addressed manifest</Tag></div><button onClick={()=>go('splits')}>Inspect splits</button></div><p className="hash">{snap.dataset_digest}</p></section>
  <section className="panel"><h2>Persisted versions</h2><Status r={vs} label="dataset versions">{d=>d.items.length?<Table label="Persisted versions" head={['Version','State','Revision','Author','Reviewer','Proposals','Digest']} rows={d.items.map(v=>[short(v.id),<Tag>{derived(v)}</Tag>,v.revision,v.author,v.reviewer||'not reviewed',v.proposals.length,<span className="hash">{v.digest}</span>])}/>:<Empty label="dataset versions"><p>No persisted child versions in this workspace. Owners and researchers can create a working draft.</p></Empty>}</Status></section>
 </div>{panel}</div>;
}

export function Splits({ctx,browseValidation}:{ctx:Ctx;browseValidation:()=>void}){
 const {base,snap}=ctx;
 const r=useResource<SplitReport>(`${base}/screens/splits`,[snap.last_sequence]);
 const colors:Record<string,string>={train:'#215db0',validation:'#87a9d6',holdout:'#c3cfbf'};
 return <Status r={r} label="split report">{d=>{const order=['train','validation','holdout'].filter(s=>d.splits[s]);const total=order.reduce((a,s)=>a+d.splits[s].samples,0)||1;
  return <div className="cols"><div className="stack"><section className="panel"><h2>Membership / manifest {short(d.manifest_digest)}</h2>
   <div className="bars">{order.map(s=><span key={s} style={{width:`${100*d.splits[s].samples/total}%`,background:colors[s]||'#999'}}/>)}</div>
   <div className="legend">{order.map(s=><span key={s}>{s} · {d.splits[s].samples} samples · {d.splits[s].groups} groups</span>)}</div>
   <Table label="Per-class split accounting" head={['Class',...order.map(s=>s==='holdout'?'Holdout (aggregate)':s[0].toUpperCase()+s.slice(1))]} rows={d.classes.map((c,i)=>[c,...order.map(s=>d.splits[s].per_class[i])])}/>
   {order.filter(s=>d.splits[s].membership_digest).map(s=><p key={s} className="hash">{s} membership SHA256 · {d.splits[s].membership_digest}</p>)}</section>
   <section className="panel"><h2>Group & overlap report</h2><p data-integrity={d.integrity.status}><Tag>{d.integrity.status.replace(/_/g,' ')}</Tag> {d.integrity.quarantined_groups} quarantined groups.</p>
    {d.integrity.problems.length?<Gate><b>Integrity blocked:</b><ul>{d.integrity.problems.map(p=><li key={p}>{p}</li>)}</ul></Gate>:<p>No sample, raw-content, pixel-content or group overlap across splits.</p>}</section></div>
   <section className="panel"><h2>Protect the evaluation plan</h2><Gate>{d.splits.holdout?.samples||0} holdout members remain sealed. Only aggregate support is shown; no holdout IDs, media or labels are returned.</Gate>
    <p>Validation is {d.evaluation_plan.validation}. Holdout is {d.evaluation_plan.holdout}.</p>
    <h3>Steward authorizations</h3>{d.evaluation_plan.authorizations.length?<pre>{JSON.stringify(d.evaluation_plan.authorizations,null,2)}</pre>:<Empty label="authorizations"><p>No holdout authorization records exist{d.evaluation_plan.authorizations_supported?'':'. This API has no authorization store yet'}.</p></Empty>}
    <button onClick={browseValidation}>Browse validation members</button></section></div>}}</Status>;
}

export function Configure({ctx}:{ctx:Ctx}){
 const {base,user,snap,go,setRunId,setStatus,refresh}=ctx;
 const cfg=useResource<ConfigureData>(`${base}/screens/configure`,[]);
 const [form,setForm]=useState<Record<string,string>|null>(null),[busy,setBusy]=useState(false),[touched,setTouched]=useState(false);
 return <Status r={cfg} label="configuration inputs">{d=>{
  const defaults=Object.fromEntries(Object.entries(d.bounds).map(([k,b])=>[k,b.default]));const f=form||defaults;
  const set=(k:string,v:string)=>{setForm({...f,[k]:v});setTouched(true)};
  const invalid=Object.entries(d.bounds).filter(([k,b])=>{const v=Number(f[k]);return f[k]===''||!Number.isFinite(v)||(b.min!==null&&v<Number(b.min))||(b.max!==null&&v>Number(b.max))||(k!=='learning_rate'&&!Number.isInteger(v))}).map(([k])=>k);
  const dirty=touched&&Object.keys(defaults).some(k=>f[k]!==defaults[k]);
  async function submit(e:React.FormEvent){e.preventDefault();if(invalid.length||!d.may_submit)return;setBusy(true);setStatus('Submitting configuration…');
   try{const r=await getJson<Run>(base+'/runs',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':user.csrf,'Idempotency-Key':crypto.randomUUID()},body:JSON.stringify({epochs:Number(f.epochs),seed:Number(f.seed),learning_rate:f.learning_rate,batch_size:Number(f.batch_size)})});
    setRunId(r.id);setForm(null);setTouched(false);await refresh().catch(()=>{});go('runs');setStatus(`Configuration queued as ${short(r.id)}. Waiting for a worker; no measured progress yet.`)}
   catch(err){setStatus(err instanceof ApiError?(err.code==='RESOURCE_PREFLIGHT'?`${err.message} · Not queued: resource preflight refused the submission. Your draft is kept.`:`${err.message} · Not queued. Your draft is kept.`):String(err))}finally{setBusy(false)}}
  const field=(k:'epochs'|'learning_rate'|'seed'|'batch_size',text:string,step?:string)=><label key={k}>{text}<input type="number" min={d.bounds[k].min??undefined} max={d.bounds[k].max??undefined} step={step} required value={f[k]} aria-invalid={invalid.includes(k)} onChange={e=>set(k,e.target.value)}/></label>;
  return <div className="cols"><form className="panel bigform" onSubmit={submit} data-form-state={busy?'submitting':invalid.length?'validation_failed':dirty?'dirty_draft':'clean'}>
   <div><div className="sectionlabel">01 / Inputs</div><div className="fields"><label>Dataset version<select><option>Pinned manifest {short(d.dataset.digest)} · {d.dataset.scope}</option></select></label><label>Training recipe<select>{d.recipes.map(r=><option key={r.id}>{r.id}</option>)}</select></label></div></div>
   <div><div className="sectionlabel">02 / Parameters</div><div className="fields">{field('epochs','Epochs')}{field('learning_rate','Learning rate','0.00001')}{field('seed','Random seed')}{field('batch_size','Batch size')}</div>
    {invalid.length>0&&<p className="error" role="alert">Out of range: {invalid.join(', ')}. Allowed: {invalid.map(k=>`${k} ${d.bounds[k as keyof ConfigureData['bounds']].min}–${d.bounds[k as keyof ConfigureData['bounds']].max}`).join('; ')}.</p>}
    {dirty&&<p className="inline-note">Unsaved draft. Nothing is queued until the server acknowledges the submission.</p>}</div>
   <div><div className="sectionlabel">03 / Selection policy</div><div className="callout">Lowest complete validation loss · earliest tie · holdout excluded from training ({d.dataset.holdout_in_training?'included':'excluded'} by server) · seeded random initialization.</div></div>
   {!d.may_submit&&<p className="error" data-state="permission_denied">Your server role ({user.role}) cannot submit runs. Only owners and researchers can.</p>}
   <div className="bottomactions"><button type="submit" className="primary" disabled={busy||!d.may_submit||invalid.length>0}>{busy?'Submitting…':'Submit configuration'}</button></div></form>
   <section className="panel"><h2>Resolved plan</h2><Detail rows={[["Recipe",d.recipes.map(r=>r.id).join(', ')],["Dataset digest",<span className="hash">{d.dataset.digest}</span>],["Train / validation",`${d.dataset.counts.train} / ${d.dataset.counts.validation}`],["Holdout",`${d.dataset.counts.holdout} · excluded`],["Epochs × batch",`${f.epochs} × ${f.batch_size}`],["Learning rate / seed",`${f.learning_rate} / ${f.seed}`],["Worker",d.worker.status==='fresh'?`fresh heartbeat (${d.worker.age_seconds}s)`:`${d.worker.status}: queued runs will wait`]]}/>
    <hr className="rule"/><PreflightGate p={d.preflight}/><button type="button" onClick={cfg.reload}>Re-check preflight</button><p className="inline-note">Current fixture run count: {snap.runs.filter(r=>!isRealRun(r)).length}.</p></section></div>}}</Status>;
}

export function Runs({ctx,cancel}:{ctx:Ctx;cancel:(run:Run)=>React.ReactNode}){
 const {base,snap,run,setRunId,go,runPicker}=ctx;
 const ops=useResource<Operations>(`${base}/screens/operations`,[snap.last_sequence],5000);
 return <div className="stack"><section className="panel"><h2>Research queue</h2><Status r={ops} label="run queue">{o=>{const legacy=o.runs.filter(r=>{const source=snap.runs.find(x=>x.id===r.id);return source!==undefined&&!isRealRun(source)});return legacy.length?<Table label="Research queue" head={['Run','Input','State','Lease','Epochs','Attempts','Action']} rows={legacy.map(r=>{const candidate=snap.runs.find(x=>x.id===r.id);const s=candidate&&!isRealRun(candidate)?candidate:undefined;return [short(r.id),s?inputLabel(snap,s):'—',<StateTag state={r.display_state}/>,r.lease==='live'?`live · ${r.lease_remaining_seconds}s left`:r.lease==='expired'?'expired':r.lease==='none'?'no lease':'—',`${r.epoch}/${r.epochs??'?'}`,r.attempts,<button onClick={()=>{setRunId(r.id);go('training')}}>Inspect run</button>]})}/>:<Empty label="run queue"><p>No fixture runs in this workspace. Real runs appear in the real-run panel.</p><button onClick={()=>go('configure')}>Configure training</button></Empty>}}</Status></section>
  <div className="half"><section className="panel"><h2>Workers</h2><Status r={ops} label="worker status">{o=><WorkerPanel o={o}/>}</Status><p className="hash">Workers run separately from the API.</p></section>
   <section className="panel"><h2>Submission record</h2>{runPicker()}{run?<><Detail rows={[["State",<StateTag state={run.state}/>],["Revision",run.revision],["Fence",run.fence]]}/><pre>{JSON.stringify(run.config,null,2)}</pre>{cancel(run)}</>:<p>Choose a run to see its resolved configuration.</p>}<button onClick={()=>go('configure')}>New experiment</button></section></div></div>;
}

function LossChart({points}:{points:{epoch:number;train_loss:number;validation_loss:number;attempt:string}[]}){
 const max=Math.max(...points.flatMap(x=>[x.train_loss,x.validation_loss]),.01);const xs=(j:number)=>30+j*550/Math.max(points.length-1,1);const ys=(v:number)=>190-(v/max)*165;
 const cuts=points.map((p,j)=>j>0&&p.attempt!==points[j-1].attempt?j:-1).filter(j=>j>0);
 return <svg className="chart" viewBox="0 0 600 220" role="img" aria-label="Committed training and validation loss per epoch"><path d="M30 15V190H580" fill="none" stroke="#dce2de"/>
  {cuts.map(j=><line key={j} x1={xs(j-.5)} x2={xs(j-.5)} y1={15} y2={190} stroke="#c9a832" strokeDasharray="4 4"/>)}
  {(['train_loss','validation_loss'] as const).map((k,i)=><polyline key={k} fill="none" stroke={i?'#7c9274':'#215db0'} strokeWidth="3" points={points.map((x,j)=>`${xs(j)},${ys(x[k])}`).join(' ')}/>)}</svg>;
}

export function Training({ctx,cancel}:{ctx:Ctx;cancel:(run:Run)=>React.ReactNode}){
 const {base,run,runPicker,go,snap}=ctx;
 const legacyRunCount=snap.runs.filter(r=>!isRealRun(r)).length;
 const lin=useResource<Lineage>(run?`${base}/screens/runs/${run.id}/lineage`:null,[run?.revision,snap.last_sequence]);
 if(!run)return <section className="panel">{runPicker()}{legacyRunCount?<p>Choose a fixture run to inspect.</p>:<Empty label="training"><p>No fixture run is selected. Real runs appear in the real-run panel.</p><button onClick={()=>go('configure')}>Configure training</button></Empty>}</section>;
 return <div className="stack"><section className="panel">{runPicker()}<div className="row between"><h2>{short(run.id)} / attempt fence {run.fence}</h2><StateTag state={lin.data?.lease==='expired'&&['running','leased'].includes(run.state)?'stale_heartbeat':run.state}/></div>
  <div className="progress"><span style={{width:`${100*run.epoch/Math.max(run.config.epochs,1)}%`}}/></div><p>{run.epoch} / {run.config.epochs} committed epochs{run.result?` · ${run.result.updates} committed optimizer updates`:''}</p>
  <p>Artifact verification: {run.artifact_status||'not_started'}{run.artifact_result?.code?` · ${run.artifact_result.code}`:''}. Training completion does not imply a verified bundle.</p>{cancel(run)}</section>
  <Status r={lin} label="run lineage">{l=>l.checkpoints.length?<div className="cols"><div className="stack">
   <section className="panel"><h2>Loss / committed epoch</h2><LossChart points={l.checkpoints.map(c=>({...c.metrics,attempt:c.attempt}))}/><p className="inline-note">Blue: train loss · green: validation loss · dashed line: new attempt. Points are committed checkpoints only.</p>
    <Table label="Committed checkpoints" head={['Epoch','Attempt','Train loss','Validation loss','Updates','Checkpoint digest']} rows={l.checkpoints.map(c=>[c.epoch,short(c.attempt),c.metrics.train_loss.toFixed(6),c.metrics.validation_loss.toFixed(6),c.metrics.updates,<span className="hash">{short(c.digest)}</span>])}/></section>
   {run.result?.steps?.length?<section className="panel"><h2>Batch telemetry (provisional)</h2><p className="inline-note">Per-batch values reported with the final result. They are not individually committed checkpoints.</p><Table label="Batch telemetry" head={['Epoch','Batch','Loss','Grad norm']} rows={run.result.steps.map(s=>[s.epoch,s.batch,s.loss.toFixed(6),s.grad_norm?.toFixed(4)??'—'])}/></section>:null}
   {run.result&&<section className="panel"><h2>Parameter update proof</h2><Detail rows={[["Initial",<span className="hash">{run.result.initial_digest}</span>],["Final",<span className="hash">{run.result.final_digest}</span>],["Final PID",run.result.pid]]}/></section>}</div>
   <div className="stack"><section className="panel"><h2>Attempt lineage</h2><Table label="Attempts" head={['Attempt','Fence','Created','Committed epochs']} rows={l.attempts.map(a=>[<span className="hash">{short(a.id)}{a.current?' (current)':''}</span>,a.fence,when(a.created),a.committed_epochs.length?`${Math.min(...a.committed_epochs)}–${Math.max(...a.committed_epochs)}`:'none'])}/>
    {run.result&&<Detail rows={[["Selection",`Epoch ${run.result.best.epoch} · validation loss ${run.result.best.loss.toFixed(6)}`],["Result scope",run.result.scope||'not reported']]}/>}<button onClick={()=>go('evaluation')}>Open evaluation</button> <button onClick={()=>go('recovery')}>Recovery detail</button></section>
    <section className="panel"><h2>Run events</h2><EventList events={l.events.slice(-12)}/></section></div></div>
   :<section className="panel empty" data-state="waiting"><h2>Waiting for execution</h2><p>No committed epoch exists for this run. No chart or checkpoint is shown until a worker commits one.</p><EventList events={l.events}/></section>}</Status></div>;
}
function EventList({events}:{events:DomainEvent[]}){return events.length?<ol className="events">{events.map(e=><li key={e.seq}><b>#{e.seq} {e.kind}</b> · {when(e.created)}{e.payload&&Object.keys(e.payload).length?<span className="hash"> {JSON.stringify(e.payload)}</span>:null}</li>)}</ol>:<p>No events recorded.</p>}

export function EvaluationScreen({ctx}:{ctx:Ctx}){
 const {base,run,runId,snap,go,runPicker}=ctx;
 const ev=useResource<Evaluation>(run?`${base}/runs/${runId}/evaluation`:null,[run?.state,run?.artifact_status]);
 if(!run)return <section className="panel">{runPicker()}<Empty label="evaluation"><p>No run selected. An evaluation needs a completed run with accepted evidence.</p></Empty></section>;
 return <div className="stack"><section className="panel">{runPicker()}</section>
  <Status r={ev} label="evaluation" blockedText={`Evaluation evidence for run ${short(runId)} is not accepted by the server, so no metrics are shown.`}>{e=>{const m=e.metrics,ind=e.independent;const same=JSON.stringify(m.matrix)===JSON.stringify(ind.matrix)&&m.n===ind.n&&m.ok===ind.ok;const state=m.missing.length?'incomplete':m.status;
   return <div className="cols"><div className="stack"><section className="panel"><h2>Confusion matrix</h2><p className="inline-note">Rows: frozen truth · columns: model prediction · split {e.split||'validation'}</p><div className="tablewrap" tabIndex={0} role="region" aria-label="Confusion matrix (scrollable)"><table className="matrix"><thead><tr><th>Actual / predicted</th>{snap.classes.map(c=><th key={c}>{c}</th>)}</tr></thead><tbody>{snap.classes.map((a,i)=><tr key={a}><th>{a}</th>{snap.classes.map((b,j)=><td key={b}><button className={i===j?'diag':''} aria-label={`${a} predicted as ${b}: ${m.matrix[i][j]} samples`} onClick={()=>{ctx.setCell([i,j]);go('errors')}}>{m.matrix[i][j]}</button></td>)}</tr>)}</tbody></table></div></section>
    <section className="panel"><h2>Population accounting</h2><Table head={['Population','Count','Disposition']} rows={[["Expected records",m.n,'All expected IDs'],['Successful predictions',m.ok,'Measured finite logits'],['Missing / failed',m.missing.length,'Kept in the denominator'],['Sealed holdout',snap.counts.holdout||0,'Not evaluated here']]}/><a href={`${base}/runs/${runId}/records`}>Export prediction records</a></section></div>
    <section className="panel"><h2>Inspect, then explain.</h2><Detail rows={[["Status",<Tag>{state}</Tag>],["Accuracy",Number.isFinite(m.accuracy)?m.accuracy.toFixed(4):'undefined'],["Macro-F1",Number.isFinite(m.macro_f1)?m.macro_f1.toFixed(4):'undefined'],["Coverage",m.coverage.toFixed(4)],["Independent recomputation",same?`counts identical · Δaccuracy ${Math.abs(m.accuracy-ind.accuracy).toExponential(1)}`:'MISMATCH with independent report'],["Evaluation digest",<span className="hash">{e.evaluation_digest||'—'}</span>]]}/>
     <hr className="rule"/><Gate>Scope {snap.scope}. These metrics cover the {e.split||'validation'} split only; sealed holdout results are unavailable.</Gate></section></div>}}</Status></div>;
}

export function Recovery({ctx}:{ctx:Ctx}){
 const {base,run,user,runPicker,snap,setStatus,refresh}=ctx;
 const lin=useResource<Lineage>(run?`${base}/screens/runs/${run.id}/lineage`:null,[run?.revision,snap.last_sequence]);
 const ops=useResource<Operations>(`${base}/screens/operations`,[snap.last_sequence]);
 const [busy,setBusy]=useState(false);
 if(!run)return <section className="panel">{runPicker()}<Empty label="recovery"><p>No run selected.</p></Empty></section>;
 async function resume(epoch:number){if(!confirm(`Replay complete epoch ${epoch}? Partial work from the interrupted attempt will not count.`))return;setBusy(true);setStatus('Requesting resume…');
  try{await getJson(base+`/runs/${run!.id}/resume`,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':user.csrf},body:JSON.stringify({replay_epoch:epoch})});setStatus(`Resume queued: replay epoch ${epoch}. Waiting for a worker.`);await refresh().catch(()=>{});lin.reload()}
  catch(e){setStatus(`${String(e instanceof Error?e.message:e)} · Resume not queued.`)}finally{setBusy(false)}}
 return <div className="cols"><div className="stack"><section className="panel">{runPicker()}<h2>Committed checkpoint boundary</h2>
  <Status r={lin} label="recovery lineage">{l=><>{l.boundaries.length?l.boundaries.map(b=><div className="recoveryrail" key={b.interrupted_seq} data-boundary={b.interrupted_seq}>
    <div className="checkpoint"><b>Epochs 1–{b.committed_epoch}</b><Tag>Committed</Tag></div><span>→</span>
    <div className="checkpoint"><b>Epoch {b.committed_epoch+1}</b><Tag>{b.resulting_state||'interrupted'} · event {b.interrupted_seq}</Tag></div><span>→</span>
    <div className="checkpoint"><b>{b.replay_epoch?`Replay epoch ${b.replay_epoch}`:'No resume yet'}</b><Tag>{b.new_attempt?`New attempt ${short(b.new_attempt)} · fence ${b.new_fence}`:b.resume_seq?'Resume queued':'Awaiting decision'}</Tag></div></div>)
   :<Empty label="interruptions"><p>No interruption is recorded for run {short(l.run_id)}. It has {l.checkpoints.length} committed checkpoints across {l.attempts.length} attempts.</p></Empty>}
   <Detail rows={[["Run state",<StateTag state={l.state}/>],["Committed epochs",`${l.checkpoints.length} of ${l.epochs}`],["Attempts used",`${l.recovery.attempts_used} of ${l.recovery.attempt_budget}`],["Latest checkpoint",l.checkpoints.length?<span className="hash">{l.checkpoints[l.checkpoints.length-1].digest}</span>:'none']]}/>
   {l.recovery.resumable&&WRITERS.includes(user.role)?<button className="primary" disabled={busy} data-state="replay_confirmation" onClick={()=>resume(l.recovery.next_replay_epoch!)}>Resume: replay epoch {l.recovery.next_replay_epoch}</button>
    :l.recovery.resumable?<p className="error" data-state="permission_denied">Your role ({user.role}) cannot resume runs.</p>
    :<Gate><span data-state="not_recoverable">Resume unavailable ({l.recovery.blocked_code}).</span> {l.recovery.blocked_code==='NOT_INTERRUPTED'?`The run is ${l.state}, not interrupted.`:l.recovery.blocked_code==='NO_COMMITTED_CHECKPOINT'?'No committed checkpoint exists to restore.':'The attempt budget is exhausted.'}</Gate>}</>}</Status></section></div>
  <section className="panel"><h2>Recovery contract</h2><p>Resume restores only the latest committed checkpoint and replays the whole next epoch. An incomplete, corrupt or lineage-mismatched checkpoint is refused; expired workers cannot revive their lease or publish output.</p>
   <Status r={ops} label="resource gate">{o=><><PreflightGate p={o.preflight}/>{o.worker.status!=='fresh'&&<p>No fresh worker: a resumed run stays queued.</p>}</>}</Status></section></div>;
}

export function ArtifactsScreen({ctx}:{ctx:Ctx}){
 const {base,run,runId,snap,runPicker}=ctx;
 const legacyRuns=snap.runs.filter(r=>!isRealRun(r));
 const art=useResource<Artifacts>(run?`${base}/runs/${runId}/artifacts`:null,[run?.artifact_status]);
 return <div className="stack"><section className="panel"><h2>Fixture artifact stages</h2>{legacyRuns.length?<Table label="Fixture artifact stages" head={['Run','Training','Artifact stage','Result code']} rows={legacyRuns.map(r=>[short(r.id),<StateTag state={r.state}/>,<Tag>{r.artifact_status||'not_started'}</Tag>,r.artifact_result?.code||'—'])}/>:<Empty label="fixture artifacts"><p>No fixture artifact records. Verified real bundles are inspected below.</p></Empty>}</section>
  <section className="panel">{runPicker()}{!run?<p>Choose a fixture run to inspect its bundle evidence.</p>:<Status r={art} label="fixture bundle evidence" blockedText={`No accepted fixture bundle evidence for run ${short(runId)} (artifact stage: ${run.artifact_status||'not_started'}). Nothing is shown in its place.`}>{a=><div className="cols bundle-cols"><section className="panel"><h2>Fixture bundle contents</h2><div className="tree">{Object.keys((a.manifest.files||{}) as object).map(f=><div key={f}>{f}</div>)}</div></section>
   <section className="panel"><h2>Fixture artifact inspector</h2><Detail rows={[["Stage",a.artifact_status||'—'],["Download",a.download_allowed?'allowed':'denied by server'],["Browser inference",a.browser_inference_allowed?'allowed':'denied by server']]}/><pre className="file">{JSON.stringify(a.manifest,null,2)}</pre>{a.receipt&&<><h3>Fixture receipt</h3><pre className="file">{JSON.stringify(a.receipt,null,2)}</pre></>}</section></div>}</Status>}</section>
  <section className="panel"><h2>Release status</h2><Detail rows={[["Server release status",snap.release],["Rights",snap.rights]]}/></section></div>;
}

export function Inference({ctx}:{ctx:Ctx}){
 const {base,snap}=ctx;
 const inf=useResource<InferenceData>(`${base}/screens/inference`,[snap.last_sequence]);
 return <Status r={inf} label="inference availability">{d=><div className="half"><section className="panel"><h2>Fresh image input</h2>
  <Gate><span data-state={d.ordinary_inference.allowed?'qualified_release_ready':'inference_denied'}>{d.ordinary_inference.allowed?'A qualified release is registered.':'No qualified release runtime is currently selectable.'}</span> {d.qualified_releases.length} qualified release{d.qualified_releases.length===1?'':'s'} are available. Use the qualified inference panel below to select the release, provide a rights-registered image, and follow the queued result.</Gate>
  <h3>Internal candidates</h3>{d.candidates.length?<Table label="Internal candidates" head={['Run','Artifact stage','Qualified']} rows={d.candidates.map(c=>[short(c.run_id),<Tag>{c.artifact_status}</Tag>,c.qualified_release?'yes':'no'])}/>:<Empty label="candidates"><p>No succeeded runs, so no candidates.</p></Empty>}</section>
  <section className="panel"><h2>Prediction inspector</h2><Empty label="inference records"><h3>Qualified results appear below</h3><p>Predictions are shown only after a successful bounded worker run. No placeholder probabilities are displayed.</p></Empty></section></div>}</Status>;
}

function SupportDiagnostics({base}:{base:string}){
 const [state,setState]=useState<'idle'|'loading'|'success'|'error'|'access_revoked'>('idle');
 async function download(){
  setState('loading');
  try{
   const blob=await downloadSupportDiagnostics(base),url=URL.createObjectURL(blob),anchor=document.createElement('a');
   anchor.href=url;anchor.download='fieldwork-support-diagnostics.json';document.body.appendChild(anchor);anchor.click();anchor.remove();
   window.setTimeout(()=>URL.revokeObjectURL(url),1000);setState('success');
  }catch(error){
   setState(error instanceof ApiError&&['session','denied','not_found'].includes(error.kind)?'access_revoked':'error');
  }
 }
 const message=state==='loading'?'Preparing redacted workspace diagnostics…':state==='success'?'Redacted diagnostics downloaded.':
  state==='access_revoked'?'Workspace access expired or was revoked. Sign in again or ask a workspace owner to restore access.':
  state==='error'?'Diagnostics could not be downloaded. Check the connection and retry.':'';
 return <section className="panel"><h2>Support diagnostics</h2><p>Download a redacted summary of API policy, configured limits, and aggregate run and version states. It excludes account names and record identifiers.</p>
  <button type="button" className="primary" onClick={download} disabled={state==='loading'}>{state==='loading'?'Preparing…':'Download diagnostics'}</button>
  <p className="support-status" role="status" aria-live="polite" data-state={state}>{message}</p>
 </section>;
}

export function Settings({ctx,signOut}:{ctx:Ctx;signOut:()=>void}){
 const {base,snap}=ctx;
 const acc=useResource<Access>(`${base}/screens/access`,[]);
 const ev=useResource<{items:DomainEvent[]}>(`${base}/events`,[snap.last_sequence]);
 const recent=useMemo(()=>ev.data?ev.data.items.slice(-10).reverse():[],[ev.data]);
 return <div className="cols"><div className="stack"><section className="panel"><h2>Workspace & identity</h2><Detail rows={[["Workspace",snap.workspace],["Signed-in account",snap.name],["Server-derived role",snap.role]]}/><p>Identity and role are server-derived. Owner role controls appear below when available.</p></section>
  <Status r={acc} label="access policy">{a=><><section className="panel"><h2>Members</h2><Table label="Members" head={['Account','Role']} rows={a.members.map(m=>[m.name,m.role])}/><p>{a.owner_count} owner{a.owner_count===1?'':'s'}. Owner membership controls load separately below; no role switch changes the signed-in account.</p></section>
   <section className="panel"><h2>Access policy</h2><p className="inline-note">Evaluated from the server's own guards.</p><Table label="Access policy" head={['Action','Permitted roles']} rows={a.policy.map(p=>[p.action,p.roles.length?p.roles.join(', '):`nobody${p.code?` (${p.code})`:''}`])}/></section>
   <section className="panel"><h2>Session</h2><Detail rows={[["Idle expiry",`${a.session.idle_timeout_minutes} minutes`],["Absolute expiry",`${a.session.absolute_hours} hours`],["Cookie",a.session.cookie],["Support diagnostics",a.support_export_supported?'available':'not available in this API'],["Retention policy",a.retention_policy_supported?'available':'managed below; recorded policy only']]}/></section></>}</Status><SupportDiagnostics base={base}/></div>
  <div className="stack"><section className="panel"><h2>Recent audit events</h2><Status r={ev} label="audit events">{()=>recent.length?<EventList events={recent}/>:<Empty label="audit events"><p>No public events in the seven-day replay window.</p></Empty>}</Status></section>
   <section className="panel"><h2>Operating boundaries</h2><Detail rows={[["Environment",snap.preflight.environment],["Release",snap.release],["Rights",snap.rights]]}/><button onClick={signOut}>Sign out</button></section></div></div>;
}
