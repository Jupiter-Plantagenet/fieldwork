import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, Empty, ErrorState, Loading, MediaImg, StateTag, Status, short, useResource, type Resource } from './resource';
import type { User, VersionRow } from './types';
import { assignInitialRealSplitPlan, authorizeStewardPlan, cancelRealRun, createRealDraft, downloadQualifiedRelease, enqueueIntake, enqueueQualifiedImageInference, enqueueRealTraining, freezeRealVersion, getIntake, getQualifiedReleases, getRealBundle, getRealIntakes, getRealRun, getRealRuns, getRealValidationSlice, getStewardPlans, getWorkspaceSettings, invalidateStewardPlan, resumeRealRun, updateMemberRole, updateWorkspaceSettings, type QualifiedRelease, type RealBundle, type RealIntake, type RealLineage, type RealRun, type RealValidation, type RealValidationSlice, type StewardPlanView, type WorkspaceSettingsView } from './real-data-client';
import { startRunPolling } from './real-run-polling';
import { IntakeDetail } from './intake-detail.ts';
import { ArtifactReceipt } from './real-receipt.ts';

type Props = { screen: string; base: string; user: User; capabilities: { real_intake?: boolean; real_runs?: boolean } | undefined;
  selectedRealRunId: string; setSelectedRealRunId: React.Dispatch<React.SetStateAction<string>>;
  realCell: { runId: string; cell: number[] }; setRealCell: (cell: { runId: string; cell: number[] }) => void; go: (route: string) => void };
const DONE_INTAKES = new Set(['complete', 'succeeded', 'failed', 'rejected', 'cancelled']);
const DONE_RUNS = new Set(['succeeded', 'failed', 'cancelled']);
const WRITERS = new Set(['owner', 'researcher']);
const REAL_SCOPE = 'real-rights-cleared';
const selectSharedVersion = (base: string, id: string) => {
  sessionStorage.setItem(`fieldwork-version:${base}`, id);
  window.dispatchEvent(new CustomEvent('fieldwork-version-refresh', { detail: { base, id } }));
};

export function RealDataPanel({ screen, base, user, capabilities, selectedRealRunId, setSelectedRealRunId, realCell, setRealCell, go }: Props) {
  const visible = ['dataset', 'versions', 'splits', 'configure', 'runs', 'training', 'evaluation', 'errors', 'recovery', 'artifacts', 'inference', 'settings'].includes(screen);
  const writer = WRITERS.has(user.role);
  const versionsResource = useResource<{ items: VersionRow[] }>(visible ? `${base}/versions` : null, [], 5000);
  const intakesResource = useResource<{ items: RealIntake[] }>(['versions', 'dataset'].includes(screen) && capabilities?.real_intake ? `${base}/real/intakes` : null, [], 5000);
  const versions = versionsResource.data?.items ?? [];
  const realVersions = useMemo(() => versions.filter(v => v.manifest.scope === REAL_SCOPE), [versions]);
  const [datasetId, setDatasetId] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState<ApiError | null>(null);
  const [intakeId, setIntakeId] = useState('');
  const [intake, setIntake] = useState<RealIntake | null>(null);
  const [selectedVersion, setSelectedVersion] = useState('');
  const [draftSource, setDraftSource] = useState<'intake' | 'parent'>('intake');
  const [selectedIntakeId, setSelectedIntakeId] = useState('');
  const [parentVersionId, setParentVersionId] = useState('');
  const [epochs, setEpochs] = useState('20');
  const [batchSize, setBatchSize] = useState('16');
  const [learningRate, setLearningRate] = useState('0.001');
  const [seed, setSeed] = useState('42');
  const [acceptedRuns, setAcceptedRuns] = useState<RealRun[]>([]);
  const [runCursor, setRunCursor] = useState<string | null>(null);
  const [runPagesAvailable, setRunPagesAvailable] = useState(false);
  const [runListLoading, setRunListLoading] = useState(false);
  const [runListLoaded, setRunListLoaded] = useState(false);
  const [run, setRun] = useState<RealRun | null>(null);
  const [runPollRetry, setRunPollRetry] = useState(0);
  const [cancelReason, setCancelReason] = useState('');
  const [replayEpoch, setReplayEpoch] = useState('');

  useEffect(() => {
    if (capabilities?.real_runs !== true) { setAcceptedRuns([]); setRunListLoaded(false); return; }
    let active = true;
    setRunListLoading(true);
    getRealRuns(base).then(page => {
      if (!active) return;
      setAcceptedRuns(page.items);
      setRunCursor(page.next_cursor);
      setRunPagesAvailable(page.next_cursor !== null);
      setRunListLoaded(true);
      setSelectedRealRunId(old => old || page.items[0]?.id || '');
    }).catch(e => {
      if (active) setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline'));
    }).finally(() => { if (active) setRunListLoading(false); });
    return () => { active = false; };
  }, [base, capabilities?.real_runs, setSelectedRealRunId]);

  useEffect(() => {
    if (!intakeId || DONE_INTAKES.has(intake?.state || '')) return;
    let active = true;
    const load = () => getIntake(base, intakeId).then(v => { if (active) setIntake(v); }).catch(e => { if (active) setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')); });
    void load();
    const timer = window.setInterval(load, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [base, intakeId, intake?.state]);
  const [inspectIntakeId, setInspectIntakeId] = useState('');
  const [inspectedIntake, setInspectedIntake] = useState<RealIntake | null>(null);
  useEffect(() => {
    setInspectedIntake(null);
    if (!inspectIntakeId) return;
    let active = true;
    getIntake(base, inspectIntakeId).then(v => { if (active) setInspectedIntake(v); }).catch(e => { if (active) setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')); });
    return () => { active = false; };
  }, [base, inspectIntakeId]);

  useEffect(() => {
    if (!selectedRealRunId || !capabilities?.real_runs) { setRun(null); return; }
    setRun(null);
    return startRunPolling({
      read: () => getRealRun(base, selectedRealRunId).then(v => v.run),
      onValue: value => { setRun(value); setAcceptedRuns(rows => rows.some(r => r.id === value.id)
        ? rows.map(r => r.id === value.id ? { ...value, version_id: rows.find(r => r.id === value.id)?.version_id || value.version_id } : r)
        : [value, ...rows]); setError(null); },
      onError: e => setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')),
      isTerminal: value => DONE_RUNS.has(value.state), intervalMs: 3000,
    });
  }, [base, selectedRealRunId, capabilities?.real_runs, runPollRetry]);

  const lineageUrl = selectedRealRunId && ['training', 'evaluation', 'errors', 'recovery'].includes(screen)
    ? `${base}/screens/runs/${encodeURIComponent(selectedRealRunId)}/lineage` : null;
  const lineage = useResource<RealLineage>(lineageUrl, [run?.revision],
    screen === 'training' && run && !DONE_RUNS.has(run.state) ? 2500 : 0);
  const validationUrl = selectedRealRunId && ['evaluation', 'errors'].includes(screen)
    && run?.id === selectedRealRunId && run.scope === 'real-training/v1' && run.state === 'succeeded' && run.artifact_status === 'verified'
      ? `${base}/real/runs/${encodeURIComponent(selectedRealRunId)}/validation` : null;
  const validation = useResource<RealValidation>(validationUrl, [run?.revision, run?.artifact_status]);
  const selectedCell = realCell.runId === selectedRealRunId ? realCell.cell : [0, 0];
  const chooseRun = (id: string) => {
    if (id !== selectedRealRunId) setRealCell({ runId: id, cell: [0, 0] });
    setSelectedRealRunId(id);
  };
  const chooseCell = (cell: number[]) => setRealCell({ runId: selectedRealRunId, cell });

  if (!visible) return null;
  const canIntake = capabilities?.real_intake === true;
  const canRuns = capabilities?.real_runs === true;
  const clearFeedback = () => { setError(null); setMessage(''); };
  const submit = async (action: () => Promise<unknown>, success: string) => {
    setBusy(true); clearFeedback();
    try { await action(); setMessage(success); }
    catch (e) { setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')); }
    finally { setBusy(false); }
  };
  const chosenVersion = realVersions.find(v => v.id === selectedVersion);
  const chosenSplitPolicy = chosenVersion?.manifest as unknown as { split_policy?: { status?: string; id?: string; purpose?: string;
    seed?: number; split_plan_digest?: string; source_version_digest?: string } } | undefined;
  const candidateMembers = (chosenVersion?.manifest as unknown as { samples?: { label: number | null; split: string; group?: string }[] } | undefined)?.samples ?? [];
  const candidateLabels = [...new Set(candidateMembers.flatMap(s => typeof s.label === 'number' ? [s.label] : []))].sort((a, b) => a - b);
  const candidateSupport = candidateLabels.map(label => {
    const rows = candidateMembers.filter(s => s.label === label);
    const forSplit = (split: string) => { const members = rows.filter(s => s.split === split); return { samples: members.length, groups: new Set(members.map(s => s.group).filter((g): g is string => !!g)).size }; };
    return { label, train: forSplit('train'), validation: forSplit('validation'), pool: forSplit('pool') };
  });
  const mayAssignInitialSplit = !!chosenVersion && chosenVersion.state === 'draft'
    && chosenSplitPolicy?.split_policy?.status === 'unassigned'
    && !chosenSplitPolicy.split_policy?.id;
  const loadOlderRuns = async () => {
    if (!runCursor || runListLoading) return;
    setRunListLoading(true);
    try {
      const page = await getRealRuns(base, runCursor);
      setAcceptedRuns(rows => [...rows, ...page.items.filter(next => !rows.some(row => row.id === next.id))]);
      setRunCursor(page.next_cursor);
      setRunPagesAvailable(page.next_cursor !== null);
      setError(null);
    } catch (e) { setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')); }
    finally { setRunListLoading(false); }
  };

  return <div className="stack" data-real-data-panel={screen}>
    {screen === 'splits' && <RealSplitsControls base={base} user={user} versions={realVersions} selectedVersion={selectedVersion} setSelectedVersion={setSelectedVersion} busy={busy} submit={submit}/>}
    {screen === 'artifacts' && <RealArtifacts base={base} user={user} runs={acceptedRuns} runListLoading={runListLoading} busy={busy} submit={submit} loadMore={loadOlderRuns} canLoadMore={runPagesAvailable}/>}
    {screen === 'inference' && <QualifiedInferencePanel base={base} user={user} busy={busy} submit={submit}/>}
    {screen === 'settings' && <RealWorkspaceSettings base={base} user={user} busy={busy} submit={submit}/>}
    {screen === 'dataset' && <section className="panel" aria-labelledby="real-intake-title">
      <h2 id="real-intake-title">Rights-cleared data intake</h2>
      {!canIntake ? <p className="inline-note" data-state="capability_unavailable">Real-data intake is not available in this workspace yet.</p> : <>
        <p>Queue a rights-reviewed image archive for processing. The server checks dataset rights before accepting it; processing may remain queued until an intake worker is available.</p>
        <form className="bigform" onSubmit={e => { e.preventDefault(); if (!file || !datasetId.trim() || file.size > 512 * 1024 * 1024) return;
          void submit(async () => { const ack = await enqueueIntake(base, user.csrf, datasetId.trim(), file); setIntakeId(ack.intake_id); setIntake(ack); setFile(null); }, 'Intake accepted. Waiting for processing status.'); }}>
          <div className="fields"><label>Rights dataset ID<input value={datasetId} maxLength={200} required autoComplete="off" onChange={e => setDatasetId(e.target.value)} /></label>
            <label>Image archive<input type="file" required aria-label="Image archive" onChange={e => setFile(e.target.files?.[0] ?? null)} /><small>Archive size limit: 512 MiB. File contents are streamed to the local service.</small></label></div>
          {file && file.size > 512 * 1024 * 1024 && <p className="error" role="alert">This archive exceeds the 512 MiB limit.</p>}
          <div className="bottomactions"><button className="primary" disabled={busy || !writer || !file || !datasetId.trim() || file.size > 512 * 1024 * 1024}>{busy ? 'Queueing…' : 'Queue archive'}</button></div>
        </form>
        {!writer && <p className="error" data-state="permission_denied">Your role cannot submit intake. Owners and researchers can queue data.</p>}
        {intake && <div className="callout" role="status" data-state={intake.state}><b>Intake {short(intake.intake_id)}</b> · <StateTag state={intake.state}/>{intake.result_batch_id && <> · result batch recorded</>}{intake.result_sha256 && <span className="hash"> · {intake.result_sha256}</span>}</div>}
        {intake && <IntakeDetail detail={intake.detail}/>}
        <section className="stack" aria-labelledby="real-intake-history-title"><h3 id="real-intake-history-title">Your recent intakes</h3>
          {intakesResource.error && <ErrorState label="intake receipts" error={intakesResource.error} retry={intakesResource.reload}/>}
          {intakesResource.data && !intakesResource.data.items.length && <Empty label="intake receipts"><p>No intake has been queued by this account.</p></Empty>}
          {!!intakesResource.data?.items.length && <label>Intake receipt<select value={inspectIntakeId} onChange={e => setInspectIntakeId(e.target.value)}><option value="">Choose an intake</option>{intakesResource.data.items.map(i => <option key={i.intake_id} value={i.intake_id}>{short(i.intake_id)} · {i.state}</option>)}</select></label>}
          {inspectedIntake && <div className="stack" data-intake-inspected={inspectedIntake.intake_id}><p>Intake {short(inspectedIntake.intake_id)} · <StateTag state={inspectedIntake.state}/></p><IntakeDetail detail={inspectedIntake.detail}/></div>}
        </section>
      </>}
    </section>}

    {screen === 'versions' && <section className="panel" aria-labelledby="real-freeze-title">
      <h2 id="real-freeze-title">Freeze a real dataset version</h2>
      {!canIntake ? <p className="inline-note" data-state="capability_unavailable">Real-data version controls are not available in this workspace yet.</p> : <>
        <section className="callout" aria-labelledby="real-draft-title">
          <h3 id="real-draft-title">Create a real working draft</h3>
          <p>Choose an accepted intake to start an unassigned pool draft, or branch from a frozen real version. The server selects the records and keeps existing validation and protected holdout membership unchanged.</p>
          <form className="fields" onSubmit={e => { e.preventDefault();
            const source = draftSource === 'intake'
              ? (selectedIntakeId ? { intake_id: selectedIntakeId } : null)
              : (realVersions.find(v => v.id === parentVersionId && v.state === 'frozen')
                ? { parent_version_id: parentVersionId, parent_version_digest: realVersions.find(v => v.id === parentVersionId)!.digest }
                : null);
            if (!source) return;
            void submit(async () => { const created = await createRealDraft<VersionRow>(base, user.csrf, source);
              setSelectedVersion(created.id); selectSharedVersion(base, created.id);
              await Promise.all([versionsResource.reload(), intakesResource.reload()]);
            }, draftSource === 'intake'
              ? 'Pool draft created. It cannot be frozen for training until a reviewed train/validation split plan exists.'
              : 'Child draft created with inherited splits. Open Sample inspector for train or pool proposals, then independently review and freeze it.');
          }}>
            <label>Draft source<select value={draftSource} onChange={e => setDraftSource(e.target.value as 'intake' | 'parent')}>
              <option value="intake">Accepted intake</option><option value="parent">Frozen real version</option>
            </select></label>
            {draftSource === 'intake' ? <label>Accepted intake<select required value={selectedIntakeId} onChange={e => setSelectedIntakeId(e.target.value)}>
              <option value="">Choose a completed intake</option>{(intakesResource.data?.items ?? []).filter(i => i.state === 'complete' && i.result_batch_id).map(i =>
                <option key={i.intake_id} value={i.intake_id}>{short(i.intake_id)} · {i.rights_dataset_id || 'rights dataset'} · accepted batch</option>)}
            </select></label> : <label>Frozen real parent<select required value={parentVersionId} onChange={e => setParentVersionId(e.target.value)}>
              <option value="">Choose a frozen real version</option>{realVersions.filter(v => v.state === 'frozen').map(v =>
                <option key={v.id} value={v.id}>{short(v.id)} · revision {v.revision}</option>)}
            </select></label>}
            <button className="primary" disabled={busy || !writer || (draftSource === 'intake' ? !selectedIntakeId : !parentVersionId)}>
              {busy ? 'Creating…' : 'Create real draft'}
            </button>
          </form>
          {intakesResource.error && <ErrorState label="accepted intakes" error={intakesResource.error} retry={intakesResource.reload}/>}
          {intakesResource.status === 'loading' && <Loading label="accepted intakes"/>}
          {intakesResource.data && !intakesResource.data.items.some(i => i.state === 'complete' && i.result_batch_id) &&
            <Empty label="accepted intakes"><p>There is no completed accepted intake for this account yet. Queue an archive from Dataset explorer, then return here after processing.</p></Empty>}
          {!writer && <p className="error" data-state="permission_denied">Owners and researchers can create real working drafts.</p>}
        </section>
        <p>Freeze rechecks the recorded rights and version revision on the server. Only real-rights-cleared versions appear here.</p>
        {versionsResource.status === 'loading' && <Loading label="dataset versions"/>}
        {versionsResource.error && <ErrorState label="dataset versions" error={versionsResource.error} retry={versionsResource.reload}/>}
        {!versionsResource.error && !versionsResource.data?.items.length && <Empty label="real dataset versions"><p>No real dataset versions are available yet. Queue an archive from Dataset explorer; this list updates when the service records versions.</p></Empty>}
        {!!realVersions.length && <div className="fields"><label>Real dataset version<select value={selectedVersion} onChange={e => setSelectedVersion(e.target.value)}><option value="">Choose a version</option>{realVersions.map(v => <option key={v.id} value={v.id}>{short(v.id)} · {v.state} · revision {v.revision}</option>)}</select></label>
          <div>{chosenVersion && <><p>Version {short(chosenVersion.id)} · {chosenVersion.state} · revision {chosenVersion.revision}</p>
            {mayAssignInitialSplit && <div className="stack"><p>This intake draft is still pool-only. Assigning this plan puts whole label-consistent groups into 70% train, 15% validation and 15% continued pool. Numeric source-photo IDs are grouped; other records remain singleton groups. It creates no holdout; the exact version still needs independent review.</p>
              <button type="button" disabled={busy || !writer} onClick={() => void submit(async () => {
                const updated = await assignInitialRealSplitPlan<VersionRow>(base, user.csrf, chosenVersion.id, chosenVersion.revision);
                setSelectedVersion(updated.id); selectSharedVersion(base, updated.id); versionsResource.reload();
              }, 'Group-disjoint candidate split assigned. No holdout was created. Review the exact version before freezing it for training.')}>{busy ? 'Assigning…' : 'Assign initial train / validation split'}</button>
            </div>}
            {chosenSplitPolicy?.split_policy?.id === 'group-stratified-candidate/v1' && <><p className="callout">Candidate-only split · 70% train / 15% validation / 15% pool · deterministic seed {chosenSplitPolicy.split_policy.seed ?? 42} · no holdout created. Review this exact version before freezing.</p>
              <p>Split plan digest <span className="hash">{chosenSplitPolicy.split_policy.split_plan_digest}</span></p>
              <p>Source draft digest <span className="hash">{chosenSplitPolicy.split_policy.source_version_digest}</span></p>
              <div className="tablewrap" tabIndex={0} role="region" aria-label="Unprotected candidate split support (scrollable)"><table><caption>Unprotected candidate split support</caption><thead><tr><th scope="col">Class index</th><th scope="col">Train samples / groups</th><th scope="col">Validation samples / groups</th><th scope="col">Pool samples / groups</th></tr></thead>
                <tbody>{candidateSupport.map(row => <tr key={row.label}><th scope="row">{row.label}</th><td>{row.train.samples} / {row.train.groups}</td><td>{row.validation.samples} / {row.validation.groups}</td><td>{row.pool.samples} / {row.pool.groups}</td></tr>)}</tbody></table></div>
            </>}
            <button className="primary" disabled={busy || !writer || chosenVersion.state !== 'reviewed'} onClick={() => void submit(async () => { await freezeRealVersion(base, user.csrf, chosenVersion.id, chosenVersion.revision); versionsResource.reload(); selectSharedVersion(base, chosenVersion.id); }, 'Freeze request accepted. The version list is refreshing.')}>{busy ? 'Freezing…' : chosenVersion.state === 'frozen' ? 'Already frozen' : chosenVersion.state === 'reviewed' ? 'Freeze real version' : 'Review required before freeze'}</button></>}</div>
        </div>}
      </>}</section>}

    {screen === 'configure' && <section className="panel" aria-labelledby="real-training-title">
      <h2 id="real-training-title">Queue real-data training</h2>
      {!canRuns ? <p className="inline-note" data-state="capability_unavailable">Real training is unavailable until the real-run service is ready.</p> : <>
        <p>Choose a frozen real version. The server rechecks rights and queue readiness before acknowledging a run. Progress is shown only when reported by the service.</p>
        {versionsResource.error && <ErrorState label="dataset versions" error={versionsResource.error} retry={versionsResource.reload}/>}
        {!realVersions.some(v => v.state === 'frozen') && <Empty label="frozen real versions"><p>No frozen real dataset versions are available.</p></Empty>}
        {!!realVersions.some(v => v.state === 'frozen') && <form onSubmit={e => { e.preventDefault(); if (!chosenVersion || chosenVersion.state !== 'frozen') return;
          void submit(async () => { const accepted = await enqueueRealTraining(base, user.csrf, { version_id: chosenVersion.id, version_revision: chosenVersion.revision, epochs: Number(epochs), batch_size: Number(batchSize), learning_rate: learningRate, seed: Number(seed) }); const tracked = { ...accepted, version_id: chosenVersion.id }; setAcceptedRuns(rows => [tracked, ...rows.filter(r => r.id !== accepted.id)]); chooseRun(accepted.id); }, 'Real training queued. No progress is shown until the worker reports it.'); }}>
          <div className="fields"><label>Frozen real version<select required value={selectedVersion} onChange={e => setSelectedVersion(e.target.value)}><option value="">Choose a frozen version</option>{realVersions.filter(v => v.state === 'frozen').map(v => <option key={v.id} value={v.id}>{short(v.id)} · revision {v.revision}</option>)}</select></label>
            <label>Epochs<input type="number" min="1" max="100" value={epochs} onChange={e => setEpochs(e.target.value)} required/></label>
            <label>Batch size<input type="number" min="1" max="32" value={batchSize} onChange={e => setBatchSize(e.target.value)} required/></label>
            <label>Learning rate<input type="number" min="0.00001" max="0.1" step="0.00001" value={learningRate} onChange={e => setLearningRate(e.target.value)} required/></label>
            <label>Seed<input type="number" min="0" max="4294967295" value={seed} onChange={e => setSeed(e.target.value)} required/></label></div>
          <div className="bottomactions"><button className="primary" disabled={busy || !writer || !chosenVersion || chosenVersion.state !== 'frozen'}>{busy ? 'Queueing…' : 'Queue real training'}</button></div>
        </form>}
        {!writer && <p className="error" data-state="permission_denied">Your role cannot queue training. Owners and researchers can submit runs.</p>}
      </>}
    </section>}

    {screen === 'runs' && <section className="panel" aria-labelledby="real-run-title">
      <h2 id="real-run-title">Real run status and controls</h2>
      {!canRuns ? <p className="inline-note" data-state="capability_unavailable">Real-run monitoring and controls are unavailable until the real-run service is ready.</p> : <>
        <p>Only acknowledged runs are tracked here. Status is refreshed from the service; queue acceptance does not imply worker progress.</p>
        {runListLoading && !runListLoaded && <Loading label="real runs"/>}
        {acceptedRuns.length ? <div className="fields"><label>Selected real run<select value={selectedRealRunId} onChange={e => chooseRun(e.target.value)}><option value="">Choose a run</option>{acceptedRuns.map(r => <option key={r.id} value={r.id}>{short(r.id)} · {r.scope?.replace('/v1','')} · {r.state}</option>)}</select></label>
          {run && <div><StateTag state={run.state}/><p>Revision {run.revision} · reported epoch {run.epoch} · artifact {run.artifact_status}</p>
            <button type="button" onClick={()=>go('training')}>Open real run details</button>
            {['queued', 'leased', 'running', 'interrupted', 'cancel_requested'].includes(run.state) && writer && <div className="stack"><label>Cancellation reason<textarea value={cancelReason} maxLength={2000} onChange={e => setCancelReason(e.target.value)}/></label><button disabled={busy || !cancelReason.trim()} onClick={() => void submit(async () => { const updated = await cancelRealRun(base, user.csrf, run, cancelReason.trim()); setRun(updated); setCancelReason(''); }, 'Cancellation requested. Waiting for the service to confirm the final state.')}>Request cancellation</button></div>}
          </div>}</div> : runListLoaded ? <Empty label="accepted real runs"><p>No real runs are recorded in this workspace. Queue one from Configure training.</p></Empty> : null}
        {runPagesAvailable && <button type="button" disabled={runListLoading} onClick={() => void loadOlderRuns()}>{runListLoading ? 'Loading…' : 'Load more real runs'}</button>}
      </>}
    </section>}

    {screen === 'training' && <RealTrainingRun base={base} user={user} runs={acceptedRuns} selectedRunId={selectedRealRunId}
      setSelectedRunId={chooseRun} run={run} lineage={lineage} loading={runListLoading} canRuns={canRuns}
      writer={writer} busy={busy} reason={cancelReason} setReason={setCancelReason} submit={submit} go={go}/>}
    {screen === 'evaluation' && <RealEvaluationRun runs={acceptedRuns} selectedRunId={selectedRealRunId} setSelectedRunId={chooseRun}
      run={run} validation={validation} loading={runListLoading} canRuns={canRuns} onCell={(a,p)=>{chooseCell([a,p]);go('errors')}}/>}
    {screen === 'errors' && <RealErrorRun base={base} runs={acceptedRuns} selectedRunId={selectedRealRunId} setSelectedRunId={chooseRun}
      run={run} validation={validation} loading={runListLoading} canRuns={canRuns} cell={selectedCell} setCell={chooseCell}/>}
    {screen === 'recovery' && <RealRecoveryRun base={base} user={user} runs={acceptedRuns} selectedRunId={selectedRealRunId}
      setSelectedRunId={chooseRun} run={run} lineage={lineage} loading={runListLoading} canRuns={canRuns}
      writer={writer} busy={busy} submit={submit} refreshRun={()=>setRunPollRetry(n=>n+1)}/>}

    {screen === 'inference' && <section className="panel" aria-labelledby="real-inference-title">
      <h2 id="real-inference-title">Qualified release inference</h2>
      <p>Private training candidates are not ordinary inference options. Use the separately registered qualified release and its current rights checks below.</p>
    </section>}

    {error && (
      <ErrorState label="real-data action" error={error} retry={() => {
        setError(null);
        if (intakeId) void getIntake(base, intakeId).then(setIntake).catch(() => {});
        if (selectedRealRunId) { setRunPollRetry(n=>n+1); void getRealRun(base, selectedRealRunId).then(v => setRun(v.run)).catch(() => {}); }
        if (canRuns) void getRealRuns(base).then(page => { setAcceptedRuns(page.items); setRunCursor(page.next_cursor); setRunPagesAvailable(page.next_cursor !== null); setRunListLoaded(true); }).catch(e => setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')));
      }} />
    )}
    {message && <p role="status" aria-live="polite" className="inline-note">{message}</p>}
  </div>;
}

const canInfer = (role: string) => ['owner', 'researcher', 'reviewer'].includes(role);
type Submit = (action: () => Promise<unknown>, success: string) => Promise<void>;

function RealSplitsControls({base, user, versions, selectedVersion, setSelectedVersion, busy, submit}: {
  base: string; user: User; versions: VersionRow[]; selectedVersion: string; setSelectedVersion: (id: string) => void; busy: boolean; submit: Submit;
}) {
  const [view, setView] = useState<StewardPlanView | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [population, setPopulation] = useState('');
  const [model, setModel] = useState('');
  const [checkpoint, setCheckpoint] = useState('');
  const [evaluator, setEvaluator] = useState('');
  const [spec, setSpec] = useState('');
  const [reason, setReason] = useState('');
  useEffect(() => {
    if (!selectedVersion) { setView(null); setError(null); return; }
    let active = true;
    getStewardPlans(base, user.csrf, selectedVersion).then(v => { if (active) { setView(v); setError(null); } })
      .catch(e => { if (active) setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')); });
    return () => { active = false; };
  }, [base, selectedVersion, user.csrf]);
  const reload = async () => { if (selectedVersion) setView(await getStewardPlans(base, user.csrf, selectedVersion)); };
  return <section className="panel" aria-labelledby="real-holdout-title">
    <h2 id="real-holdout-title">Real holdout plan steward controls</h2>
    <p>Only an explicit database steward assignment can authorize or invalidate a plan. Holdout identities, labels, media and paths remain sealed. A consumed population can never be reauthorized.</p>
    <label>Frozen real version<select value={selectedVersion} onChange={e => setSelectedVersion(e.target.value)}><option value="">Choose a frozen real version</option>{versions.filter(v => v.state === 'frozen').map(v => <option key={v.id} value={v.id}>{short(v.id)} · revision {v.revision}</option>)}</select></label>
    {error && <ErrorState label="steward authorization" error={error} retry={() => { void reload().then(() => setError(null)).catch(e => setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline'))); }} />}
    {error?.code === 'HOLDOUT_STEWARD_REQUIRED' && <p className="error" data-state="permission_denied">No explicit steward assignment exists for this account. Workspace ownership does not grant steward authority.</p>}
    {view && <><p>Frozen version digest · <span className="hash">{view.version.digest}</span></p><h3>Protected populations · aggregate support only</h3>
      {view.populations.length ? <div className="stack">{view.populations.map(p => <div className="callout" key={p.tag}><b>{p.tag}</b> · {p.count} members · <span className="hash">{p.digest}</span><pre>{JSON.stringify(p.support, null, 2)}</pre></div>)}</div> : <Empty label="protected populations"><p>No protected population exists in this version.</p></Empty>}
      <h3>Authorize a candidate</h3><form className="bigform" onSubmit={e => { e.preventDefault(); const p = view.populations.find(x => x.tag === population); if (!p) return;
        void submit(async () => { await authorizeStewardPlan(base, user.csrf, { version_id: view.version.id, version_digest: view.version.digest, population_digest: p.digest, population_count: p.count, population_tag: p.tag, candidate_model_digest: model, candidate_checkpoint_digest: checkpoint, evaluator, usefulness_spec_sha256: spec }); await reload(); }, 'Holdout plan authorization recorded by the steward service.'); }}>
        <div className="fields"><label>Protected population<select required value={population} onChange={e => setPopulation(e.target.value)}><option value="">Choose population</option>{view.populations.map(p => <option key={p.tag} value={p.tag}>{p.tag} · {p.count} members</option>)}</select></label>
          <label>Candidate model SHA256<input required pattern="[0-9a-f]{64}" maxLength={64} value={model} onChange={e => setModel(e.target.value)} /></label>
          <label>Candidate checkpoint SHA256<input required pattern="[0-9a-f]{64}" maxLength={64} value={checkpoint} onChange={e => setCheckpoint(e.target.value)} /></label>
          <label>Evaluator identity<input required maxLength={200} value={evaluator} onChange={e => setEvaluator(e.target.value)} /></label>
          <label>Usefulness specification SHA256<input required pattern="[0-9a-f]{64}" maxLength={64} value={spec} onChange={e => setSpec(e.target.value)} /></label></div>
        <button className="primary" disabled={busy || !population || !model || !checkpoint || !evaluator || !spec}>Authorize evaluation plan</button>
      </form>
      <h3>Plan receipts</h3>{view.plans.length ? <div className="stack">{view.plans.map(p => <div className="callout" key={p.plan_id} data-state={p.state}><b>{p.plan_id}</b> · <StateTag state={p.state}/> · exposures {p.exposures}{p.consumed_utc ? ' · consumed; exposure is permanent' : ''}{p.invalidated_reason && <p>Reason: {p.invalidated_reason}</p>}{p.state !== 'invalidated' && <div className="stack"><label>Invalidation reason<textarea minLength={10} maxLength={2000} value={reason} onChange={e => setReason(e.target.value)} /></label><button disabled={busy || reason.trim().length < 10} onClick={() => void submit(async () => { await invalidateStewardPlan(base, user.csrf, p.plan_id, reason.trim()); setReason(''); await reload(); }, 'Plan invalidated. Any prior exposure remains permanently recorded.')}>Invalidate plan</button></div>}</div>)}</div> : <Empty label="holdout plans"><p>No holdout plans are recorded for this version.</p></Empty>}</>}
  </section>;
}

function RealRunPicker({runs, selectedRunId, setSelectedRunId, loading, canRuns}: {
  runs: RealRun[]; selectedRunId: string; setSelectedRunId: (id: string) => void; loading: boolean; canRuns: boolean;
}) {
  return <label>Selected real run<select aria-label="Selected real run" disabled={!canRuns || loading && !runs.length}
    value={selectedRunId} onChange={e=>setSelectedRunId(e.target.value)}>
    <option value="">Choose a real run</option>{runs.map(r=><option key={r.id} value={r.id}>
      {short(r.id)} · {r.scope?.replace('/v1','') || 'real'} · {r.state}</option>)}
  </select></label>;
}

function RealTrainingRun({base,user,runs,selectedRunId,setSelectedRunId,run,lineage,loading,canRuns,writer,busy,reason,setReason,submit,go}: {
  base:string; user:User; runs:RealRun[]; selectedRunId:string; setSelectedRunId:(id:string)=>void;
  run:RealRun|null; lineage:Resource<RealLineage>; loading:boolean; canRuns:boolean; writer:boolean; busy:boolean;
  reason:string; setReason:(value:string)=>void; submit:Submit; go:(route:string)=>void;
}) {
  return <section className="panel" data-real-run-screen="training" aria-labelledby="real-training-title">
    <h2 id="real-training-title">Real training run</h2>
    <p>Only database-reported progress and committed real checkpoints appear here. No fixture metrics are substituted.</p>
    <RealRunPicker runs={runs} selectedRunId={selectedRunId} setSelectedRunId={setSelectedRunId} loading={loading} canRuns={canRuns}/>
    {!canRuns ? <p data-state="capability_unavailable">Real-run reads are unavailable.</p> : !run ? <Empty label="real training run">Choose a real run to inspect its durable execution record.</Empty>
      : run.scope !== 'real-training/v1' ? <div className="callout" data-state="wrong_run_scope">This run is {run.scope}; training metrics are not available for this run type.</div>
      : <><dl className="detail"><dt>Run state</dt><dd><StateTag state={run.state}/></dd><dt>Run ID</dt><dd className="hash">{run.id}</dd>
        <dt>Reported epoch</dt><dd>{run.epoch} · database run state</dd><dt>Artifact status</dt><dd>{run.artifact_status}</dd>
        <dt>Revision</dt><dd>{run.revision}</dd></dl>
        {['queued','leased','running','interrupted','cancel_requested'].includes(run.state) && writer && <div className="stack"><label>Cancellation reason<textarea value={reason} maxLength={2000} onChange={e=>setReason(e.target.value)}/></label>
          <button disabled={busy || !reason.trim()} onClick={()=>void submit(async()=>{const updated=await cancelRealRun(base,user.csrf,run,reason.trim());setReason('');},'Cancellation requested. The service will report its final state.')}>Request cancellation</button></div>}
        <Status r={lineage} label="real training lineage" blockedText="No accepted real checkpoint lineage is available; training metrics are not fabricated.">
          {l=><div className="stack"><h3>Committed real checkpoints · {l.checkpoints.length} of {l.epochs}</h3>
            {l.checkpoints.length ? <div className="tablewrap" tabIndex={0} role="region" aria-label="Committed real checkpoints (scrollable)"><table><thead><tr><th>Epoch</th><th>Train loss</th><th>Validation loss</th><th>Updates</th><th>Attempt</th><th>Checkpoint SHA256</th></tr></thead><tbody>
              {l.checkpoints.map(cp=><tr key={`${cp.epoch}:${cp.attempt}`}><th>{cp.epoch}</th><td>{cp.metrics.train_loss.toFixed(6)}</td><td>{cp.metrics.validation_loss.toFixed(6)}</td><td>{cp.metrics.updates}</td><td>{short(cp.attempt)}</td><td className="hash">{cp.digest}</td></tr>)}
            </tbody></table></div> : <Empty label="real checkpoints">No committed checkpoint exists yet. Loss charts and validation metrics remain empty until the worker commits a checkpoint.</Empty>}
            <h3>Attempt lineage</h3>{l.attempts.length ? <div className="tablewrap" tabIndex={0} role="region" aria-label="Attempt lineage (scrollable)"><table><thead><tr><th>Attempt</th><th>Fence</th><th>Started</th><th>Committed epochs</th><th>Current</th></tr></thead><tbody>{l.attempts.map(a=><tr key={a.id}><td className="hash">{a.id}</td><td>{a.fence}</td><td>{a.created}</td><td>{a.committed_epochs.join(', ') || 'none'}</td><td>{a.current?'yes':'no'}</td></tr>)}</tbody></table></div> : <p>No attempt has claimed this run.</p>}
            <h3>Recent run events</h3>{l.events.length ? <ol className="events">{l.events.slice(-12).map(e=><li key={e.seq}><b>#{e.seq} {e.kind}</b> · {e.created}</li>)}</ol> : <p>No public run events.</p>}
            <ArtifactReceipt events={l.events}/>
            <div className="bottomactions"><button type="button" onClick={()=>go('evaluation')}>Open real validation</button><button type="button" onClick={()=>go('recovery')}>Open recovery detail</button></div>
          </div>}
        </Status>
      </>}
  </section>;
}

function RealEvaluationRun({runs,selectedRunId,setSelectedRunId,run,validation,loading,canRuns,onCell}: {
  runs:RealRun[]; selectedRunId:string; setSelectedRunId:(id:string)=>void; run:RealRun|null;
  validation:Resource<RealValidation>; loading:boolean; canRuns:boolean; onCell:(actual:number,predicted:number)=>void;
}) {
  return <section className="panel" data-real-run-screen="evaluation" aria-labelledby="real-evaluation-title">
    <h2 id="real-evaluation-title">Verified real validation</h2>
    <p>Only a successfully verified private bundle supplies confusion counts. Sealed holdout membership and results are not requested.</p>
    <RealRunPicker runs={runs} selectedRunId={selectedRunId} setSelectedRunId={setSelectedRunId} loading={loading} canRuns={canRuns}/>
    {!run ? <Empty label="real evaluation">Choose a real run. Pending, failed, or unverified runs have no evaluation metrics.</Empty>
      : run.scope !== 'real-training/v1' ? <div data-state="wrong_run_scope">Validation metrics apply only to real training runs.</div>
      : run.state !== 'succeeded' || run.artifact_status !== 'verified' ? <div className="callout" data-state={run.state === 'failed' ? 'failed' : 'waiting'}>
        No verified validation report is available for this run. Current state: {run.state}; artifact status: {run.artifact_status}.</div>
      : validation.data?.run_id !== run.id ? (validation.error ? <ErrorState label="verified real validation" error={validation.error} retry={validation.reload}/> : <Loading label="verified real validation"/>)
      : <Status r={validation} label="verified real validation" blockedText="The validation report is unavailable or its current rights check failed.">
        {v=><div className="stack"><p className="inline-note">Evidence scope: {v.evidence_scope} · bundle {v.bundle_digest}</p>
          <div className="callout" data-validation-status={v.metrics.status}><b>Validation report status: {v.metrics.status}</b>{v.metrics.status !== 'complete' && <p>This report is partial; the displayed counts and metrics do not represent a complete prediction set.</p>}</div>
          <div className="tablewrap" tabIndex={0} role="region" aria-label="Real validation confusion matrix (scrollable)"><table className="matrix"><caption>Real validation confusion matrix · rows are frozen truth, columns are measured prediction</caption><thead><tr><th>Actual / predicted</th>{v.classes.map(c=><th key={c}>{c}</th>)}</tr></thead><tbody>{v.metrics.matrix.map((row,i)=><tr key={v.classes[i]}><th>{v.classes[i]}</th>{row.map((count,j)=><td key={v.classes[j]}><button className={i===j?'diag':''} aria-label={`${v.classes[i]} predicted as ${v.classes[j]}: ${count} validation samples`} onClick={()=>onCell(i,j)}>{count}</button></td>)}</tr>)}</tbody></table></div>
          <div className="tablewrap" tabIndex={0} role="region" aria-label="Measured validation summary (scrollable)"><table><caption>Measured validation summary</caption><tbody><tr><th scope="row">Expected validation records</th><td>{v.metrics.n}</td></tr><tr><th scope="row">Successful predictions</th><td>{v.metrics.ok}</td></tr><tr><th scope="row">Accuracy</th><td>{metric(v.metrics.accuracy)}</td></tr><tr><th scope="row">Macro F1</th><td>{metric(v.metrics.macro_f1)}</td></tr><tr><th scope="row">Coverage</th><td>{metric(v.metrics.coverage)}</td></tr><tr><th scope="row">Cross entropy</th><td>{metric(v.metrics.cross_entropy)} · {v.metrics.cross_entropy_complete ? 'complete' : 'incomplete'}</td></tr><tr><th scope="row">Independent verifier</th><td>{v.independent_metrics_match?'matches recomputation':'mismatch'}</td></tr></tbody></table></div>
          <div className="tablewrap" tabIndex={0} role="region" aria-label="Validation prediction dispositions (scrollable)"><table><caption>Validation prediction dispositions</caption><thead><tr><th>Disposition</th><th>Records</th></tr></thead><tbody>{Object.entries(v.metrics.disposition_counts).sort(([a],[b])=>a.localeCompare(b)).map(([name,count])=><tr key={name}><th scope="row">{name}</th><td>{count}</td></tr>)}</tbody></table></div>
          <p className="hash">Evaluation digest · {v.evaluation_digest}</p>
        </div>}
      </Status>}
  </section>;
}

function RealErrorRun({base,runs,selectedRunId,setSelectedRunId,run,validation,loading,canRuns,cell,setCell}: {
  base:string; runs:RealRun[]; selectedRunId:string; setSelectedRunId:(id:string)=>void; run:RealRun|null;
  validation:Resource<RealValidation>; loading:boolean; canRuns:boolean; cell:number[]; setCell:(cell:number[])=>void;
}) {
  const [bucket,setBucket]=useState<'cell'|'missing'>('cell');
  const [page,setPage]=useState<RealValidationSlice|null>(null); const [members,setMembers]=useState<RealValidationSlice['members']>([]);
  const [sliceError,setSliceError]=useState<ApiError|null>(null); const [sliceBusy,setSliceBusy]=useState(false);
  const [retry,setRetry]=useState(0);
  const requestKey=`${selectedRunId}:${run?.id||''}:${bucket}:${cell[0]??0}:${cell[1]??0}:${validation.data?.evaluation_digest||''}`;
  const requestKeyRef=useRef(requestKey); requestKeyRef.current=requestKey;
  useEffect(()=>{
    let active=true; setPage(null); setMembers([]); setSliceError(null);
    if(!run || validation.data?.run_id!==run.id || run.scope!=='real-training/v1') return ()=>{active=false};
    const predicted=bucket==='cell'?(cell[1]??0):null;
    getRealValidationSlice(base,run.id,{actual:cell[0]??0,predicted,bucket,offset:0}).then(value=>{
      if(active){setPage(value);setMembers(value.members);setSliceError(null)}
    }).catch(e=>{if(active)setSliceError(e instanceof ApiError?e:new ApiError(0,String(e),'offline'))});
    return ()=>{active=false};
  },[base,run?.id,run?.scope,validation.data?.evaluation_digest,cell[0],cell[1],bucket,retry]);
  async function more(){
    if(!run||!page||page.next_offset===null||sliceBusy)return;
    const requestedKey=requestKey;
    setSliceBusy(true);
    try{const next=await getRealValidationSlice(base,run.id,{actual:cell[0]??0,predicted:bucket==='cell'?(cell[1]??0):null,bucket,offset:page.next_offset});
      if(requestKeyRef.current!==requestedKey)return;
      if(next.membership_digest!==page.membership_digest||next.evaluation_digest!==page.evaluation_digest||next.total!==page.total)throw new ApiError(409,'REAL_VALIDATION_SLICE_CHANGED','blocked');
      setPage(next);setMembers(old=>[...old,...next.members]);setSliceError(null);
    }catch(e){setSliceError(e instanceof ApiError?e:new ApiError(0,String(e),'offline'))}finally{setSliceBusy(false)}
  }
  const classes=validation.data?.classes||[];
  return <section className="panel" data-real-run-screen="errors" aria-labelledby="real-errors-title">
    <h2 id="real-errors-title">Real validation error investigation</h2>
    <p>Members come only from the verified validation population. Each thumbnail is fetched again through the current rights-gated media route.</p>
    <RealRunPicker runs={runs} selectedRunId={selectedRunId} setSelectedRunId={setSelectedRunId} loading={loading} canRuns={canRuns}/>
    {!run ? <Empty label="real error slice">Choose a real training run.</Empty>
      : validation.data?.run_id!==run.id ? (validation.error ? <ErrorState label="verified validation evidence" error={validation.error} retry={validation.reload}/> : <Loading label="verified validation evidence"/>)
      : <div className="stack"><div className="tools"><label>Actual class<select value={cell[0]??0} onChange={e=>setCell([Number(e.target.value),cell[1]??0])}>{classes.map((c,i)=><option key={c} value={i}>{c}</option>)}</select></label>
        <label>Disposition<select value={bucket} onChange={e=>setBucket(e.target.value as 'cell'|'missing')}><option value="cell">Predicted class</option><option value="missing">Missing or failed</option></select></label>
        {bucket==='cell'&&<label>Predicted class<select value={cell[1]??0} onChange={e=>setCell([cell[0]??0,Number(e.target.value)])}>{classes.map((c,i)=><option key={c} value={i}>{c}</option>)}</select></label>}</div>
        {sliceError&&<ErrorState label="validation slice" error={sliceError} retry={()=>setRetry(n=>n+1)}/>}
        {!page&&!sliceError&&<Loading label="validation slice"/>}
        {page&&<section className="panel"><h3>{classes[cell[0]??0]} → {bucket==='missing'?'missing / failed':classes[cell[1]??0]}</h3>
          <p>{page.total} exact validation members · {members.length} loaded</p>
          {members.length?<div className="gallery">{members.map(item=><div className="samplecard" role="group" aria-label={`Validation member ${short(item.sample_id)}`} key={item.sample_id}>
            <MediaImg className="art" src={`${base}/real/samples/${encodeURIComponent(item.sample_id)}/media`} alt={`Rights-cleared validation member: ${classes[item.actual]}; ${item.predicted===null?item.status:`predicted ${classes[item.predicted]}`}`}/>
            <div className="meta"><b>{short(item.sample_id)}</b><span>{classes[item.actual]} → {item.predicted===null?item.status:classes[item.predicted]}</span></div>
          </div>)}</div>:<Empty label="validation error slice">No validation members match this cell.</Empty>}
          {page.next_offset!==null&&<button disabled={sliceBusy} onClick={()=>void more()}>{sliceBusy?'Loading…':'Load more validation members'}</button>}
          <p className="hash">Membership SHA256 · {page.membership_digest}</p><p className="hash">Evaluation SHA256 · {page.evaluation_digest}</p>
        </section>}
      </div>}
  </section>;
}

function RealRecoveryRun({base,user,runs,selectedRunId,setSelectedRunId,run,lineage,loading,canRuns,writer,busy,submit,refreshRun}: {
  base:string; user:User; runs:RealRun[]; selectedRunId:string; setSelectedRunId:(id:string)=>void;
  run:RealRun|null; lineage:Resource<RealLineage>; loading:boolean; canRuns:boolean; writer:boolean; busy:boolean; submit:Submit; refreshRun:()=>void;
}) {
  const [replayEpoch,setReplayEpoch]=useState('');
  return <section className="panel" data-real-run-screen="recovery" aria-labelledby="real-recovery-title">
    <h2 id="real-recovery-title">Real run recovery</h2>
    <p>Recovery follows the durable real attempt and committed checkpoint ledger. Failed runs remain terminal; no fixture checkpoint is used.</p>
    <RealRunPicker runs={runs} selectedRunId={selectedRunId} setSelectedRunId={setSelectedRunId} loading={loading} canRuns={canRuns}/>
    {!run ? <Empty label="real recovery">Choose a real run to inspect its recovery boundary.</Empty>
      : <Status r={lineage} label="real recovery lineage">
        {l=><div className="stack"><dl className="detail"><dt>Run state</dt><dd><StateTag state={l.state}/></dd><dt>Committed checkpoints</dt><dd>{l.checkpoints.length} of {l.epochs}</dd>
          <dt>Attempts</dt><dd>{l.recovery.attempts_used} of {l.recovery.attempt_budget}</dd><dt>Latest checkpoint</dt><dd>{l.checkpoints.length?<span className="hash">{l.checkpoints[l.checkpoints.length-1].digest}</span>:'none'}</dd>
          <dt>Recovery eligibility</dt><dd>{l.recovery.resumable?'server reports resumable':l.recovery.blocked_code||'not available'}</dd></dl>
          {l.boundaries.map(b=><div className="recoveryrail" key={b.interrupted_seq}><div className="checkpoint"><b>Committed through epoch {b.committed_epoch}</b><StateTag state="succeeded"/></div><span>→</span><div className="checkpoint"><b>Interruption</b><StateTag state={b.resulting_state||'interrupted'}/><small>{b.interrupted_at}</small></div><span>→</span><div className="checkpoint"><b>{b.replay_epoch?`Replay epoch ${b.replay_epoch}`:'No replay requested'}</b><small>{b.new_attempt?`Attempt ${short(b.new_attempt)} · fence ${b.new_fence}`:'Awaiting recovery decision'}</small></div></div>)}
          {l.recovery.resumable && writer && run.scope==='real-training/v1' && <div className="row"><label>Replay epoch<input type="number" min="1" max={l.epochs} value={replayEpoch||String(l.recovery.next_replay_epoch)} onChange={e=>setReplayEpoch(e.target.value)}/></label>
            <button className="primary" disabled={busy||!Number.isInteger(Number(replayEpoch||l.recovery.next_replay_epoch))||Number(replayEpoch||l.recovery.next_replay_epoch)!==l.recovery.next_replay_epoch}
              onClick={()=>void submit(async()=>{const ack=await resumeRealRun(base,user.csrf,run.id,Number(replayEpoch||l.recovery.next_replay_epoch));setReplayEpoch(String(ack.replay_epoch));refreshRun();},'Real resume request accepted; waiting for the new attempt record.')}>Resume at epoch {l.recovery.next_replay_epoch}</button>
          </div>}
          {l.recovery.resumable&&!writer&&<p data-state="permission_denied">Only owners and researchers can request recovery.</p>}
          {!l.recovery.resumable&&<p data-state="not_recoverable">This run is not resumable: {l.recovery.blocked_code||'server eligibility not met'}.</p>}
        </div>}
      </Status>}
  </section>;
}

function metric(value:number|null|undefined){return typeof value==='number'&&Number.isFinite(value)?value.toFixed(4):'undefined';}

function QualifiedInferencePanel({base, user, busy, submit}: {base:string; user:User; busy:boolean; submit:Submit}) {
  const releases = useResource<{items:QualifiedRelease[]}>(`${base}/qualified-releases`, []);
  const [releaseId, setReleaseId] = useState('');
  const [memberId, setMemberId] = useState('');
  const [file, setFile] = useState<File|null>(null);
  const [run, setRun] = useState<RealRun|null>(null);
  const [pollFailure, setPollFailure] = useState<ApiError|null>(null);
  const [pollRetry, setPollRetry] = useState(0);
  const release = releases.data?.items.find(x => x.release_id === releaseId) || releases.data?.items[0];
  useEffect(() => { if (release && !releaseId) setReleaseId(release.release_id); }, [release?.release_id, releaseId]);
  useEffect(() => {
    if (!run || ['succeeded','failed','cancelled'].includes(run.state)) return;
    return startRunPolling({
      read: () => getRealRun(base, run.id).then(v => v.run),
      onValue: value => { setRun(value); setPollFailure(null); },
      onError: e => setPollFailure(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')),
      isTerminal: value => ['succeeded','failed','cancelled'].includes(value.state), intervalMs: 1500,
    });
  }, [base, run?.id, run?.state, pollRetry]);
  return <div className="stack"><section className="panel"><h2>Qualified release inference</h2>
    <p>Only a release whose frozen usefulness result and consumed plan match the operator registry can be selected. Inference runs in the local network-off pinned model worker; the browser sends image bytes and a registered rights member ID, never a model path or code.</p>
    <Status r={releases} label="qualified releases">{data => data.items.length ? <form className="bigform" onSubmit={e => { e.preventDefault(); if (!release || !file || !memberId.trim()) return; void submit(async () => { const queued = await enqueueQualifiedImageInference(base, user.csrf, release.release_id, memberId.trim(), file); setPollFailure(null); setRun(queued); }, 'Qualified inference queued for the bounded local worker.'); }}>
      <div className="fields"><label>Qualified model<select value={release?.release_id || ''} onChange={e => setReleaseId(e.target.value)}>{data.items.map(x => <option key={x.release_id} value={x.release_id}>{x.recipe} · {x.release_id}</option>)}</select></label>
        <label>Registered image member ID<input required maxLength={512} value={memberId} onChange={e => setMemberId(e.target.value)} placeholder="Exact rights registry member ID" /></label>
        <label>Image file<input required type="file" accept="image/jpeg,image/png,image/webp" onChange={e => setFile(e.target.files?.[0] || null)} /></label></div>
        <p className="inline-note">PNG, JPEG or WebP · ≤5 MiB. The image digest and member ID must match current signed read-only inference rights. Protected members are refused without exposing membership.</p>
        {!release?.inference_allowed && <p className="error" data-state="permission_denied">Your role or the qualified pinned model runtime is not ready for inference.</p>}
        <button className="primary" disabled={busy || !release?.inference_allowed || !file || !memberId.trim() || file.size > 5*1024*1024}>Run qualified inference</button>
      </form> : <Empty label="qualified release"><p>No qualified release is currently selectable. Internal candidates are not offered here.</p></Empty>}</Status>
  </section>
  <section className="panel"><h2>Prediction inspector</h2>{!run ? <Empty label="inference records"><p>No inference request yet.</p></Empty> : <div data-state={run.state}>
    <p>Run <span className="hash">{run.id}</span> · {run.state}</p>
    {pollFailure&&<ErrorState label="qualified inference status" error={pollFailure} retry={()=>setPollRetry(n=>n+1)}/>}
    {run.prediction ? <><p>Top class: <b>{run.prediction.classes[run.prediction.top1]}</b></p><div className="tablewrap" tabIndex={0} role="region" aria-label="Prediction probabilities (scrollable)"><table><thead><tr><th>Class</th><th>Probability</th></tr></thead><tbody>{run.prediction.classes.map((name,i)=><tr key={name}><th scope="row">{name}</th><td>{(run.prediction!.probabilities[i]*100).toFixed(2)}%</td></tr>)}</tbody></table></div><p className="inline-note">Probabilities are not calibrated confidence or out-of-distribution detection. This result remains private to this workspace.</p></> : <p>{run.state==='failed'?'Inference failed; no prediction is presented.':'Waiting for the fixed worker; no placeholder prediction is shown.'}</p>}
  </div>}</section></div>;
}

function RealArtifacts({base, user, runs, runListLoading, busy, submit, loadMore, canLoadMore}: {
  base: string; user: User; runs: RealRun[]; runListLoading: boolean; busy: boolean; submit: Submit; loadMore: () => Promise<void>; canLoadMore: boolean;
}) {
  const qualified = useResource<{items: QualifiedRelease[]}>(`${base}/qualified-releases`, []);
  const [runId, setRunId] = useState('');
  const [bundle, setBundle] = useState<RealBundle | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const eligible = runs.filter(r => r.scope === 'real-training/v1' && r.state === 'succeeded' && r.artifact_status === 'verified');
  const selected = runId && eligible.some(r => r.id === runId) ? runId : eligible[0]?.id || '';
  const receiptLineage = useResource<RealLineage>(selected ? `${base}/screens/runs/${encodeURIComponent(selected)}/lineage` : null, []);
  useEffect(() => {
    if (!selected) { setBundle(null); return; }
    let active = true;
    getRealBundle(base, selected).then(v => { if (active) { setBundle(v); setError(null); } })
      .catch(e => { if (active) setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')); });
    return () => { active = false; };
  }, [base, selected]);
  return <section className="panel" aria-labelledby="real-artifacts-title">
    <h2 id="real-artifacts-title">Model releases</h2>
    <p>Private training candidates remain inspectable but are not available to ordinary download or inference. A separate qualified release appears here only when its exact consumed plan, model and aggregate result still match the local operator registry.</p>
    <Status r={qualified} label="qualified releases">{q => q.items.length ? q.items.map(item => <section className="callout" key={item.release_id} data-state="qualified_release">
      <h3>Qualified release · {item.recipe}</h3><p>{item.release_id} · frozen plan {short(item.plan_id)}</p>
      <dl className="detail"><dt>Bundle SHA256</dt><dd className="hash">{item.bundle_digest}</dd><dt>Model SHA256</dt><dd className="hash">{item.model_digest}</dd><dt>Frozen-usefulness accuracy</dt><dd>{(item.aggregate.accuracy * 100).toFixed(2)}% · {item.aggregate.n} examples</dd><dt>Public export</dt><dd>No</dd></dl>
      {item.download_allowed && <button className="primary" disabled={busy} onClick={() => void submit(async () => { const blob = await downloadQualifiedRelease(base, item.release_id, user.csrf); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `fieldwork-${item.release_id}.zip`; a.click(); URL.revokeObjectURL(url); }, 'Qualified release downloaded after current rights and consumed-plan checks.')}>Download qualified release</button>}
      {!item.download_allowed && <p className="inline-note" data-state="permission_denied">Your role cannot download model artifacts.</p>}
    </section>) : <Empty label="qualified releases"><p>No release currently passes the exact registry and consumed-plan checks.</p></Empty>}</Status>
    <h3>Private training candidates</h3><p>These model bundles are internal candidates. They cannot be downloaded or selected by ordinary browser inference.</p>
    {runListLoading && !runs.length && <Loading label="real runs"/>}
    {!eligible.length ? <Empty label="verified real bundles"><p>No verified real bundle is available in the loaded real-run records.</p></Empty> : <label>Verified real training run<select value={selected} onChange={e => setRunId(e.target.value)}>{eligible.map(r => <option key={r.id} value={r.id}>{short(r.id)} · verified</option>)}</select></label>}
    {canLoadMore && <button disabled={runListLoading} onClick={() => void loadMore()}>{runListLoading ? 'Loading…' : 'Load more runs'}</button>}
    {error && <ErrorState label="verified model bundle" error={error} retry={() => { if (selected) void getRealBundle(base, selected).then(setBundle).catch(e => setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline'))); }} />}
    {bundle && <><dl className="detail"><dt>Bundle digest</dt><dd className="hash">{bundle.bundle_digest}</dd><dt>Scope</dt><dd>{bundle.scope}</dd><dt>Dataset version</dt><dd>{bundle.lineage.version_id}</dd><dt>Dataset digest</dt><dd className="hash">{bundle.lineage.dataset_digest}</dd></dl>
      <h3>Verified bundle files</h3><div className="tablewrap" tabIndex={0} role="region" aria-label="Verified bundle files (scrollable)"><table><thead><tr><th>File</th><th>Bytes</th><th>SHA256</th></tr></thead><tbody>{Object.entries(bundle.manifest.files).map(([name, file]) => <tr key={name}><th scope="row">{name}</th><td>{file.bytes}</td><td className="hash">{file.sha256}</td></tr>)}</tbody></table></div>
      <p className="inline-note" data-state="permission_denied">Private candidates are not downloadable or selectable by ordinary inference, regardless of workspace role.</p><p className="inline-note">Public export authorized: no. This bundle is private and validation-only.</p>
      <Status r={receiptLineage} label="artifact verification receipt">{l => <ArtifactReceipt events={l.events}/>}</Status></>}
  </section>;
}

function RealWorkspaceSettings({base, user, busy, submit}: {base: string; user: User; busy: boolean; submit: Submit}) {
  const [view, setView] = useState<WorkspaceSettingsView | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [draft, setDraft] = useState({retention_days: '365', max_concurrent_runs: '2', max_epochs: '100'});
  const [roles, setRoles] = useState<Record<string, string>>({});
  const reload = async () => { const next = await getWorkspaceSettings(base); setView(next); setDraft({ retention_days: String(next.settings.retention_days), max_concurrent_runs: String(next.settings.max_concurrent_runs), max_epochs: String(next.settings.max_epochs) }); setRoles(Object.fromEntries(next.members.map(m => [m.name, m.role]))); setError(null); };
  useEffect(() => { let active = true; getWorkspaceSettings(base).then(next => { if (active) { setView(next); setDraft({ retention_days: String(next.settings.retention_days), max_concurrent_runs: String(next.settings.max_concurrent_runs), max_epochs: String(next.settings.max_epochs) }); setRoles(Object.fromEntries(next.members.map(m => [m.name, m.role]))); } }).catch(e => { if (active) setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline')); }); return () => { active = false; }; }, [base]);
  return <section className="panel" aria-labelledby="real-settings-title"><h2 id="real-settings-title">Workspace controls</h2><p>Roles remain server-derived. Owners manage existing account roles and revisioned workspace limits.</p>
    {!view ? (error ? <ErrorState label="workspace controls" error={error} retry={() => { void reload().catch(e => setError(e instanceof ApiError ? e : new ApiError(0, String(e), 'offline'))); }} /> : <Loading label="workspace controls"/>) : <>
      <h3>Workspace policy · revision {view.settings.revision}</h3><form className="bigform" onSubmit={e => { e.preventDefault(); void submit(async () => { await updateWorkspaceSettings(base, user.csrf, { ...view.settings, retention_days: Number(draft.retention_days), max_concurrent_runs: Number(draft.max_concurrent_runs), max_epochs: Number(draft.max_epochs) }); await reload(); }, 'Workspace policy saved with a new revision.'); }}>
        <div className="fields"><label>Minimum evidence retention (days)<input type="number" min="30" max="3650" value={draft.retention_days} onChange={e => setDraft({...draft, retention_days:e.target.value})}/></label><label>Concurrent real run limit<input type="number" min="1" max="16" value={draft.max_concurrent_runs} onChange={e => setDraft({...draft, max_concurrent_runs:e.target.value})}/></label><label>Maximum epochs per real run<input type="number" min="1" max="100" value={draft.max_epochs} onChange={e => setDraft({...draft, max_epochs:e.target.value})}/></label></div>
        {user.role === 'owner' ? <button className="primary" disabled={busy}>Save workspace policy</button> : <p className="error" data-state="permission_denied">Only owners can change workspace policy.</p>}
      </form><p className="inline-note">Evidence retention can only increase and no automatic record deletion is exposed. Run limits are enforced at admission; the workspace cap does not promise parallel CPU execution.</p>
      <h3>Members · {view.owner_count} owner{view.owner_count === 1 ? '' : 's'}</h3><div className="stack">{view.members.map(m => <div className="fields" key={m.name}><label>Account<input readOnly value={m.name}/></label><label>Role<select disabled={busy || user.role !== 'owner'} value={roles[m.name] || m.role} onChange={e => setRoles({...roles, [m.name]:e.target.value})}><option value="owner">Owner</option><option value="researcher">Researcher</option><option value="reviewer">Reviewer</option><option value="viewer">Viewer</option></select></label>{user.role === 'owner' && roles[m.name] !== m.role && <button disabled={busy} onClick={() => void submit(async () => { await updateMemberRole(base, user.csrf, m.name, roles[m.name]); await reload(); }, 'Membership role changed; the account’s existing sessions no longer pass role validation.')}>Save role</button>}</div>)}</div><p className="inline-note">The last owner cannot be demoted. Membership changes are audited and old sessions fail the issued-role check.</p>
      <h3>Workspace control audit</h3>{view.audit.length ? <div className="tablewrap" tabIndex={0} role="region" aria-label="Workspace control audit (scrollable)"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Revision / detail</th></tr></thead><tbody>{view.audit.map((event, i) => <tr key={`${event.event_type}:${event.at_utc}:${i}`}><td>{event.at_utc}</td><td>{event.actor}</td><td>{event.event_type}</td><td>{JSON.stringify(event.detail)}{event.revision ? ` · revision ${event.revision}` : ''}</td></tr>)}</tbody></table></div> : <Empty label="workspace control audit"><p>No workspace policy or membership changes are recorded.</p></Empty>}
    </>}</section>;
}
