import { ApiError, classify, getJson } from './resource';

const jsonHeaders = (csrf: string, extra: Record<string, string> = {}) => ({
  'Content-Type': 'application/json',
  'X-CSRF-Token': csrf,
  ...extra,
});

export type RealRun = {
  id: string;
  state: string;
  revision: number;
  epoch: number;
  scope: string;
  artifact_status: string;
  cancel_generation: number | null;
  version_id: string;
  prediction?: { classes: string[]; probabilities: number[]; top1: number };
};
export type RealLineage = {
  run_id: string; state: string; epoch: number; epochs: number; fence: number; revision: number;
  current_attempt: string | null; lease: 'live' | 'expired' | null;
  attempts: { id: string; fence: number; created: string; cancel_generation?: number | null; committed_epochs: number[]; current: boolean }[];
  checkpoints: { epoch: number; attempt: string; digest: string; metrics: { epoch: number; train_loss: number; validation_loss: number; updates: number } }[];
  events: { seq: string; kind: string; created: string; payload: Record<string, unknown> | null }[];
  boundaries: { interrupted_seq: string; interrupted_at: string; resulting_state: string | null; committed_epoch: number; resume_seq: string | null; replay_epoch: number | null; new_attempt: string | null; new_fence: number | null }[];
  recovery: { resumable: boolean; blocked_code: string | null; next_replay_epoch: number | null; attempt_budget: number; attempts_used: number };
};
export type RealValidation = {
  run_id: string; scope: 'real-training/v1'; split: 'validation'; evidence_scope: 'validation_only';
  classes: string[]; metrics: { n: number; ok: number; accuracy: number | null; coverage: number | null;
    matrix: number[][]; support: number[]; precision: (number | null)[]; recall: (number | null)[];
    f1: (number | null)[]; macro_f1: number | null; cross_entropy: number | null; status: string;
    disposition_counts: Record<string, number>; null_reasons: Record<string, unknown>; cross_entropy_complete: boolean };
  independent_metrics_match: true; bundle_digest: string; evaluation_digest: string;
};
export type RealValidationSlice = { run_id: string; split: 'validation'; bucket: 'cell' | 'missing';
  predicate: { actual: number; predicted: number | null }; total: number; offset: number; limit: number;
  members: { sample_id: string; actual: number; predicted: number | null; status: string }[];
  next_offset: number | null; membership_digest: string; evaluation_digest: string };
export type RealRunPage = { items: RealRun[]; next_cursor: string | null };
import type { IntakeDetailView } from './intake-detail.ts';
export type RealIntake = {
  intake_id: string;
  state: string;
  result_batch_id?: string | null;
  result_sha256?: string | null;
  created_utc?: string;
  finished_utc?: string | null;
  status_url?: string;
  rights_dataset_id?: string;
  detail?: IntakeDetailView | null;
};
export type RealIntakePage = { items: RealIntake[] };
export type HoldoutPopulation = { tag: string; digest: string; count: number; support: Record<string, { samples: number; groups: number }> };
export type HoldoutPlan = { plan_id: string; version_digest: string; population_digest: string; population_count: number;
  candidate_model_digest: string; candidate_checkpoint_digest: string; evaluator: string; usefulness_spec_sha256: string;
  steward: string; state: 'authorized' | 'consumed' | 'invalidated'; authorized_utc: string; consumed_utc: string | null;
  exposures: number; invalidated_reason: string | null; result_sha256: string | null };
export type StewardPlanView = { version: { id: string; revision: number; digest: string }; populations: HoldoutPopulation[]; plans: HoldoutPlan[]; holdout_rows_returned: 0 };
export type WorkspaceSettings = { revision: number; retention_days: number; max_concurrent_runs: number; max_epochs: number; updated_utc: string | null };
export type WorkspaceSettingsView = { settings: WorkspaceSettings; members: { name: string; role: string }[]; owner_count: number; roles_editable: boolean; retention_enforced: boolean; audit: { actor: string; event_type: string; revision: number | null; detail: Record<string, unknown>; at_utc: string }[] };
export type RealBundle = { run_id: string; bundle_digest: string; manifest: { files: Record<string, { sha256: string; bytes: number }> };
  lineage: Record<string, string | number>; scope: string; download_allowed: boolean; public_export_authorized: false };
export type QualifiedRelease = { release_id: string; purpose: 'qualified_release'; recipe: 'small-residual/v1';
  bundle_digest: string; model_digest: string; version_id: string; version_digest: string;
  plan_id: string; plan_result_sha256: string; aggregate: { accuracy: number; macro_f1: number; coverage: number; n: number };
  public_export_authorized: false; download_allowed: boolean; inference_allowed: boolean };

async function checked<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { code?: string; detail?: string };
    throw new ApiError(response.status, String(body.code || body.detail || response.statusText || 'ERROR'), classify(response.status));
  }
  return response.json() as Promise<T>;
}

export async function enqueueIntake(base: string, csrf: string, datasetId: string, file: File): Promise<RealIntake> {
  const query = new URLSearchParams({ dataset_id: datasetId });
  let response: Response;
  try {
    response = await fetch(`${base}/real/intakes?${query}`, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/octet-stream' },
      body: file,
    });
  } catch {
    throw new ApiError(0, 'NETWORK_UNREACHABLE', 'offline');
  }
  return checked<RealIntake>(response);
}

export const getIntake = (base: string, id: string) => getJson<RealIntake>(`${base}/real/intakes/${encodeURIComponent(id)}`);
export const getRealIntakes = (base: string) => getJson<RealIntakePage>(`${base}/real/intakes`);
export const createRealDraft = <T = unknown>(base: string, csrf: string, source:
  { intake_id: string } | { parent_version_id: string; parent_version_digest: string }) =>
  getJson<T>(`${base}/real/versions`, {
    method: 'POST', headers: jsonHeaders(csrf), body: JSON.stringify(source),
  });
export const assignInitialRealSplitPlan = <T = unknown>(base: string, csrf: string, id: string, revision: number) =>
  getJson<T>(`${base}/real/versions/${encodeURIComponent(id)}/split-plan`, {
    method: 'POST', headers: jsonHeaders(csrf), body: JSON.stringify({ revision }),
  });
export const getRealRuns = (base: string, after: string | null = null) => {
  const query = new URLSearchParams({ limit: '50' });
  if (after) query.set('after', after);
  return getJson<RealRunPage>(`${base}/real/runs?${query}`, { cache: 'no-store' });
};
export const freezeRealVersion = (base: string, csrf: string, id: string, revision: number) =>
  getJson(`${base}/real/versions/${encodeURIComponent(id)}/freeze`, {
    method: 'POST', headers: jsonHeaders(csrf), body: JSON.stringify({ revision }),
  });

export function enqueueRealTraining(base: string, csrf: string, payload: {
  version_id: string; version_revision: number; epochs: number; batch_size: number;
  learning_rate: string; seed: number;
}) {
  return getJson<RealRun>(`${base}/real/runs`, {
    method: 'POST', headers: jsonHeaders(csrf, { 'Idempotency-Key': crypto.randomUUID() }), body: JSON.stringify(payload),
  });
}
export const getRealRun = (base: string, id: string) => getJson<{ run: RealRun }>(`${base}/real/runs/${encodeURIComponent(id)}`, { cache: 'no-store' });
export const getRealLineage = (base: string, id: string) =>
  getJson<RealLineage>(`${base}/screens/runs/${encodeURIComponent(id)}/lineage`, { cache: 'no-store' });
export const getRealValidation = (base: string, id: string) =>
  getJson<RealValidation>(`${base}/real/runs/${encodeURIComponent(id)}/validation`, { cache: 'no-store' });
export const getRealValidationSlice = (base: string, id: string, input: {
  actual: number; predicted: number | null; bucket: 'cell' | 'missing'; offset?: number; limit?: number;
}) => {
  const query = new URLSearchParams({ actual: String(input.actual), bucket: input.bucket,
    offset: String(input.offset ?? 0), limit: String(input.limit ?? 24) });
  if (input.predicted !== null) query.set('predicted', String(input.predicted));
  return getJson<RealValidationSlice>(`${base}/real/runs/${encodeURIComponent(id)}/validation/slices?${query}`, { cache: 'no-store' });
};
export function cancelRealRun(base: string, csrf: string, run: RealRun, reason: string) {
  const idempotencyKey = crypto.randomUUID();
  return getJson(`${base}/real/runs/${encodeURIComponent(run.id)}/cancel`, {
    method: 'POST', headers: jsonHeaders(csrf, { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${run.revision}"` }),
    body: JSON.stringify({ expected_revision: run.revision, reason }),
  }).then(() => getRealRun(base, run.id)).then(v => v.run);
}
export function resumeRealRun(base: string, csrf: string, id: string, replayEpoch: number) {
  return getJson<{ state: string; replay_epoch: number }>(`${base}/real/runs/${encodeURIComponent(id)}/resume`, {
    method: 'POST', headers: jsonHeaders(csrf), body: JSON.stringify({ replay_epoch: replayEpoch }),
  });
}
export const getStewardPlans = (base: string, csrf: string, versionId: string) => {
  const query = new URLSearchParams({ version_id: versionId });
  return getJson<StewardPlanView>(`${base}/real/holdout/plans?${query}`, { headers: { 'X-CSRF-Token': csrf } });
};
export const authorizeStewardPlan = (base: string, csrf: string, payload: {
  version_id: string; version_digest: string; population_digest: string; population_count: number; population_tag: string;
  candidate_model_digest: string; candidate_checkpoint_digest: string; evaluator: string; usefulness_spec_sha256: string;
}) => getJson<{ plan_id: string; state: string; holdout_rows_returned: 0 }>(`${base}/real/holdout/plans`, {
  method: 'POST', headers: jsonHeaders(csrf), body: JSON.stringify(payload),
});
export const invalidateStewardPlan = (base: string, csrf: string, planId: string, reason: string) =>
  getJson<{ plan_id: string; state: string; was_consumed?: boolean; exposures?: number }>(
    `${base}/real/holdout/plans/${encodeURIComponent(planId)}/invalidate`, {
      method: 'POST', headers: jsonHeaders(csrf), body: JSON.stringify({ reason }),
    });

export const getWorkspaceSettings = (base: string) => getJson<WorkspaceSettingsView>(`${base}/real/settings`);
export async function downloadSupportDiagnostics(base: string): Promise<Blob> {
  let response: Response;
  try {
    response = await fetch(`${base}/real/support-diagnostics`, { credentials: 'same-origin' });
  } catch { throw new ApiError(0, 'NETWORK_UNREACHABLE', 'offline'); }
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { code?: string; detail?: string };
    throw new ApiError(response.status, String(body.code || body.detail || response.statusText || 'ERROR'), classify(response.status));
  }
  return response.blob();
}
export const updateWorkspaceSettings = (base: string, csrf: string, payload: WorkspaceSettings) =>
  getJson<{ settings: WorkspaceSettings; saved: boolean }>(`${base}/real/settings`, {
    method: 'PUT', headers: jsonHeaders(csrf), body: JSON.stringify({
      expected_revision: payload.revision, retention_days: payload.retention_days,
      max_concurrent_runs: payload.max_concurrent_runs, max_epochs: payload.max_epochs,
    }),
  });
export const updateMemberRole = (base: string, csrf: string, member: string, role: string) =>
  getJson<{ member: string; role: string; sessions_revoked: boolean }>(
    `${base}/real/settings/members/${encodeURIComponent(member)}`, {
      method: 'PUT', headers: jsonHeaders(csrf), body: JSON.stringify({ role }),
    });

export const getRealBundle = (base: string, runId: string) =>
  getJson<RealBundle>(`${base}/real/runs/${encodeURIComponent(runId)}/bundle`);
export async function downloadRealBundle(base: string, runId: string, csrf: string): Promise<Blob> {
  let response: Response;
  try {
    response = await fetch(`${base}/real/runs/${encodeURIComponent(runId)}/bundle/download`, {
      credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf },
    });
  } catch { throw new ApiError(0, 'NETWORK_UNREACHABLE', 'offline'); }
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { code?: string; detail?: string };
    throw new ApiError(response.status, String(body.code || body.detail || response.statusText || 'ERROR'), classify(response.status));
  }
  return response.blob();
}

export const getQualifiedReleases = (base: string) =>
  getJson<{items: QualifiedRelease[]}>(`${base}/qualified-releases`);
export async function downloadQualifiedRelease(base: string, releaseId: string, csrf: string): Promise<Blob> {
  let response: Response;
  try {
    response = await fetch(`${base}/qualified-releases/${encodeURIComponent(releaseId)}/download`, {
      credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf },
    });
  } catch { throw new ApiError(0, 'NETWORK_UNREACHABLE', 'offline'); }
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { code?: string; detail?: string };
    throw new ApiError(response.status, String(body.code || body.detail || response.statusText || 'ERROR'), classify(response.status));
  }
  return response.blob();
}
export async function enqueueQualifiedImageInference(base: string, csrf: string, releaseId: string,
  memberId: string, file: File): Promise<RealRun> {
  const query = new URLSearchParams({ member_id: memberId });
  let response: Response;
  try {
    response = await fetch(`${base}/qualified-releases/${encodeURIComponent(releaseId)}/inferences/image?${query}`, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf, 'Idempotency-Key': crypto.randomUUID(), 'Content-Type': file.type },
      body: file,
    });
  } catch { throw new ApiError(0, 'NETWORK_UNREACHABLE', 'offline'); }
  return checked<RealRun>(response);
}

