"""Real data intake: archive -> restricted quarantine -> bounded decode -> catalog.

Dispositions (exclusive, one per archive member, each with a reason):
  accepted  - new sample identity created (raw + pixel digest, media promoted)
  rejected  - unsafe path/type, size/pixel bounds, decode failure, non-image, rights
  duplicate - pixel-identical to an existing or in-batch sample (different raw bytes),
              or raw-identical to another member of the same batch; linked, no new ID
  noop      - raw digest already in the workspace catalog (re-import), or a directory
Reconciliation: source_total = accepted + rejected + duplicate + noop.

Rights are checked last and only for would-be-accepted members: the persisted
signed `local_private_training` decision must verify against the exact digest.
Schema below is applied to the isolated database by tools/round4_db.py; the
retained database needs the same DDL as an operator migration (see handoff).
"""
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import psutil
from psycopg.types.json import Jsonb

from .acquisition import ArchiveRejected, sha256_file, stage_archive
from .data import canonical, digest

DECODER_SCRIPT = Path(__file__).resolve().parent / 'decode_child.py'
ITEM_TIMEOUT_S = 10
CHILD_RSS_LIMIT = 512 * 1024 * 1024
INTAKE_TIMEOUT_S = 60 * 60
IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.webp'}

# Stable taxonomy identities (blueprint: class order by UUID, not filesystem order).
TAXONOMY = [
    {'index': 0, 'id': 'b6a4e7a2-5c0f-4d1e-9a51-0d6f3c1e7a01', 'name': 'Daisy', 'source_dir': 'daisy'},
    {'index': 1, 'id': 'b6a4e7a2-5c0f-4d1e-9a51-0d6f3c1e7a02', 'name': 'Dandelion', 'source_dir': 'dandelion'},
    {'index': 2, 'id': 'b6a4e7a2-5c0f-4d1e-9a51-0d6f3c1e7a03', 'name': 'Rose', 'source_dir': 'roses'},
    {'index': 3, 'id': 'b6a4e7a2-5c0f-4d1e-9a51-0d6f3c1e7a04', 'name': 'Sunflower', 'source_dir': 'sunflowers'},
    {'index': 4, 'id': 'b6a4e7a2-5c0f-4d1e-9a51-0d6f3c1e7a05', 'name': 'Tulip', 'source_dir': 'tulips'},
]
LABEL_BY_DIR = {t['source_dir']: t['index'] for t in TAXONOMY}

INTAKE_SCHEMA = '''
CREATE TABLE IF NOT EXISTS fw_intake_batches(
  workspace text NOT NULL, batch_id uuid NOT NULL, archive_name text NOT NULL,
  archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'), archive_bytes bigint NOT NULL,
  rights_dataset_id text, policy text NOT NULL, decoder text, actor text NOT NULL,
  state text NOT NULL CHECK (state IN ('staging','complete','rejected')), reason text,
  source_total int, accepted int, rejected int, duplicate int, noop int, report_sha256 text,
  started_utc timestamptz NOT NULL DEFAULT clock_timestamp(), finished_utc timestamptz,
  PRIMARY KEY(workspace,batch_id),
  CHECK (state<>'complete' OR source_total=accepted+rejected+duplicate+noop));
CREATE TABLE IF NOT EXISTS fw_samples(
  workspace text NOT NULL, sample_id uuid NOT NULL, raw_sha256 text NOT NULL, raw_bytes bigint NOT NULL,
  pixel_sha256 text NOT NULL, width int NOT NULL, height int NOT NULL, format text NOT NULL, decoder text NOT NULL,
  media_path text NOT NULL, source_member text NOT NULL, source_label int, rights_dataset_id text,
  first_batch uuid NOT NULL, created_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace,sample_id), UNIQUE(workspace,raw_sha256));
CREATE INDEX IF NOT EXISTS fw_samples_pixel ON fw_samples(workspace,pixel_sha256);
CREATE TABLE IF NOT EXISTS fw_intake_members(
  workspace text NOT NULL, batch_id uuid NOT NULL, ordinal int NOT NULL, member text NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('accepted','rejected','duplicate','noop')),
  reason text NOT NULL CHECK (length(reason)>0), raw_sha256 text, pixel_sha256 text,
  sample_id uuid, linked_sample_id uuid, claimed_label int,
  PRIMARY KEY(workspace,batch_id,ordinal), FOREIGN KEY(workspace,batch_id) REFERENCES fw_intake_batches(workspace,batch_id),
  CHECK ((disposition='accepted')=(sample_id IS NOT NULL)),
  CHECK (disposition<>'duplicate' OR linked_sample_id IS NOT NULL));
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['fw_intake_batches','fw_samples','fw_intake_members'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename=t AND policyname='fw_intake_tenant') THEN
      EXECUTE format('CREATE POLICY fw_intake_tenant ON %I USING (workspace=current_setting(''fieldwork.workspace'',true)) WITH CHECK (workspace=current_setting(''fieldwork.workspace'',true))', t);
    END IF;
  END LOOP; END $$;
REVOKE ALL ON fw_intake_batches,fw_samples,fw_intake_members FROM PUBLIC;
'''
# Request principal may READ the catalog; only the intake operator writes it.
INTAKE_API_GRANTS = ['GRANT SELECT ON fw_intake_batches, fw_samples, fw_intake_members TO fieldwork_api']


class Decoder:
    """One bounded decoder child at a time; killed and restarted on timeout/RSS."""

    def __init__(self):
        self.proc = None
        self.version = None
        self.restarts = 0
        self.peak_rss = 0

    def _start(self):
        env = {k: v for k, v in os.environ.items() if k in ('SYSTEMROOT', 'PATH', 'TEMP', 'TMP')}
        env['OMP_NUM_THREADS'] = '1'
        self.proc = subprocess.Popen([sys.executable, '-I', '-B', str(DECODER_SCRIPT)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
        self.q = queue.Queue()
        threading.Thread(target=self._pump, args=(self.proc, self.q), daemon=True).start()
        hello = self.q.get(timeout=30)
        self.version = json.loads(hello)['decoder']

    @staticmethod
    def _pump(proc, q):
        for line in proc.stdout:
            q.put(line)
        q.put(None)

    def _kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)
        self.proc = None

    def decode(self, path):
        if self.proc is None:
            self._start()
        self.proc.stdin.write(json.dumps({'path': str(path)}) + '\n')
        self.proc.stdin.flush()
        deadline = time.monotonic() + ITEM_TIMEOUT_S
        ps = psutil.Process(self.proc.pid)
        while True:
            try:
                line = self.q.get(timeout=0.05)
                break
            except queue.Empty:
                try:
                    rss = ps.memory_info().rss
                except psutil.Error:
                    rss = 0
                self.peak_rss = max(self.peak_rss, rss)
                if rss > CHILD_RSS_LIMIT:
                    self._kill(); self.restarts += 1
                    return {'ok': False, 'reason': 'DECODER_MEMORY_LIMIT'}
                if time.monotonic() > deadline:
                    self._kill(); self.restarts += 1
                    return {'ok': False, 'reason': 'DECODER_TIMEOUT'}
        if line is None:
            self._kill(); self.restarts += 1
            return {'ok': False, 'reason': 'DECODER_CRASHED'}
        return json.loads(line)

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.stdin.close()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._kill()


def _tenant(c, workspace):
    c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (workspace,))


def run_intake(store, workspace, actor, archive, *, quarantine_root, media_root, rights_check=None,
               rights_dataset_id=None, member_prefix='', label_of=None, report_dir=None,
               decoder_factory=None, repair_missing_features=False):
    """Import one archive. Returns the reconciled report (also persisted).

    rights_check(member_id, raw_sha256, raw_bytes) -> None if permitted, else a reason.
    label_of(member_id) -> int|None claimed source label.

    ``decoder_factory`` is an operator-controlled constructor seam. The legacy
    subprocess decoder is only for trusted local fixtures/CLI workflows. The
    W3 real-data worker must supply its pinned isolated container decoder.
    """
    t0 = time.monotonic()
    if repair_missing_features and (rights_check is None or not rights_dataset_id):
        raise ValueError('FEATURE_REPAIR_REQUIRES_CURRENT_RIGHTS_CHECK')
    archive = Path(archive)
    a_sha, a_bytes = sha256_file(archive)
    batch = str(uuid.uuid4())
    from .acquisition import POLICY
    with store.connect() as c:
        _tenant(c, workspace)
        c.execute('''INSERT INTO fw_intake_batches(workspace,batch_id,archive_name,archive_sha256,archive_bytes,
            rights_dataset_id,policy,actor,state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'staging')''',
                  (workspace, batch, archive.name, a_sha, a_bytes, rights_dataset_id, POLICY, actor))
    stage_dir = Path(quarantine_root) / batch
    rows = []
    archive_reason = None
    try:
        inventory = stage_archive(archive, stage_dir)
        members = inventory['members']
    except ArchiveRejected as exc:
        archive_reason = 'ARCHIVE_REJECTED:' + exc.code
        members = exc.members
        for m in members:
            m.update(disposition='rejected', reason=archive_reason)
    decoder = decoder_factory() if decoder_factory is not None else Decoder()
    seen_raw, seen_pixel = {}, {}
    try:
        with store.connect() as c:
            _tenant(c, workspace)
            for m in members:
                if time.monotonic() - t0 > INTAKE_TIMEOUT_S:
                    raise TimeoutError('INTAKE_TIMEOUT')
                row = {'ordinal': m['ordinal'], 'member': m['name']}
                rows.append(row)
                if m['disposition'] == 'rejected':
                    row.update(disposition='rejected', reason=m['reason']); continue
                if m['disposition'] == 'directory':
                    row.update(disposition='noop', reason='DIRECTORY_ENTRY_NOT_A_SAMPLE'); continue
                path = stage_dir / m['path']
                member_id = m['path'][len(member_prefix):] if member_prefix and m['path'].startswith(member_prefix) else m['path']
                row['member'] = member_id
                raw_sha = m['sha256']
                row['raw_sha256'] = raw_sha
                row['claimed_label'] = label_of(member_id) if label_of else None
                if Path(m['path']).suffix.lower() not in IMAGE_EXT:
                    row.update(disposition='rejected', reason='NOT_AN_IMAGE_MEMBER'); continue
                # In-batch check first: this batch's own inserts are visible to the
                # lookup below (same transaction) and must not masquerade as re-imports.
                if raw_sha in seen_raw:
                    row.update(disposition='duplicate', reason='RAW_DUPLICATE_IN_BATCH', linked_sample_id=seen_raw[raw_sha]); continue
                prior = c.execute('''SELECT sample_id,raw_bytes,pixel_sha256,source_member,rights_dataset_id
                    FROM fw_samples WHERE workspace=%s AND raw_sha256=%s FOR UPDATE''', (workspace, raw_sha)).fetchone()
                if prior:
                    if not repair_missing_features:
                        row.update(disposition='noop', reason='RAW_DIGEST_ALREADY_IMPORTED', linked_sample_id=str(prior['sample_id'])); continue
                    feature = c.execute('''SELECT 1 FROM public.fw_sample_perceptual_features
                        WHERE workspace=%s AND sample_id=%s AND algorithm='phash-dct64/v1' ''',
                        (workspace, prior['sample_id'])).fetchone()
                    if feature:
                        row.update(disposition='noop', reason='RAW_DIGEST_ALREADY_IMPORTED', linked_sample_id=str(prior['sample_id'])); continue
                    d = decoder.decode(path)
                    if not d['ok']:
                        row.update(disposition='rejected', reason=d['reason']); continue
                    row['pixel_sha256'] = d['pixel_sha256']
                    # Repair is deliberately limited to the exact canonical
                    # raw member, rights dataset, byte count and pixel identity.
                    # Re-encoded/pixel-only duplicates cannot repair another row.
                    if (prior['raw_bytes'] != m['size'] or prior['pixel_sha256'] != d['pixel_sha256']
                            or prior['source_member'] != member_id
                            or prior['rights_dataset_id'] != rights_dataset_id):
                        row.update(disposition='noop', reason='RAW_DIGEST_ALREADY_IMPORTED',
                                   linked_sample_id=str(prior['sample_id'])); continue
                    if rights_check is not None:
                        denial = rights_check(member_id, raw_sha, m['size'])
                        if denial:
                            row.update(disposition='rejected', reason='RIGHTS:' + denial); continue
                    if (d.get('phash_algorithm') != 'phash-dct64/v1'
                            or not isinstance(d.get('phash_hex'), str)
                            or not re.fullmatch(r'[0-9a-f]{16}', d['phash_hex'])):
                        raise RuntimeError('DECODER_PHASH_RESULT_INVALID')
                    c.execute('''SELECT fw_intake_cap_v1.repair_sample_phash(
                        %s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (workspace, prior['sample_id'], raw_sha, m['size'], d['pixel_sha256'],
                         d['phash_hex'], decoder.version, member_id, rights_dataset_id))
                    row.update(disposition='noop', reason='RAW_DIGEST_FEATURE_BACKFILLED',
                               linked_sample_id=str(prior['sample_id']))
                    continue
                d = decoder.decode(path)
                if not d['ok']:
                    row.update(disposition='rejected', reason=d['reason']); continue
                row['pixel_sha256'] = d['pixel_sha256']
                prior = c.execute('SELECT sample_id FROM fw_samples WHERE workspace=%s AND pixel_sha256=%s ORDER BY sample_id LIMIT 1',
                                  (workspace, d['pixel_sha256'])).fetchone()
                if prior:
                    row.update(disposition='duplicate', reason='PIXEL_IDENTICAL_DIFFERENT_ENCODING', linked_sample_id=str(prior['sample_id'])); continue
                if d['pixel_sha256'] in seen_pixel:
                    row.update(disposition='duplicate', reason='PIXEL_IDENTICAL_DIFFERENT_ENCODING_IN_BATCH', linked_sample_id=seen_pixel[d['pixel_sha256']]); continue
                if rights_check is not None:
                    denial = rights_check(member_id, raw_sha, m['size'])
                    if denial:
                        row.update(disposition='rejected', reason='RIGHTS:' + denial); continue
                sid = str(uuid.uuid4())
                ext = Path(m['path']).suffix.lower()
                media = Path(media_root) / raw_sha[:2] / (raw_sha + ext)
                media.parent.mkdir(parents=True, exist_ok=True)
                if not media.exists():
                    shutil.copyfile(path, media)
                if sha256_file(media)[0] != raw_sha:
                    raise RuntimeError('MEDIA_PROMOTION_DIGEST')
                c.execute('''INSERT INTO fw_samples(workspace,sample_id,raw_sha256,raw_bytes,pixel_sha256,width,height,format,decoder,
                    media_path,source_member,source_label,rights_dataset_id,first_batch) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                          (workspace, sid, raw_sha, m['size'], d['pixel_sha256'], d['width'], d['height'], d['format'], decoder.version,
                           str(media), member_id, row['claimed_label'], rights_dataset_id, batch))
                if d.get('phash_algorithm') is not None or d.get('phash_hex') is not None:
                    if (d.get('phash_algorithm') != 'phash-dct64/v1'
                            or not isinstance(d.get('phash_hex'), str)
                            or not re.fullmatch(r'[0-9a-f]{16}', d['phash_hex'])):
                        raise RuntimeError('DECODER_PHASH_RESULT_INVALID')
                    c.execute('''SELECT fw_intake_cap_v1.publish_sample_phash(%s,%s,%s,%s,%s,%s)''',
                              (workspace, sid, raw_sha, d['pixel_sha256'], d['phash_hex'], decoder.version))
                seen_raw[raw_sha] = sid
                seen_pixel[d['pixel_sha256']] = sid
                row.update(disposition='accepted', reason='ACCEPTED', sample_id=sid)
            counts = {k: sum(1 for r in rows if r['disposition'] == k) for k in ('accepted', 'rejected', 'duplicate', 'noop')}
            source_total = len(members)
            if source_total != sum(counts.values()):
                raise RuntimeError('RECONCILIATION_FAILED')
            for r in rows:
                c.execute('''INSERT INTO fw_intake_members(workspace,batch_id,ordinal,member,disposition,reason,raw_sha256,pixel_sha256,
                    sample_id,linked_sample_id,claimed_label) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                          (workspace, batch, r['ordinal'], r['member'], r['disposition'], r['reason'], r.get('raw_sha256'),
                           r.get('pixel_sha256'), r.get('sample_id'), r.get('linked_sample_id'), r.get('claimed_label')))
            report = {'schema': 'fieldwork.intake-report/v1', 'batch_id': batch, 'workspace': workspace, 'actor': actor,
                      'archive': archive.name, 'archive_sha256': a_sha, 'archive_bytes': a_bytes,
                      'archive_level_rejection': archive_reason, 'decoder': decoder.version,
                      'decoder_restarts': decoder.restarts, 'decoder_peak_rss_bytes': decoder.peak_rss,
                      'source_total': source_total, **counts,
                      'reconciles': source_total == sum(counts.values()),
                      'reason_counts': _reason_counts(rows), 'elapsed_s': round(time.monotonic() - t0, 3),
                      'members': rows}
            report_bytes = canonical(report)
            c.execute('''UPDATE fw_intake_batches SET state=%s,reason=%s,decoder=%s,source_total=%s,accepted=%s,rejected=%s,duplicate=%s,
                noop=%s,report_sha256=%s,finished_utc=clock_timestamp() WHERE workspace=%s AND batch_id=%s''',
                      ('rejected' if archive_reason else 'complete', archive_reason, decoder.version, source_total, counts['accepted'],
                       counts['rejected'], counts['duplicate'], counts['noop'], digest(report_bytes), workspace, batch))
    finally:
        decoder.close()
        # Quarantine copies are disposable: accepted bytes were promoted by digest.
        shutil.rmtree(stage_dir, ignore_errors=True)
    if report_dir:
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        (Path(report_dir) / f'intake-{batch}.json').write_bytes(report_bytes)
    report['report_sha256'] = digest(report_bytes)
    return report


def _reason_counts(rows):
    out = {}
    for r in rows:
        key = r['disposition'] + ':' + r['reason'].split(':')[0] + (':' + r['reason'].split(':')[1] if r['reason'].startswith(('RIGHTS:', 'ARCHIVE_REJECTED:')) else '')
        out[key] = out.get(key, 0) + 1
    return out
