"""Round-4 milestone 3a: real intake path, ML-T-INTAKE cases.

Order: (1) valid real archive, (2) corrupt, (3) oversized, (4) unsafe tar,
(5) unsafe zip, (6) expansion bomb, (7) same pixels different encoding,
(8) the identical real archive a second time.
Fixtures are derived locally (from accepted CC-BY assets or synthetic bytes) into
var/datasets/tf_flowers/intake-fixtures/, a directory separate from the code.
"""
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

from round4_common import DS, EVIDENCE, admin_dsn, context, request_store, set_registry_env, write_json
from PIL import Image, ImageOps
from fieldwork.intake import LABEL_BY_DIR, run_intake
from fieldwork.rights import RightsService
from fieldwork.rights_decision import DecisionRejected
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.store import Store

FIX = DS / 'intake-fixtures'
OUT = EVIDENCE / 'intake'


def tar_with(path, entries, mode='w:gz'):
    with tarfile.open(path, mode) as tf:
        for e in entries:
            ti = tarfile.TarInfo(e['name'])
            if e.get('type') == 'symlink':
                ti.type = tarfile.SYMTYPE; ti.linkname = e['target']; tf.addfile(ti)
            elif e.get('type') == 'hardlink':
                ti.type = tarfile.LNKTYPE; ti.linkname = e['target']; tf.addfile(ti)
            elif e.get('type') == 'zeros':
                ti.size = e['size']; tf.addfile(ti, _Zeros(e['size']))
            else:
                ti.size = len(e['data']); tf.addfile(ti, io.BytesIO(e['data']))


class _Zeros(io.RawIOBase):
    def __init__(self, n):
        self.n = n

    def readable(self):
        return True

    def readinto(self, b):
        k = min(len(b), self.n)
        b[:k] = bytes(k)
        self.n -= k
        return k


def png_bytes(img):
    buf = io.BytesIO(); img.save(buf, 'PNG', optimize=False); return buf.getvalue()


def build_fixtures(sample_paths):
    FIX.mkdir(parents=True, exist_ok=True)
    real = [Path(p).read_bytes() for p in sample_paths[:3]]
    tar_with(FIX / 'corrupt.tar.gz', [
        {'name': 'corrupt/truncated.jpg', 'data': real[0][:2048]},
        {'name': 'corrupt/garbage.jpg', 'data': b'\xff\xd8\xff\xe0' + os.urandom(4000)},
        {'name': 'corrupt/text-named-jpg.jpg', 'data': b'this is not an image\n' * 50},
        {'name': 'corrupt/bmp-unsupported.bmp', 'data': _bmp()},
    ])
    big = Image.new('RGB', (5000, 4500), (40, 120, 40))
    tar_with(FIX / 'oversized.tar.gz', [
        {'name': 'oversized/22_5_megapixel.png', 'data': png_bytes(big)},
        {'name': 'oversized/21MiB_member.jpg', 'data': os.urandom(21 * 1024 * 1024)},
    ])
    tar_with(FIX / 'unsafe.tar.gz', [
        {'name': '../escape.jpg', 'data': real[0]},
        {'name': '/absolute.jpg', 'data': real[0]},
        {'name': 'C:/drive.jpg', 'data': real[0]},
        {'name': 'dir\\backslash.jpg', 'data': real[0]},
        {'name': 'link.jpg', 'type': 'symlink', 'target': '/etc/passwd'},
        {'name': 'hard.jpg', 'type': 'hardlink', 'target': 'link.jpg'},
        {'name': 'safe/../../double.jpg', 'data': real[0]},
        {'name': 'aux.jpg', 'data': real[0]},
    ], mode='w:gz')
    with zipfile.ZipFile(FIX / 'unsafe.zip', 'w') as zf:
        zf.writestr('../../zip-escape.jpg', real[1])
        info = zipfile.ZipInfo('zip-link.jpg'); info.external_attr = (0o120777 << 16)
        zf.writestr(info, '/etc/passwd')
        zf.writestr('ok/../../../x.jpg', real[1])
    # Declared expansion 60 x 19MiB = 1140MiB > 1GiB; rejected by header pre-scan before any write.
    tar_with(FIX / 'expansion-bomb.tar.gz', [{'name': f'bomb/{i:02d}.jpg', 'type': 'zeros', 'size': 19 * 1024 * 1024} for i in range(60)])
    entries = []
    for i, p in enumerate(sample_paths[:3]):
        with Image.open(p) as im:
            rgb = ImageOps.exif_transpose(im).convert('RGB')
        entries.append({'name': f'reencoded/same_pixels_{i}.png', 'data': png_bytes(rgb)})
        if i == 0:
            entries.append({'name': 'reencoded/flipped_new_pixels.png', 'data': png_bytes(rgb.transpose(Image.Transpose.FLIP_LEFT_RIGHT))})
    tar_with(FIX / 'same-pixels-different-encoding.tar.gz', entries)


def _bmp():
    buf = io.BytesIO(); Image.new('RGB', (8, 8)).save(buf, 'BMP'); return buf.getvalue()


def main():
    ctx = context()
    ws = ctx['workspace_id']
    set_registry_env()
    req = request_store(ws)
    service = RightsService(req, load_trusted_registry)
    operator = Store(dsn=admin_dsn())
    dataset = ctx['rights_dataset_eligible']

    def rights_check(member_id, raw_sha, size):
        with req.rights_repository() as repo:
            row = repo.asset(ws, dataset, member_id)
            if not row:
                return 'NOT_IN_RIGHTS_INVENTORY'
            if row['asset_sha256'] != raw_sha or row['asset_bytes'] != size:
                return 'DIGEST_DIFFERS_FROM_RIGHTS_INVENTORY'
            raw = repo.decision(ws, dataset, member_id, 'local_private_training')
            if raw is None:
                return 'MISSING_DECISION'
            try:
                service._verify(repo, ws, dataset, member_id, 'local_private_training', raw)
            except DecisionRejected as exc:
                return exc.code
        return None

    def label_of(member_id):
        return LABEL_BY_DIR.get(member_id.split('/', 1)[0])

    common = dict(quarantine_root=DS / 'quarantine', media_root=DS / 'media', rights_check=rights_check,
                  rights_dataset_id=dataset, report_dir=OUT / 'reports')
    actor = ctx['actors']['steward']
    real = DS / 'archive/flower_photos.tgz'
    results = {}
    results['1_valid_real_archive'] = run_intake(operator, ws, actor, real, member_prefix='flower_photos/', label_of=label_of, **common)
    with operator.connect() as c:
        paths = [r['media_path'] for r in c.execute("SELECT media_path FROM fw_samples WHERE workspace=%s ORDER BY source_member LIMIT 3", (ws,)).fetchall()]
        before_second = c.execute('SELECT count(*) n FROM fw_samples WHERE workspace=%s', (ws,)).fetchone()['n']
    build_fixtures(paths)
    for key, name in [('2_corrupt', 'corrupt.tar.gz'), ('3_oversized', 'oversized.tar.gz'), ('4_unsafe_tar', 'unsafe.tar.gz'),
                      ('5_unsafe_zip', 'unsafe.zip'), ('6_expansion_bomb', 'expansion-bomb.tar.gz'),
                      ('7_same_pixels_different_encoding', 'same-pixels-different-encoding.tar.gz')]:
        results[key] = run_intake(operator, ws, actor, FIX / name, **common)
    with operator.connect() as c:
        ids_before = {r['sample_id'] for r in c.execute('SELECT sample_id FROM fw_samples WHERE workspace=%s', (ws,)).fetchall()}
    results['8_same_real_archive_again'] = run_intake(operator, ws, actor, real, member_prefix='flower_photos/', label_of=label_of, **common)
    with operator.connect() as c:
        ids_after = {r['sample_id'] for r in c.execute('SELECT sample_id FROM fw_samples WHERE workspace=%s', (ws,)).fetchall()}
        batches = c.execute('SELECT batch_id,archive_name,state,reason,source_total,accepted,rejected,duplicate,noop,report_sha256 FROM fw_intake_batches WHERE workspace=%s ORDER BY started_utc', (ws,)).fetchall()
        empty_reasons = c.execute("SELECT count(*) n FROM fw_intake_members WHERE workspace=%s AND (reason IS NULL OR reason='')", (ws,)).fetchone()['n']
    # Request principal can read the catalog only inside its tenant.
    with req.connect() as c:
        visible = c.execute('SELECT count(*) n FROM fw_samples').fetchone()['n']
    from fieldwork.store import TENANT
    TENANT.set('00000000-0000-0000-0000-000000000000')
    with req.connect() as c:
        other_tenant_visible = c.execute('SELECT count(*) n FROM fw_samples').fetchone()['n']
    TENANT.set(ws)

    def rejected_reasons(r):
        return sorted({m['reason'] for m in r['members'] if m['disposition'] == 'rejected'})
    checks = {
        'every_batch_reconciles': all(r['reconciles'] for r in results.values()),
        'second_identical_intake_new_sample_ids': len(ids_after - ids_before),
        'second_identical_intake_accepted': results['8_same_real_archive_again']['accepted'],
        'traversal_rejected': any('TRAVERSAL' in x for x in rejected_reasons(results['4_unsafe_tar'])) and any('TRAVERSAL' in x for x in rejected_reasons(results['5_unsafe_zip'])),
        'symlink_rejected': 'SYMLINK_MEMBER' in rejected_reasons(results['4_unsafe_tar']) and 'SYMLINK_MEMBER' in rejected_reasons(results['5_unsafe_zip']),
        'hardlink_rejected': 'HARDLINK_MEMBER' in rejected_reasons(results['4_unsafe_tar']),
        'expansion_rejected': results['6_expansion_bomb']['archive_level_rejection'] == 'ARCHIVE_REJECTED:EXPANSION_LIMIT',
        'expansion_prescan_before_write': 'header pre-scan raises before the destination is created; asserted by tests/test_dataset_round4.py::test_expansion_prescan_rejects_before_any_write',
        'corrupt_reasons': rejected_reasons(results['2_corrupt']),
        'oversized_reasons': rejected_reasons(results['3_oversized']),
        'same_pixel_dispositions': {m['member']: [m['disposition'], m['reason']] for m in results['7_same_pixels_different_encoding']['members']},
        'members_with_empty_reason': empty_reasons,
        'catalog_visible_to_request_principal_own_tenant': visible,
        'catalog_visible_to_request_principal_other_tenant': other_tenant_visible,
        'samples_after_first_real_intake': before_second,
    }
    summary = {'workspace_id': ws, 'rights_dataset_id': dataset,
               'batches': [dict(b, batch_id=str(b['batch_id'])) for b in batches],
               'per_case': {k: {x: v[x] for x in ('batch_id', 'archive', 'archive_sha256', 'source_total', 'accepted', 'rejected', 'duplicate', 'noop',
                                                   'reconciles', 'reason_counts', 'archive_level_rejection', 'decoder', 'decoder_restarts',
                                                   'decoder_peak_rss_bytes', 'elapsed_s', 'report_sha256')} for k, v in results.items()},
               'checks': checks}
    write_json(OUT / 'intake-summary.json', summary)
    print(json.dumps(summary, indent=1, default=str))


if __name__ == '__main__':
    main()
