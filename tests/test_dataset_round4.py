"""Round-4 dataset lane: staging safety, LICENSE parsing, grouping/splits, holdout, verifier."""
import io
import json
import subprocess
import sys
import tarfile
import uuid
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _tar(path, entries):
    with tarfile.open(path, 'w:gz') as tf:
        for name, kind, data in entries:
            ti = tarfile.TarInfo(name)
            if kind == 'sym':
                ti.type = tarfile.SYMTYPE; ti.linkname = data; tf.addfile(ti)
            else:
                ti.size = len(data); tf.addfile(ti, io.BytesIO(data))


def test_stage_rejects_unsafe_members_and_keeps_safe(tmp_path):
    from fieldwork.acquisition import stage_archive
    a = tmp_path / 'a.tgz'
    _tar(a, [('ok/x.jpg', 'f', b'abc'), ('../up.jpg', 'f', b'1'), ('/abs.jpg', 'f', b'1'), ('C:/d.jpg', 'f', b'1'),
             ('l.jpg', 'sym', '/etc/passwd'), ('ok/x.jpg', 'f', b'dup'), ('con.jpg', 'f', b'1')])
    inv = stage_archive(a, tmp_path / 'out')
    d = {(m['ordinal']): (m['disposition'], m['reason']) for m in inv['members']}
    assert d[1] == ('staged', 'STAGED')
    assert d[2] == ('rejected', 'PATH_TRAVERSAL')
    assert d[3] == ('rejected', 'ABSOLUTE_PATH')
    assert d[4] == ('rejected', 'BACKSLASH_OR_DRIVE_PATH')
    assert d[5] == ('rejected', 'SYMLINK_MEMBER')
    assert d[6] == ('rejected', 'DUPLICATE_PATH')
    assert d[7] == ('rejected', 'RESERVED_PATH_COMPONENT')
    assert sorted(p.name for p in (tmp_path / 'out').rglob('*') if p.is_file()) == ['x.jpg']
    assert not (tmp_path / 'up.jpg').exists()


def test_zip_symlink_and_traversal_rejected(tmp_path):
    from fieldwork.acquisition import stage_archive
    z = tmp_path / 'a.zip'
    with zipfile.ZipFile(z, 'w') as zf:
        zf.writestr('../../e.jpg', b'1')
        info = zipfile.ZipInfo('s.jpg'); info.external_attr = 0o120777 << 16
        zf.writestr(info, '/etc/passwd')
        zf.writestr('fine.jpg', b'2')
    inv = stage_archive(z, tmp_path / 'o')
    assert [m['reason'] for m in inv['members']] == ['PATH_TRAVERSAL', 'SYMLINK_MEMBER', 'STAGED']


def test_expansion_prescan_rejects_before_any_write(tmp_path, monkeypatch):
    from fieldwork import acquisition
    monkeypatch.setattr(acquisition, 'MAX_EXPANDED', 10)
    a = tmp_path / 'b.tgz'
    _tar(a, [('a.jpg', 'f', b'x' * 8), ('b.jpg', 'f', b'y' * 8)])
    with pytest.raises(acquisition.ArchiveRejected) as e:
        acquisition.stage_archive(a, tmp_path / 'o')
    assert e.value.code == 'EXPANSION_LIMIT' and len(e.value.members) == 2
    assert not (tmp_path / 'o').exists()


def test_license_parser_literal_and_profile_rows():
    from fieldwork.acquisition import parse_license
    raw = ('All images ... License, available at:\nhttps://creativecommons.org/licenses/by/2.0/\nThe photographers...\n\n'
           'daisy/123_ab_n.jpg CC-BY by A  B - https://www.flickr.com/photos/x/123/\n'
           'roses/9_ab.jpg CC-BY https://www.flickr.com/photos/someone/ - by Some One\n'
           'tulips/5_x.jpg CC-BY by Q - https://www.flickr.com/photos/x/6/\n').encode()
    p = parse_license(raw)
    assert [r['source_kind'] for r in p['records']] == ['photo_page', 'profile_or_other', 'profile_or_other']
    assert p['records'][0]['author'] == 'A  B' and not p['unparsed']


def test_groups_link_transitively_and_quarantine_label_conflicts():
    from fieldwork.splits import assign_splits, build_groups, integrity
    samples = {f's{i}': i % 2 for i in range(10)}
    edges = [('s0', 's2', 'phash', 3), ('s2', 's4', 'phash', 5), ('s1', 's3', 'phash', 1), ('s5', 's6', 'phash', 2)]
    claims = [('s8', 1, 'x/s8-copy', 'RAW_DUPLICATE_IN_BATCH')]
    groups, q = build_groups(samples, claims, edges)
    assert {tuple(g['members']) for g in q} == {('s5', 's6'), ('s8',)}
    assert ('s0', 's2', 's4') in {tuple(g['members']) for g in groups}
    a = assign_splits(groups, 2, {'targets': {'train': .5, 'validation': .25, 'holdout': .25}, 'seed': 42,
                                   'tie_order': ['train', 'validation', 'holdout']})
    by = {}
    for g in groups:
        for m in g['members']:
            by.setdefault(a[g['group_id']], []).append({'sample_id': m, 'raw_sha256': m, 'pixel_sha256': m, 'group_id': g['group_id']})
    assert integrity(by, groups, a, q) == []


def test_real_freeze_blocks_holdout_migration_and_missing_rights():
    from fieldwork.dataset_versions import check_real_manifest
    samples = []
    for c in range(5):
        for i in range(60):
            samples.append({'id': f'{c}-{i}', 'label': c, 'split': 'holdout' if i < 50 else ('train' if i < 55 else 'validation'),
                            'group': f'g{c}-{i}', 'sha256': f'h{c}{i}', 'pixel_sha256': f'p{c}{i}', 'source_member': f'm{c}{i}'})
    m = {'scope': 'real-rights-cleared', 'classes': list('abcde'), 'samples': samples, 'quarantine': []}
    verified = {s['source_member']: s['sha256'] for s in samples}
    assert check_real_manifest(m, verified)[0] == []
    import copy
    m2 = copy.deepcopy(m)
    m2['samples'][0]['split'] = 'train'
    assert any(p.startswith('PROTECTED_GROUP_MIGRATED') for p in check_real_manifest(m2, verified, parent=m)[0])
    verified.pop('m00')
    assert 'RIGHTS:m00' in check_real_manifest(m, verified)[0]


def test_independent_verifier_fixtures_stdlib_only():
    p = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/verify_population_metrics.py'), '--fixtures'], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    assert json.loads(p.stdout)['all_pass']
    import ast
    tree = ast.parse((ROOT / 'tools/verify_population_metrics.py').read_text())
    mods = {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert mods <= {'hashlib', 'json', 'math', 'random', 'sys'}, mods  # random: round-5 stdlib group bootstrap


def test_verifier_agrees_with_service_on_missing_and_zero_support():
    sys.path.insert(0, str(ROOT / 'tools'))
    from verify_population_metrics import compare, compute
    from fieldwork.metrics import evaluate
    pop = [{'id': f'i{i}', 'label': i % 4 if i % 4 != 3 else 0, 'sha256': 'a' * 64, 'group': f'g{i % 5}'} for i in range(20)]
    model = 'b' * 64
    recs = []
    for i, p in enumerate(pop):
        status = 'decode_failed' if i == 3 else 'ok'
        recs.append({'id': p['id'], 'label': p['label'], 'sha256': p['sha256'], 'model': model, 'status': status,
                     'logits': [] if status != 'ok' else [float((i * 7 + j) % 5) for j in range(5)]})
    service = evaluate(pop, [dict(r) for r in recs], 5, model)
    mine = compute(pop, recs, 5, model)
    assert compare(mine, service) == []
    assert mine['recall'][4] is None and mine['null_reasons']['recall'][4] == 'no_true_support'


def test_holdout_exposure_is_atomic_steward_only_and_model_locked(isolated_store, monkeypatch):
    import re
    from fieldwork import holdout, rights_registry
    from fieldwork.rights_decision import TrustedReviewer
    s = isolated_store
    # Stewardship is now an explicit operator assignment (migration 006) bound to a trusted
    # reviewer key; account role `owner` alone grants nothing. Throwaway DB only: use the
    # authored 006 DDL for fw_holdout_stewards and an authored in-memory trust registry.
    ddl = re.search(r'CREATE TABLE fw_holdout_stewards \(.*?\n\);', (ROOT / 'migrations/006_real_data_api.sql').read_text(), re.S).group(0)
    reviewer, key, other_key = (str(uuid.uuid4()) for _ in range(3))
    monkeypatch.setattr(rights_registry, 'load_trusted_registry',
                        lambda: {(reviewer, key): TrustedReviewer('00' * 32, frozenset({'w1'}), frozenset())})
    with s.connect() as c:
        c.execute(holdout.HOLDOUT_SCHEMA)
        c.execute(ddl)
        c.execute("INSERT INTO fw_accounts VALUES('stew','s','h','w1','owner'),('res','s','h','w1','researcher'),('rogue','s','h','w1','owner')")
        c.execute("INSERT INTO fw_holdout_stewards(workspace,actor,reviewer_id,key_id,assigned_by) VALUES('w1','stew',%s,%s,'operator'),('w1','rogue',%s,%s,'operator')",
                  (reviewer, key, reviewer, other_key))
    with pytest.raises(holdout.HoldoutRefused, match='STEWARD_KEY_NOT_TRUSTED'):
        holdout.authorize(s, 'w1', 'rogue', version_id='v0', version_digest='d', population_digest='p', population_count=1,
                          model_digest='m' * 64, checkpoint_digest='c', evaluator='e', spec_sha256='x')
    plan = holdout.authorize(s, 'w1', 'stew', version_id='v', version_digest='d', population_digest='p', population_count=1,
                             model_digest='m' * 64, checkpoint_digest='c', evaluator='e', spec_sha256='x')
    with pytest.raises(holdout.HoldoutRefused, match='STEWARD_ROLE_REQUIRED'):
        holdout.consume(s, 'w1', 'res', plan, 'm' * 64)
    with pytest.raises(holdout.HoldoutRefused, match='MODEL_SWAP'):
        holdout.consume(s, 'w1', 'stew', plan, 'n' * 64)
    p = holdout.consume(s, 'w1', 'stew', plan, 'm' * 64)
    assert p['state'] == 'consumed' and p['exposures'] == 1
    with pytest.raises(holdout.HoldoutRefused, match='MODEL_SWAP'):
        holdout.consume(s, 'w1', 'stew', plan, 'n' * 64)
    holdout.invalidate_for_tuning(s, 'w1', plan, 'post-exposure tuning')
    with pytest.raises(holdout.HoldoutRefused, match='PLAN_INVALIDATED'):
        holdout.consume(s, 'w1', 'stew', plan, 'm' * 64)
