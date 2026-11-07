"""Round-5 dataset-lane tests: small-residual/v1 recipe + codec, Commons licence policy,
child-version protected population checks, independent group bootstrap, release bundle scope."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

from fieldwork import residual_recipe as rr  # noqa: E402
from fieldwork.data import canonical, digest  # noqa: E402
from fieldwork.metrics import evaluate  # noqa: E402
from fieldwork.protected_population import (check_child, overlaps_exposed_population,
                                            population_members, researcher_view)  # noqa: E402


def _view(n_train=10, n_val=5):
    rng = np.random.default_rng(0)
    rows, arrays = [], {'train': [], 'validation': []}
    for split, n in (('train', n_train), ('validation', n_val)):
        for i in range(n):
            sid = f'{split[0]}{i:03d}'
            rows.append({'id': sid, 'label': i % 5, 'split': split, 'group': 'G-' + sid, 'sha256': '0' * 64})
    rows.sort(key=lambda s: s['id'])
    for split in ('train', 'validation'):
        for s in sorted((r for r in rows if r['split'] == split), key=lambda r: r['id']):
            arrays[split].append(rng.integers(0, 255, (144, 160, 3), dtype=np.uint8))
    return {'digest': 'a' * 64, 'version_id': 'v', 'samples': rows}, (arrays['train'], arrays['validation'])


CFG = {'epochs': 2, 'batch_size': 4, 'peak_lr': 0.002, 'weight_decay': 0.05, 'schedule': 'cosine', 'warmup_epochs': 1,
       'augmentation': 'rrc-jitter-v1', 'dropout': 0.2, 'threads': 1}


def test_recipe_is_allowlisted_and_within_parameter_budget():
    net = rr.build()
    assert sum(p.numel() for p in net.parameters()) <= rr.PARAM_BUDGET
    with pytest.raises(ValueError):
        rr.default_config(augmentation='arbitrary-python')
    with pytest.raises(ValueError):
        rr.default_config(batch_size=64)
    for invalid in ({'threads':3},{'seed':True},{'dropout':float('nan')},{'dropout':1.0},{'python':'payload'}):
        with pytest.raises(ValueError):rr.default_config(**invalid)


def test_epoch_boundary_resume_equals_uninterrupted_run(tmp_path):
    view, pre = _view()
    full = rr.train(view, tmp_path / 'full', CFG, log=lambda _: None, preloaded=pre)
    part = rr.train(view, tmp_path / 'part', CFG, log=lambda _: None, preloaded=pre, stop_after_epoch=1)
    ck = tmp_path / 'part' / 'epoch-1'
    resumed = rr.train(view, tmp_path / 'part', CFG, log=lambda _: None, preloaded=pre,
                       resume=(ck, part['history'][0]['checkpoint_digest']))
    assert resumed['final_digest'] == full['final_digest']
    assert [h['validation_loss'] for h in resumed['history']] == [h['validation_loss'] for h in full['history']]
    assert resumed['updates'] == full['updates'] == 2 * 3


def test_codec_rejects_tampering_and_extra_tensors(tmp_path):
    view, pre = _view()
    r = rr.train(view, tmp_path / 'run', dict(CFG, epochs=1), log=lambda _: None, preloaded=pre)
    ck = Path(r['selected']['path'])
    rr.validate_checkpoint(ck, r['selected']['checkpoint_digest'])
    bad = tmp_path / 'bad'
    shutil.copytree(ck, bad)
    data = bytearray((bad / 'state.safetensors').read_bytes())
    data[-5] ^= 0xFF
    (bad / 'state.safetensors').write_bytes(bytes(data))
    with pytest.raises(ValueError):
        rr.validate_checkpoint(bad)
    net = rr.build()
    exp = rr.expected_checkpoint_tensors(net)
    from safetensors.torch import save_file
    t = {k: torch.zeros(v[1], dtype={'F32': torch.float32, 'U8': torch.uint8, 'I64': torch.int64}[v[0]]) for k, v in exp.items()}
    t['evil.extra'] = torch.zeros(1)
    save_file(t, str(tmp_path / 'x.safetensors'))
    with pytest.raises(ValueError, match='keys'):
        rr.tensor_header(tmp_path / 'x.safetensors', exp)
    (bad/'manifest.json').write_bytes(b'{"schema":1,"schema":1}')
    with pytest.raises(ValueError,match='duplicate JSON key'):
        rr.validate_checkpoint(bad)
    shutil.copyfile(ck/'manifest.json',bad/'manifest.json')
    shutil.copyfile(ck/'state.safetensors',bad/'state.safetensors')
    metadata=json.loads((bad/'state.json').read_bytes())
    first=metadata['param_names'][0]
    metadata['slots'][first]['exp_avg']={'tensor':'rng.torch'}
    (bad/'state.json').write_bytes(canonical(metadata))
    manifest=json.loads((bad/'manifest.json').read_bytes())
    manifest['files']['state.json']={'bytes':(bad/'state.json').stat().st_size,'sha256':digest((bad/'state.json').read_bytes())}
    (bad/'manifest.json').write_bytes(canonical(manifest))
    with pytest.raises(ValueError,match='optimizer tensor identity'):
        rr.validate_checkpoint(bad)


def test_commons_licence_policy():
    from commons_source import classify_licence

    def meta(lic, url='', artist='Jane', short='', restrictions=''):
        return {'License': {'value': lic}, 'LicenseUrl': {'value': url}, 'Artist': {'value': artist}, 'LicenseShortName': {'value': short},
                'Restrictions': {'value': restrictions}}
    assert classify_licence(meta('cc-by-4.0', 'https://creativecommons.org/licenses/by/4.0'))['exclusion_reasons'] == []
    assert classify_licence(meta('cc-by-3.0-de', 'https://creativecommons.org/licenses/by/3.0/de/deed.en'))['exclusion_reasons'] == []
    assert 'LICENSE_CONFLICT_BY_SA' in classify_licence(meta('cc-by-sa-4.0', 'https://creativecommons.org/licenses/by-sa/4.0'))['exclusion_reasons']
    assert classify_licence(meta('cc0'))['exclusion_reasons'] == []
    assert classify_licence(meta('pd'))['exclusion_reasons'] == []
    assert 'AUTHOR_MISSING' in classify_licence(meta('cc-by-2.0', 'https://creativecommons.org/licenses/by/2.0', artist=''))['exclusion_reasons']
    assert 'RESTRICTIONS_PRESENT' in classify_licence(meta('cc0', restrictions='personality'))['exclusion_reasons']
    assert any(x.startswith('LICENSE_NOT_ACCEPTED') for x in classify_licence(meta('gfdl'))['exclusion_reasons'])
    assert any(x.startswith('LICENSE_NOT_ACCEPTED') for x in classify_licence(meta(''))['exclusion_reasons'])


def _manifest():
    samples = []
    for c in range(5):
        for i in range(3):
            for split in ('train', 'validation', 'holdout'):
                sid = f'{split}-{c}-{i}'
                samples.append({'id': sid, 'label': c, 'split': split, 'group': 'G-' + sid, 'sha256': digest(sid.encode()),
                                'pixel_sha256': digest(b'p' + sid.encode()), 'source_member': sid})
    m = {'scope': 'real-rights-cleared', 'classes': ['a', 'b', 'c', 'd', 'e'], 'samples': samples, 'quarantine': []}
    return m


def test_child_version_rules_and_researcher_view():
    parent = _manifest()
    child = json.loads(json.dumps(parent))
    for s in child['samples']:
        if s['split'] == 'holdout':
            s['holdout_population'] = 'old'
    for c in range(5):
        for i in range(50):
            sid = f'new-{c}-{i}'
            child['samples'].append({'id': sid, 'label': c, 'split': 'holdout', 'group': f'NG-{c}-{i % 25}', 'sha256': digest(sid.encode()),
                                     'pixel_sha256': digest(b'p' + sid.encode()), 'source_member': sid, 'holdout_population': 'new'})
    verified = {s['source_member']: s['sha256'] for s in child['samples']}
    problems, _, psup = check_child(child, verified, parent, 'new')
    assert problems == [] and all(v == {'samples': 50, 'groups': 25} for v in psup.values())
    members, pd = population_members(child, 'new')
    assert len(members) == 250 and all(m['id'].startswith('new-') for m in members)
    assert all(s['split'] in ('train', 'validation') for s in researcher_view(child)['samples'])
    bad = json.loads(json.dumps(child))
    bad['samples'].append({**bad['samples'][-1], 'id': 'sneak', 'split': 'train', 'holdout_population': None, 'group': 'GS', 'sha256': digest(b's'),
                           'pixel_sha256': digest(b'ps'), 'source_member': 'sneak'})
    verified['sneak'] = digest(b's')
    assert any(p.startswith('NEW_MEMBER_OUTSIDE') for p in check_child(bad, verified, parent, 'new')[0])
    reseal = json.loads(json.dumps(child))
    next(s for s in reseal['samples'] if s.get('holdout_population') == 'old')['holdout_population'] = 'new'
    assert any(p.startswith('PARENT_MEMBER_RESEALED') for p in check_child(reseal, verified, parent, 'new')[0])
    small = json.loads(json.dumps(child))
    small['samples'] = [s for s in small['samples'] if not (s.get('holdout_population') == 'new' and s['label'] == 2 and int(s['id'].split('-')[2]) >= 10)]
    assert any(p.startswith('NEW_POPULATION_SUPPORT') for p in check_child(small, verified, parent, 'new')[0])


@pytest.mark.parametrize('field,value', [
    ('id', 'rekeyed-case'), ('label', 4), ('group', 'regrouped-case'),
    ('sha256', 'c' * 64), ('pixel_sha256', 'd' * 64),
])
def test_exposed_content_guard_survives_mutable_population_keys(field, value):
    prior = {'samples': [{'id': 'case-1', 'label': 1, 'group': 'group-1',
        'split': 'holdout', 'holdout_population': 'old', 'sha256': 'a' * 64,
        'pixel_sha256': 'b' * 64, 'source_member': 'archive/photo.jpg',
        'rights_dataset_id': 'rights-1'}], 'rights_dataset_id': 'rights-1'}
    candidate = json.loads(json.dumps(prior))
    candidate['samples'][0]['holdout_population'] = 'new'
    candidate['samples'][0][field] = value
    _, old_digest = population_members(prior, 'old')
    exposures = [{'population_digest': old_digest, 'manifest': prior, 'state': 'frozen'}]

    assert overlaps_exposed_population(candidate, 'new', exposures) is True


def test_exposed_content_guard_fails_closed_without_historical_frozen_manifest():
    candidate = {'samples': [{'id': 'case', 'label': 1, 'group': 'g', 'split': 'holdout',
        'holdout_population': 'new', 'sha256': 'a' * 64, 'pixel_sha256': 'b' * 64}]}
    with pytest.raises(ValueError, match='PROTECTED_HISTORY_SNAPSHOT_UNAVAILABLE'):
        overlaps_exposed_population(candidate, 'new', [{'population_digest': 'c' * 64,
            'manifest': None, 'state': None}])


def test_independent_bootstrap_matches_service():
    rng = np.random.default_rng(3)
    pop = [{'id': f'x{i}', 'label': i % 5, 'sha256': '0' * 64, 'group': f'g{i // 3}'} for i in range(60)]
    model = 'm' * 64
    recs = [{'id': p['id'], 'label': p['label'], 'sha256': p['sha256'], 'model': model, 'status': 'ok', 'logits': rng.normal(size=5).tolist()} for p in pop]
    svc = evaluate(pop, [dict(r) for r in recs], 5, model)
    from verify_population_metrics import group_bootstrap
    gb = group_bootstrap(pop, recs, 5)
    assert abs(gb['lower'] - svc['group_accuracy_interval']['lower']) <= 1e-12
    assert abs(gb['upper'] - svc['group_accuracy_interval']['upper']) <= 1e-12
    assert gb['group_support'] == svc['group_support']
