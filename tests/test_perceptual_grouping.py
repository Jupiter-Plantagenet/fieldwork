"""Authored nonsensitive hash-graph fixtures; no media, DB, or protected rows."""
from hashlib import sha256

from fieldwork.perceptual_grouping import group_new_samples
from fieldwork import perceptual_grouping


def row(sample_id, value, *, raw=None, pixel=None, source=None, label=0):
    raw = raw or (sample_id.encode().hex() * 32)[:64]
    pixel = pixel or sha256((sample_id + '-pixels').encode()).hexdigest()
    return {'id': sample_id, 'label': label, 'source_member': source or f'images/{sample_id}.jpg',
            'raw_sha256': raw, 'pixel_sha256': pixel,
            'phash': {'algorithm': 'phash-dct64/v1', 'hex': f'{value:016x}',
                      'raw_sha256': raw, 'pixel_sha256': pixel,
                      'decoder': 'fixture-pinned-decoder/v2'}}


def test_hash_threshold_six_links_and_seven_does_not():
    samples = [row('a', 0), row('b', 0x3f), row('c', 0xfc1)]
    result = group_new_samples(samples)
    pairs = {(edge['a'], edge['b'], edge['detail']) for edge in result['edges']
             if edge['kind'] == 'phash_near_duplicate'}
    assert ('a', 'b', '6') in pairs
    assert ('a', 'c', '7') not in pairs
    assert result['membership']['a']['group'] == result['membership']['b']['group']
    assert result['membership']['a']['group'] != result['membership']['c']['group']


def test_candidate_edges_form_transitive_components_and_link_source_photo():
    samples = [row('a', 0), row('b', 0x3f), row('c', 0xfff),
               row('d', 0xffffffffffffffff, source='flower/998877_variant-a.jpg'),
               row('e', 0x123456789abcdef0, source='flower/998877_variant-b.jpg')]
    result = group_new_samples(samples)
    assert result['membership']['a']['group'] == result['membership']['b']['group']
    assert result['membership']['b']['group'] == result['membership']['c']['group']
    assert result['membership']['d']['group'] == result['membership']['e']['group']
    assert any(edge['kind'] == 'same_source_photo_id' and edge['detail'] == '998877'
               for edge in result['edges'])
    assert result['audit_complete'] is True


def test_exact_raw_and_pixel_duplicate_edges_are_union_inputs():
    samples = [row('a', 0, raw='a' * 64), row('b', 0xffffffffffffffff, raw='a' * 64),
               row('c', 0x0f0f0f0f0f0f0f0f, pixel='b' * 64),
               row('d', 0xf0f0f0f0f0f0f0f0, pixel='b' * 64)]
    result = group_new_samples(samples)
    assert result['membership']['a']['group'] == result['membership']['b']['group']
    assert result['membership']['c']['group'] == result['membership']['d']['group']
    assert {edge['kind'] for edge in result['edges']} >= {'raw_equal', 'pixel_equal'}


def test_label_conflict_quarantines_the_full_transitive_component():
    samples = [row('a', 0, label=0), row('b', 0x3f, label=1), row('c', 0xfff, label=1)]
    result = group_new_samples(samples)
    assert result['membership']['a']['group'] == result['membership']['c']['group']
    assert all(result['membership'][sid]['quarantined'] for sid in ('a', 'b', 'c'))
    assert result['quarantine'][0]['reason'] == 'LABEL_CONFLICT'
    assert result['quarantine'][0]['members'] == ['a', 'b', 'c']


def test_duplicate_source_claim_is_applied_to_its_server_linked_sample():
    samples = [row('a', 0, label=0), row('b', 0xffffffffffffffff, label=0)]
    result = group_new_samples(samples, [{'sample_id': 'a', 'label': 1,
                                        'source_member': 'flower/duplicate.jpg'}])
    assert result['membership']['a']['quarantined'] is True
    assert result['membership']['b']['quarantined'] is False


def test_missing_feature_never_claims_complete_audit():
    sample = row('a', 0)
    sample.pop('phash')
    result = group_new_samples([sample], require_complete=False)
    assert result['audit_complete'] is False
    assert result['missing_feature_samples'] == ['a']


def test_dense_candidate_graph_fails_closed_at_edge_bound(monkeypatch):
    monkeypatch.setattr(perceptual_grouping, 'MAX_CANDIDATE_EDGES', 2)
    try:
        group_new_samples([row('a', 0), row('b', 0), row('c', 0)])
    except perceptual_grouping.GroupingUnavailable as exc:
        assert str(exc) == 'GROUP_AUDIT_EDGE_LIMIT'
    else:
        raise AssertionError('dense graph must not produce a partial audit')
