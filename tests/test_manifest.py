def test_fixture_freeze_is_content_addressed_and_disjoint(tmp_path):
    from fieldwork.data import generate, verify
    m = generate(tmp_path)
    assert m['scope'] == 'synthetic-execution-only'
    assert len(m['samples']) == 45
    assert len({s['sha256'] for s in m['samples']}) == 45
    assert verify(tmp_path, m) == m['digest']
    p = tmp_path / m['samples'][0]['file']
    p.write_bytes(b'corrupt')
    import pytest
    with pytest.raises(ValueError, match='digest'):
        verify(tmp_path, m)
