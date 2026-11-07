def test_real_database_and_committed_bytes_restore_into_isolated_database():
    from tools.restore_rehearsal import rehearse
    result=rehearse()
    assert result['restored_database_isolated'] is True
    assert result['source_checkpoints']==result['restored_checkpoints']
    assert result['verified_files']>0
    assert result['migration_idempotent'] is True
    assert result['external_volume_disaster_recovery'] is False
    assert result['live_database_reset'] is False
