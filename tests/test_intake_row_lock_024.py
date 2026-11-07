"""Migration 024: the intake worker can row-lock fw_samples for its duplicate lookup, and nothing more."""
import psycopg
import pytest
from pathlib import Path

from tests.chain_support import chain  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
LOOKUP = 'SELECT sample_id,raw_bytes,pixel_sha256,source_member,rights_dataset_id FROM fw_samples WHERE false FOR UPDATE'


def _as_intake_worker(c):
    c.execute('SET ROLE fieldwork_intake_worker')


def test_intake_duplicate_lookup_needs_024_and_gains_no_write(chain):
    with chain.dba.connect() as c:  # pre-024 chain: the exact intake query is refused
        _as_intake_worker(c)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(LOOKUP)
    with chain.dba.connect() as c:
        c.execute((ROOT / 'migrations/024_intake_sample_row_lock_capability.sql').read_text(encoding='utf-8'))
    with chain.dba.connect() as c:
        _as_intake_worker(c)
        c.execute(LOOKUP)  # now permitted
        c.execute('RESET ROLE')
        flags = c.execute("""SELECT has_table_privilege('fieldwork_intake_worker','public.fw_samples','UPDATE') t,
            has_column_privilege('fieldwork_intake_worker','public.fw_samples','raw_sha256','UPDATE') l,
            has_column_privilege('fieldwork_intake_worker','public.fw_samples','row_lock_capability','UPDATE') r""").fetchone()
    assert flags['t'] is False and flags['l'] is False and flags['r'] is True
    with chain.dba.connect() as c:  # the column is guarded by the 015 rejection function
        trig = c.execute("""SELECT p.proname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid='public.fw_samples'::regclass AND t.tgname='fw024_reject_row_lock_capability'""").fetchone()
    assert trig and trig['proname'] == 'fw015_reject_row_lock_capability_mutation'
