"""ML-T-INTAKE hostile-input acceptance matrix, executed on current source.

The REAL ``intake.run_intake`` + ``acquisition.stage_archive`` run against a
throwaway PostgreSQL database (isolated_store fixture on the verify cluster) with
the production decoder: the pinned, no-network Docker image
(fieldwork-decoder:r6-phash-20261102-01, ContainerDecoder). Hostile members are real
bytes: corrupt/truncated images, non-image payloads renamed .png, GIF/APNG, a
30000x30000 PNG decompression bomb, 21 MiB members, zip/tar traversal, absolute and
drive paths, symlink/hardlink/fifo members, duplicate paths, zip/tar expansion
bombs, and pixel-identical re-encodings.

Test-environment note: ``fw_intake_cap_v1.publish_sample_phash`` is a SECURITY
DEFINER function that only the production intake-worker role may call under a live
queue lease (covered by migration/worker tests). In this throwaway database it is
replaced by a recording stub so run_intake can be driven end to end by the real
container decoder. Nothing else is stubbed.
"""
import hashlib
import io
import json
import os
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from tests.hostile_fixtures import (
    DECODER_IMAGE_ID, PIXEL_IMAGE_ID, apng_bytes, gif_bytes, jpeg_resave_of, pattern_jpeg, pattern_png,
    pattern_png_reencoded, pattern_png_rgba_opaque, pattern_webp_lossless, pickle_payload,
    png_decompression_bomb, smooth_png, tar_bytes, tar_gz_bomb, zip_bomb_bytes, zip_bytes)

WS = 'ws-hostile'
ACTOR = 'operator-hostile'
MIB = 1024 * 1024


@pytest.fixture
def store(isolated_store):
    from fieldwork.intake import INTAKE_SCHEMA
    with isolated_store.connect() as c:
        c.execute(INTAKE_SCHEMA)
        c.execute('''CREATE SCHEMA IF NOT EXISTS fw_intake_cap_v1;
            CREATE TABLE public.stub_phash(sample_id uuid, raw_sha256 text, pixel_sha256 text, hash_hex text);
            CREATE FUNCTION fw_intake_cap_v1.publish_sample_phash(w text, s uuid, r text, p text, h text, d text)
              RETURNS void LANGUAGE sql AS $$ INSERT INTO public.stub_phash VALUES (s, r, p, h) $$;''')
    return isolated_store


@pytest.fixture(scope='module')
def docker_decoder_ready():
    import subprocess
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE')}
    out = subprocess.run(['docker', '--context', 'default', 'image', 'inspect', '--format', '{{.Id}}', DECODER_IMAGE_ID],
                         capture_output=True, text=True, timeout=30, env=env)
    assert out.stdout.strip() == DECODER_IMAGE_ID, 'pinned intake decoder image missing'


class Env:
    def __init__(self, store, tmp):
        self.store, self.tmp = store, Path(tmp)
        self.quarantine = self.tmp / 'quarantine'; self.media = self.tmp / 'media'
        self.private = self.tmp / 'private'; self.private.mkdir(exist_ok=True)
        self.n = 0

    def archive(self, data: bytes, suffix='.zip'):
        self.n += 1
        path = self.tmp / f'archive-{self.n}{suffix}'
        path.write_bytes(data)
        return path

    def run(self, archive, **kw):
        from fieldwork.container_decoder import ContainerDecoder
        from fieldwork.intake import run_intake
        return run_intake(self.store, WS, ACTOR, archive, quarantine_root=self.quarantine, media_root=self.media,
                          decoder_factory=lambda: ContainerDecoder(DECODER_IMAGE_ID, private_dir=self.private), **kw)

    def samples(self):
        with self.store.connect() as c:
            c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (WS,))
            return c.execute('SELECT sample_id::text,raw_sha256,pixel_sha256,media_path FROM fw_samples ORDER BY sample_id').fetchall()

    def batch(self, batch_id):
        with self.store.connect() as c:
            c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (WS,))
            b = c.execute('SELECT * FROM fw_intake_batches WHERE batch_id=%s', (batch_id,)).fetchone()
            m = c.execute('SELECT * FROM fw_intake_members WHERE batch_id=%s ORDER BY ordinal', (batch_id,)).fetchall()
            return b, m

    def phash_rows(self):
        with self.store.connect() as c:
            return c.execute('SELECT sample_id::text FROM public.stub_phash').fetchall()


@pytest.fixture
def env(store, tmp_path, docker_decoder_ready):
    return Env(store, tmp_path)


def assert_reconciled(env, report, *, expect_total):
    """The frozen reconciliation law, the persisted batch row and the persisted per-member rows."""
    assert report['source_total'] == expect_total
    assert report['source_total'] == report['accepted'] + report['rejected'] + report['duplicate'] + report['noop']
    assert report['reconciles'] is True
    assert len(report['members']) == expect_total or report['archive_level_rejection']
    for member in report['members']:
        assert member['disposition'] in ('accepted', 'rejected', 'duplicate', 'noop')
        assert isinstance(member['reason'], str) and member['reason'], member      # every omission has a reason
        assert (member['disposition'] == 'accepted') == ('sample_id' in member)
        if member['disposition'] == 'duplicate':
            assert member.get('linked_sample_id')
    batch, rows = env.batch(report['batch_id'])
    assert batch['state'] in ('complete', 'rejected')
    assert (batch['source_total'], batch['accepted'], batch['rejected'], batch['duplicate'], batch['noop']) == (
        report['source_total'], report['accepted'], report['rejected'], report['duplicate'], report['noop'])
    assert len(rows) == report['source_total']
    assert all(r['reason'] for r in rows)
    assert not (env.quarantine / report['batch_id']).exists()          # quarantine disposed


def reasons(report):
    return {m['member']: (m['disposition'], m['reason']) for m in report['members']}


# =========================================================================== A. mixed hostile ZIP
def _mixed_zip_members():
    a = pattern_png(1)
    valid_png = a
    members = [
        ('flowers/daisy/good1.png', valid_png, 'file'),                                       # 1  accepted
        ('flowers/daisy/good2.png', pattern_png(2), 'file'),                                  # 2  accepted
        ('flowers/rose/good3.jpg', pattern_jpeg(3), 'file'),                                  # 3  accepted
        ('flowers/rose/good4.webp', pattern_webp_lossless(4), 'file'),                        # 4  accepted
        ('flowers/daisy/good1-copy.png', valid_png, 'file'),                                  # 5  raw duplicate
        ('flowers/daisy/good1-reencoded.png', pattern_png_reencoded(1), 'file'),              # 6  same pixels, other PNG bytes
        ('flowers/daisy/good1-lossless.webp', pattern_webp_lossless(1), 'file'),              # 7  same pixels, WEBP
        ('flowers/daisy/good1-rgba.png', pattern_png_rgba_opaque(1), 'file'),                 # 8  same pixels, RGBA opaque
        ('flowers/rose/corrupt.png', b'\x89PNG\r\n\x1a\n' + b'\x00\x01garbage' * 40, 'file'),  # 9  corrupt
        ('flowers/rose/truncated.png', pattern_png(5, (200, 200))[:400], 'file'),             # 10 truncated
        ('flowers/x/notimage.png', pickle_payload('/tmp/never'), 'file'),                     # 11 pickle renamed .png
        ('flowers/x/gif.png', gif_bytes(), 'file'),                                           # 12 unsupported format
        ('flowers/x/page.png', b'<html><script>alert(1)</script></html>', 'file'),            # 13 html renamed .png
        ('flowers/x/notes.txt', b'hello', 'file'),                                            # 14 not an image member
        ('flowers/x/big.png', b'\0' * (21 * MIB), 'file'),                                    # 15 oversized member
        ('flowers/x/bomb.png', png_decompression_bomb(), 'file'),                             # 16 900 MP decompression bomb
        ('../escape.png', pattern_png(6), 'file'),                                            # 17 traversal
        ('/abs/escape.png', pattern_png(7), 'file'),                                          # 18 absolute
        ('C:/win/escape.png', pattern_png(8), 'file'),                                        # 19 drive path
        ('flowers/x/link.png', '/etc/passwd', 'sym'),                                         # 20 symlink member
        ('con.png', pattern_png(9), 'file'),                                                  # 21 reserved name
        ('flowers/daisy/good1.png', pattern_png(10), 'file'),                                 # 22 duplicate path
        ('flowers/x/animated.png', apng_bytes(), 'file'),                                     # 23 multi-frame
        ('flowers/x/zipped.png', zip_bytes([('a.png', pattern_png(11), 'file')]), 'file'),    # 24 zip renamed .png
        ('flowers/', None, 'dir'),                                                            # 25 directory
    ]
    return members


EXPECTED_MIXED = {
    'flowers/daisy/good1.png': ('accepted', 'ACCEPTED'),
    'flowers/daisy/good2.png': ('accepted', 'ACCEPTED'),
    'flowers/rose/good3.jpg': ('accepted', 'ACCEPTED'),
    'flowers/rose/good4.webp': ('accepted', 'ACCEPTED'),
    'flowers/daisy/good1-copy.png': ('duplicate', 'RAW_DUPLICATE_IN_BATCH'),
    'flowers/daisy/good1-reencoded.png': ('duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING'),
    'flowers/daisy/good1-lossless.webp': ('duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING'),
    'flowers/daisy/good1-rgba.png': ('duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING'),
    'flowers/rose/corrupt.png': ('rejected', 'DECODE_FAILED:OSError'),
    'flowers/rose/truncated.png': ('rejected', 'DECODE_FAILED:OSError'),
    'flowers/x/notimage.png': ('rejected', 'DECODE_FAILED:UnidentifiedImageError'),
    'flowers/x/gif.png': ('rejected', 'UNSUPPORTED_FORMAT:GIF'),
    'flowers/x/page.png': ('rejected', 'DECODE_FAILED:UnidentifiedImageError'),
    'flowers/x/notes.txt': ('rejected', 'NOT_AN_IMAGE_MEMBER'),
    'flowers/x/big.png': ('rejected', 'MEMBER_TOO_LARGE'),
    'flowers/x/bomb.png': ('rejected', 'PIXEL_LIMIT'),
    '../escape.png': ('rejected', 'PATH_TRAVERSAL'),
    '/abs/escape.png': ('rejected', 'ABSOLUTE_PATH'),
    'C:/win/escape.png': ('rejected', 'BACKSLASH_OR_DRIVE_PATH'),
    'flowers/x/link.png': ('rejected', 'SYMLINK_MEMBER'),
    'con.png': ('rejected', 'RESERVED_PATH_COMPONENT'),
    'flowers/x/animated.png': ('rejected', 'MULTIFRAME'),
    'flowers/x/zipped.png': ('rejected', 'DECODE_FAILED:UnidentifiedImageError'),
    'flowers/': ('noop', 'DIRECTORY_ENTRY_NOT_A_SAMPLE'),
}


def test_mixed_hostile_zip_exact_outcome_counts_and_reason_codes(env):
    report = env.run(env.archive(zip_bytes(_mixed_zip_members())))
    got = reasons(report)
    # the duplicate-path member keeps its own row; same name as good1, so compare by ordinal below
    assert [m['disposition'] for m in report['members']].count('rejected') == 16
    for name, expected in EXPECTED_MIXED.items():
        assert got[name] == expected or name == 'flowers/daisy/good1.png', (name, got[name])
    by_ordinal = {m['ordinal']: m for m in report['members']}
    assert (by_ordinal[1]['disposition'], by_ordinal[1]['reason']) == ('accepted', 'ACCEPTED')
    assert (by_ordinal[22]['disposition'], by_ordinal[22]['reason']) == ('rejected', 'DUPLICATE_PATH')
    assert (report['accepted'], report['rejected'], report['duplicate'], report['noop']) == (4, 16, 4, 1)
    assert_reconciled(env, report, expect_total=25)
    assert report['reason_counts']['accepted:ACCEPTED'] == 4
    assert report['reason_counts']['rejected:DECODE_FAILED'] == 5
    assert report['reason_counts']['duplicate:PIXEL_IDENTICAL_DIFFERENT_ENCODING'] == 3
    assert report['reason_counts']['duplicate:RAW_DUPLICATE_IN_BATCH'] == 1
    # accepted samples: distinct raw and pixel identities, stub phash published exactly for accepted ids
    samples = env.samples()
    accepted_ids = sorted(m['sample_id'] for m in report['members'] if m['disposition'] == 'accepted')
    assert sorted(s['sample_id'] for s in samples) == accepted_ids and len(accepted_ids) == 4
    assert len({s['raw_sha256'] for s in samples}) == 4 and len({s['pixel_sha256'] for s in samples}) == 4
    assert sorted(r['sample_id'] for r in env.phash_rows()) == accepted_ids


def test_hostile_bytes_are_never_promoted_to_media_or_catalogue(env):
    """Raw malicious bytes can never be served: they have no catalogue row and no promoted media file."""
    members = _mixed_zip_members()
    report = env.run(env.archive(zip_bytes(members)))
    hostile = {name: data for name, data, kind in members if kind == 'file' and EXPECTED_MIXED.get(name, ('', ''))[0] == 'rejected'}
    hostile_digests = {hashlib.sha256(d).hexdigest() for d in hostile.values()}
    promoted = {p.stem for p in env.media.rglob('*') if p.is_file()}
    catalogue = {s['raw_sha256'] for s in env.samples()}
    assert promoted == catalogue                               # only decoded, accepted images are promoted
    assert promoted.isdisjoint(hostile_digests) and catalogue.isdisjoint(hostile_digests)
    assert len(promoted) == 4
    for path in env.media.rglob('*'):
        if path.is_file():
            assert path.suffix in {'.png', '.jpg', '.webp'}
            assert hashlib.sha256(path.read_bytes()).hexdigest() == path.stem
            from PIL import Image
            with Image.open(path) as im:                       # promoted bytes are genuine images
                assert im.format in {'PNG', 'JPEG', 'WEBP'}
    # nothing escaped the quarantine/media roots
    assert not (env.tmp / 'escape.png').exists() and not (env.tmp.parent / 'escape.png').exists()
    assert report['accepted'] == 4


# =========================================================================== B. mixed hostile TAR
def test_tar_symlink_hardlink_fifo_backslash_traversal_members(env):
    good = pattern_png(21)
    tar = tar_bytes([
        ('imgs/ok.png', good, 'file'),                      # 1 accepted
        ('imgs/sym.png', '../../../etc/passwd', 'sym'),     # 2 symlink
        ('imgs/hard.png', 'imgs/ok.png', 'hard'),           # 3 hardlink
        ('imgs/pipe.png', None, 'fifo'),                    # 4 special
        ('imgs\\back.png', good, 'file'),                   # 5 backslash
        ('imgs/../../up.png', good, 'file'),                # 6 traversal (embedded)
        ('./imgs/./ok.png', pattern_png(22), 'file'),       # 7 normalises onto member 1 -> duplicate path
        ('/etc/cron.d/x.png', good, 'file'),                # 8 absolute
        ('imgs/trailing.png.', good, 'file'),               # 9 trailing dot reserved component
        ('imgs/', None, 'dir'),                             # 10 directory
    ])
    report = env.run(env.archive(tar, '.tar'))
    got = [(m['member'], m['disposition'], m['reason']) for m in report['members']]
    assert got == [
        ('imgs/ok.png', 'accepted', 'ACCEPTED'),
        ('imgs/sym.png', 'rejected', 'SYMLINK_MEMBER'),
        ('imgs/hard.png', 'rejected', 'HARDLINK_MEMBER'),
        ('imgs/pipe.png', 'rejected', 'SPECIAL_MEMBER'),
        ('imgs\\back.png', 'rejected', 'BACKSLASH_OR_DRIVE_PATH'),
        ('imgs/../../up.png', 'rejected', 'PATH_TRAVERSAL'),
        ('./imgs/./ok.png', 'rejected', 'DUPLICATE_PATH'),
        ('/etc/cron.d/x.png', 'rejected', 'ABSOLUTE_PATH'),
        ('imgs/trailing.png.', 'rejected', 'RESERVED_PATH_COMPONENT'),
        ('imgs', 'noop', 'DIRECTORY_ENTRY_NOT_A_SAMPLE'),      # tarfile strips the trailing slash of directories
    ]
    assert (report['accepted'], report['rejected'], report['duplicate'], report['noop']) == (1, 8, 0, 1)
    assert_reconciled(env, report, expect_total=10)
    assert not (env.tmp / 'up.png').exists() and not (env.tmp.parent / 'up.png').exists()


# =========================================================================== C. same archive twice
def test_second_identical_intake_creates_zero_new_sample_ids(env):
    data = zip_bytes([
        ('d/a.png', pattern_png(31), 'file'), ('d/b.jpg', pattern_jpeg(32), 'file'),
        ('d/a-reencoded.png', pattern_png_reencoded(31), 'file'),
        ('d/bad.png', b'\x89PNG\r\n\x1a\ngarbage garbage garbage', 'file'),
        ('../up.png', pattern_png(33), 'file'), ('d/', None, 'dir')])
    path = env.archive(data)
    first = env.run(path)
    assert (first['accepted'], first['rejected'], first['duplicate'], first['noop']) == (2, 2, 1, 1)
    assert_reconciled(env, first, expect_total=6)
    before = env.samples()
    ids_before = {s['sample_id'] for s in before}
    assert len(ids_before) == 2
    second = env.run(path)
    assert second['batch_id'] != first['batch_id']
    assert second['accepted'] == 0 and not any('sample_id' in m for m in second['members'])
    assert {m['member']: (m['disposition'], m['reason']) for m in second['members']} == {
        'd/a.png': ('noop', 'RAW_DIGEST_ALREADY_IMPORTED'),
        'd/b.jpg': ('noop', 'RAW_DIGEST_ALREADY_IMPORTED'),
        'd/a-reencoded.png': ('duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING'),
        'd/bad.png': ('rejected', 'DECODE_FAILED:UnidentifiedImageError'),
        '../up.png': ('rejected', 'PATH_TRAVERSAL'),
        'd/': ('noop', 'DIRECTORY_ENTRY_NOT_A_SAMPLE')}
    assert (second['accepted'], second['rejected'], second['duplicate'], second['noop']) == (0, 2, 1, 3)
    assert_reconciled(env, second, expect_total=6)
    assert {s['sample_id'] for s in env.samples()} == ids_before            # zero new sample IDs
    # links point at the ORIGINAL sample ids
    linked = {m['linked_sample_id'] for m in second['members'] if m['disposition'] in ('noop', 'duplicate') and m.get('linked_sample_id')}
    assert linked <= ids_before and len(linked) == 2
    # repacked (different archive bytes, same members, reversed order): still zero new IDs
    repack = env.archive(zip_bytes(list(reversed([
        ('d/a.png', pattern_png(31), 'file'), ('d/b.jpg', pattern_jpeg(32), 'file'),
        ('d/a-reencoded.png', pattern_png_reencoded(31), 'file')]))))
    third = env.run(repack)
    assert third['accepted'] == 0 and third['noop'] == 2 and third['duplicate'] == 1
    assert_reconciled(env, third, expect_total=3)
    assert {s['sample_id'] for s in env.samples()} == ids_before
    assert len(env.phash_rows()) == 2


def test_same_pixels_different_encoding_across_batches(env):
    first = env.run(env.archive(zip_bytes([('p/a.png', pattern_png(41), 'file')])))
    sid = first['members'][0]['sample_id']
    second = env.run(env.archive(zip_bytes([
        ('q/a.webp', pattern_webp_lossless(41), 'file'),
        ('q/a-rgba.png', pattern_png_rgba_opaque(41), 'file'),
        ('q/a-opt.png', pattern_png_reencoded(41), 'file'),
        ('q/different.png', pattern_png(42), 'file')])))
    got = {m['member']: (m['disposition'], m['reason'], m.get('linked_sample_id')) for m in second['members']}
    assert got['q/a.webp'] == ('duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING', sid)
    assert got['q/a-rgba.png'] == ('duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING', sid)
    assert got['q/a-opt.png'] == ('duplicate', 'PIXEL_IDENTICAL_DIFFERENT_ENCODING', sid)
    assert got['q/different.png'][:2] == ('accepted', 'ACCEPTED')
    assert (second['accepted'], second['duplicate']) == (1, 3)
    assert_reconciled(env, second, expect_total=4)
    assert len(env.samples()) == 2


def test_lossy_jpeg_resave_has_new_pixels_by_policy_and_is_not_an_exact_duplicate(env):
    """Policy pin: duplicates are PIXEL-EXACT (RGB8 digest). Lossy recompression changes pixels, so it is
    a new sample here; near-duplicate handling is the perceptual-grouping lane (phash-dct64/v1)."""
    png = smooth_png()
    first = env.run(env.archive(zip_bytes([('a.png', png, 'file')])))
    second = env.run(env.archive(zip_bytes([('a-resaved.jpg', jpeg_resave_of(png), 'file')])))
    assert first['accepted'] == 1 and second['accepted'] == 1 and second['duplicate'] == 0
    s = env.samples()
    assert len(s) == 2 and s[0]['pixel_sha256'] != s[1]['pixel_sha256']


# =========================================================================== D. archive-level rejection
def test_zip_expansion_bomb_rejected_at_prescan_before_any_write(env):
    bomb = zip_bomb_bytes(members=60, member_bytes=19 * MIB)           # 1.1 GiB declared, ~1000:1
    path = env.archive(bomb)
    assert path.stat().st_size < 3 * MIB and 60 * 19 * MIB > 1024 * MIB
    report = env.run(path)
    assert report['archive_level_rejection'] == 'ARCHIVE_REJECTED:EXPANSION_LIMIT'
    assert (report['source_total'], report['accepted'], report['rejected'], report['duplicate'], report['noop']) == (60, 0, 60, 0, 0)
    assert {m['reason'] for m in report['members']} == {'ARCHIVE_REJECTED:EXPANSION_LIMIT'}
    assert_reconciled(env, report, expect_total=60)
    batch, _ = env.batch(report['batch_id'])
    assert batch['state'] == 'rejected' and batch['reason'] == 'ARCHIVE_REJECTED:EXPANSION_LIMIT'
    assert env.samples() == [] and not env.media.exists()


def test_tar_gz_expansion_bomb_rejected_at_prescan(env, tmp_path):
    path = tmp_path / 'bomb.tar.gz'
    tar_gz_bomb(path, members=54, member_bytes=19 * MIB)
    assert 54 * 19 * MIB / path.stat().st_size > 200                  # >200:1 expansion ratio
    report = env.run(path)
    assert report['archive_level_rejection'] == 'ARCHIVE_REJECTED:EXPANSION_LIMIT'
    assert (report['accepted'], report['rejected'], report['duplicate'], report['noop']) == (0, 54, 0, 0)
    assert_reconciled(env, report, expect_total=54)
    assert env.samples() == [] and not env.media.exists()


def test_zip_with_members_over_the_member_cap_is_per_member_rejected_not_extracted(env):
    bomb = zip_bomb_bytes(members=8, member_bytes=25 * MIB)           # each member > 20 MiB cap
    report = env.run(env.archive(bomb))
    assert report['archive_level_rejection'] is None
    assert {m['reason'] for m in report['members']} == {'MEMBER_TOO_LARGE'}
    assert (report['accepted'], report['rejected']) == (0, 8)
    assert_reconciled(env, report, expect_total=8)
    assert not env.media.exists()


def test_zip_whose_header_lies_about_size_never_writes_more_than_declared(env, tmp_path):
    from tests.hostile_fixtures import lying_zip_bytes
    path = env.archive(lying_zip_bytes(real_bytes=25 * MIB, declared=64))
    report = env.run(path)
    assert report['archive_level_rejection'] == 'ARCHIVE_REJECTED:ARCHIVE_UNREADABLE:BadZipFile'
    assert (report['source_total'], report['accepted'], report['rejected'], report['duplicate'], report['noop']) == (1, 0, 1, 0, 0)
    assert report['members'][0]['reason'] == 'ARCHIVE_REJECTED:ARCHIVE_UNREADABLE:BadZipFile'
    assert_reconciled(env, report, expect_total=1)
    assert env.samples() == [] and not env.media.exists()


def test_unreadable_and_empty_archives_are_rejected_with_batch_level_reason(env):
    truncated = zip_bytes([('a.png', pattern_png(51), 'file')])[:60]
    cases = {
        'truncated_zip': (truncated, 'ARCHIVE_REJECTED:ARCHIVE_UNREADABLE:BadZipFile'),
        'random_bytes': (os.urandom(4096), 'ARCHIVE_REJECTED:ARCHIVE_UNREADABLE:ReadError'),
        'pickle_as_archive': (pickle_payload('/tmp/never'), 'ARCHIVE_REJECTED:ARCHIVE_UNREADABLE:ReadError'),
    }
    for name, (data, reason) in cases.items():
        report = env.run(env.archive(data))
        assert report['archive_level_rejection'] == reason, name
        assert (report['source_total'], report['accepted'], report['rejected'], report['duplicate'], report['noop']) == (0, 0, 0, 0, 0)
        assert env.batch(report['batch_id'])[0]['state'] == 'rejected'
    assert env.samples() == []


def test_archive_too_large_rejected_before_reading_members(tmp_path):
    from fieldwork.acquisition import ArchiveRejected, MAX_ARCHIVE, stage_archive
    path = tmp_path / 'huge.zip'
    with path.open('wb') as f:
        f.truncate(MAX_ARCHIVE + 1)
    with pytest.raises(ArchiveRejected) as caught:
        stage_archive(path, tmp_path / 'stage')
    assert caught.value.code == 'ARCHIVE_TOO_LARGE'
    assert not (tmp_path / 'stage').exists()


def test_too_many_members_rejected_at_prescan(tmp_path):
    from fieldwork.acquisition import ArchiveRejected, MAX_MEMBERS, stage_archive
    path = tmp_path / 'many.zip'
    with zipfile.ZipFile(path, 'w') as zf:
        for i in range(MAX_MEMBERS + 1):
            zf.writestr(f'm{i}.png', b'')
    with pytest.raises(ArchiveRejected) as caught:
        stage_archive(path, tmp_path / 'stage')
    assert caught.value.code == 'TOO_MANY_MEMBERS' and len(caught.value.members) == MAX_MEMBERS + 1
    assert not (tmp_path / 'stage').exists()


def test_stage_destination_must_be_empty_and_unsafe_members_never_touch_disk(tmp_path):
    from fieldwork.acquisition import ArchiveRejected, stage_archive
    path = tmp_path / 'a.tar'
    path.write_bytes(tar_bytes([('x/../../outside.png', b'1', 'file'), ('ok.png', b'2', 'file')]))
    stage = tmp_path / 'stage'
    stage.mkdir(); (stage / 'preexisting').write_text('x')
    with pytest.raises(ArchiveRejected) as caught:
        stage_archive(path, stage)
    assert caught.value.code == 'DESTINATION_NOT_EMPTY'
    fresh = tmp_path / 'fresh'
    inventory = stage_archive(path, fresh)
    assert [(m['reason']) for m in inventory['members']] == ['PATH_TRAVERSAL', 'STAGED']
    assert not (tmp_path / 'outside.png').exists() and not (fresh.parent / 'outside.png').exists()
    assert sorted(p.name for p in fresh.rglob('*') if p.is_file()) == ['ok.png']


# =========================================================================== E. oversized input
def test_oversized_member_rejected_by_host_decoder_gate_without_starting_container(tmp_path, docker_decoder_ready):
    from fieldwork.container_decoder import ContainerDecoder, MAX_FILE
    path = tmp_path / 'big.png'
    path.write_bytes(b'\x89PNG\r\n\x1a\n' + b'\0' * (MAX_FILE + 10))
    decoder = ContainerDecoder(DECODER_IMAGE_ID, private_dir=tmp_path)
    result = decoder.decode(path)
    assert result['ok'] is False and result['reason'] == 'FILE_TOO_LARGE'
    assert not list(Path(tmp_path).glob('.decoder-sessions/*/.decoder-*.cid'))     # no container was ever started


def test_oversized_upload_rejected_with_413_and_partial_removed(tmp_path):
    import asyncio
    from fastapi import HTTPException
    from starlette.requests import Request
    from fieldwork.real_api import MAX_ARCHIVE_BYTES, _stage_upload
    chunk = b'\0' * MIB
    sent = {'n': 0}

    async def receive():
        if sent['n'] > MAX_ARCHIVE_BYTES // MIB + 2:
            return {'type': 'http.request', 'body': b'', 'more_body': False}
        sent['n'] += 1
        return {'type': 'http.request', 'body': chunk, 'more_body': True}
    request = Request({'type': 'http', 'method': 'POST', 'headers': [], 'query_string': b'', 'path': '/x'}, receive)
    upload_root = tmp_path / 'uploads'
    with pytest.raises(HTTPException) as caught:
        asyncio.run(_stage_upload(request, upload_root))
    assert caught.value.status_code == 413 and caught.value.detail == 'ARCHIVE_TOO_LARGE'
    assert list(upload_root.iterdir()) == []                      # no partial or final file survives

    async def empty():
        return {'type': 'http.request', 'body': b'', 'more_body': False}
    with pytest.raises(HTTPException) as caught:
        asyncio.run(_stage_upload(Request({'type': 'http', 'method': 'POST', 'headers': [], 'query_string': b'', 'path': '/x'}, empty), upload_root))
    assert caught.value.status_code == 422 and caught.value.detail == 'EMPTY_ARCHIVE'


# =========================================================================== F. rights and omissions
def test_rights_denial_is_a_reasoned_rejection_and_creates_no_sample(env):
    denied = {'d/deny.png'}

    def rights(member, raw_sha, size):
        return 'NO_SIGNED_DECISION' if member in denied else None
    report = env.run(env.archive(zip_bytes([('d/ok.png', pattern_png(61), 'file'), ('d/deny.png', pattern_png(62), 'file')])),
                     rights_check=rights, rights_dataset_id='dataset-1')
    assert reasons(report) == {'d/ok.png': ('accepted', 'ACCEPTED'), 'd/deny.png': ('rejected', 'RIGHTS:NO_SIGNED_DECISION')}
    assert_reconciled(env, report, expect_total=2)
    assert len(env.samples()) == 1


# =========================================================================== G. container-level decoders (hostile images)
def _pixel_decoder(tmp_path):
    from fieldwork.real_pixel_decoder import ContainerRealPixelDecoder
    return ContainerRealPixelDecoder(PIXEL_IMAGE_ID, private_dir=tmp_path)


def test_pixel_decoder_container_rejects_hostile_images_and_unifies_encodings(tmp_path, docker_decoder_ready):
    from fieldwork.container_decoder import DecoderUnavailable
    decoder = _pixel_decoder(tmp_path)
    size = (200, 160)
    ok, payload = decoder.decode_bytes(pattern_png(71, size))
    assert ok['ok'] is True and min(ok['width'], ok['height']) == 144 and len(payload) == ok['width'] * ok['height'] * 3
    for name, data, code in (
            ('corrupt', b'\x89PNG\r\n\x1a\n' + b'\x00\x01garbage' * 40, 'DECODE_FAILED'),
            ('pickle', pickle_payload('/tmp/never'), 'DECODE_FAILED'),
            ('html', b'<html><script>1</script>', 'DECODE_FAILED'),
            ('gif', gif_bytes(), 'FORMAT_OR_PIXEL_LIMIT'),
            ('apng', apng_bytes(), 'MULTIFRAME'),
            ('pixel_bomb', png_decompression_bomb(), 'PIXEL_LIMIT')):
        with pytest.raises(DecoderUnavailable) as caught:
            decoder.decode_bytes(data)
        assert caught.value.code == code, name
    # same pixels, different encodings -> same canonical identity and same numeric output
    results = [decoder.decode_bytes(b) for b in (pattern_png(72, size), pattern_png_reencoded(72, size),
                                                 pattern_webp_lossless(72, size), pattern_png_rgba_opaque(72, size))]
    assert {r[0]['canonical_pixel_sha256'] for r in results} == {results[0][0]['canonical_pixel_sha256']}
    assert {r[0]['pixel_sha256'] for r in results} == {results[0][0]['pixel_sha256']}
    assert [r[0]['format'] for r in results] == ['PNG', 'PNG', 'WEBP', 'PNG']
    assert len({r[1] for r in results}) == 1
    different = decoder.decode_bytes(pattern_png(73, size))[0]
    assert different['canonical_pixel_sha256'] != results[0][0]['canonical_pixel_sha256']
    with pytest.raises(DecoderUnavailable) as caught:
        decoder.decode_bytes(b'\0' * (20 * MIB + 1))
    assert caught.value.code == 'REAL_PIXEL_INPUT_BOUNDS'
    decoder.close()


# =========================================================================== H. real media route (ML-T-SAFE: never served inline)
def _media_client(env, decisions):
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from fieldwork.real_api import create_router
    user = {'name': ACTOR, 'workspace': WS, 'csrf': 'x'}

    class Rights:
        def require(self, workspace, dataset, actor, purpose):
            assert purpose == 'private_thumbnail_ui'
            return decisions
    app = FastAPI()
    app.include_router(create_router(store=env.store, session_dependency=lambda: user, writer_dependency=lambda: user,
                                     rights_service=Rights(), media_root=env.media, upload_root=env.tmp / 'uploads'))
    return TestClient(app), SimpleNamespace


def test_media_route_never_serves_hostile_bytes_inline(env):
    """Through the REAL router and DB: only decoded images are served, as image/* + nosniff;
    swapped or mistyped bytes are refused; hostile intake members have no route target at all."""
    from types import SimpleNamespace
    good = pattern_png(81)
    hostile_html = b'<html><script>alert(document.cookie)</script></html>'
    report = env.run(env.archive(zip_bytes([('m/ok.png', good, 'file'), ('m/evil.png', hostile_html, 'file'),
                                           ('m/pickle.png', pickle_payload('/tmp/never'), 'file')])),
                     rights_dataset_id='ds-1', rights_check=lambda m, s, n: None)
    assert (report['accepted'], report['rejected']) == (1, 2)
    sample = env.samples()[0]
    sid = sample['sample_id']
    decisions = [SimpleNamespace(member_id='m/ok.png', asset_sha256=sample['raw_sha256'])]
    client, _ = _media_client(env, decisions)
    url = f'/api/v1/workspaces/{WS}/real/samples/{sid}/media'
    with client:
        ok = client.get(url)
        assert ok.status_code == 200 and ok.content == good
        assert ok.headers['content-type'] == 'image/png' and ok.headers['x-content-type-options'] == 'nosniff'
        assert 'content-disposition' not in ok.headers or 'inline' not in ok.headers['content-disposition']
        # hostile intake members were never catalogued: no sample id exists to request
        for name, data in (('m/evil.png', hostile_html),):
            assert hashlib.sha256(data).hexdigest() not in {s['raw_sha256'] for s in env.samples()}
        import uuid
        assert client.get(f'/api/v1/workspaces/{WS}/real/samples/{uuid.uuid4()}/media').status_code == 404
        # media file replaced on disk by hostile bytes of the same length -> refused, bytes never returned
        media = Path(sample['media_path'])
        media.write_bytes((hostile_html + b' ' * len(good))[:len(good)])
        swapped = client.get(url)
        assert swapped.status_code == 409 and swapped.json()['detail'] == 'MEDIA_DIGEST_MISMATCH'
        assert b'<script>' not in swapped.content
        media.write_bytes(good)
        assert client.get(url).status_code == 200
        # corrupted catalogue row pointing at an executable/HTML type is refused (defence in depth)
        with env.store.connect() as c:
            c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (WS,))
            c.execute("UPDATE fw_samples SET format='HTML' WHERE sample_id=%s", (sid,))
        assert client.get(url).status_code == 415
        with env.store.connect() as c:
            c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (WS,))
            c.execute("UPDATE fw_samples SET format='PNG', media_path=%s WHERE sample_id=%s",
                      (str(env.tmp / 'outside.png'), sid))
        (env.tmp / 'outside.png').write_bytes(good)
        assert client.get(url).status_code == 404                       # outside the media root
        # missing/other-workspace rights decision -> 403, no bytes
        with env.store.connect() as c:
            c.execute("SELECT set_config('fieldwork.workspace',%s,true)", (WS,))
            c.execute("UPDATE fw_samples SET media_path=%s WHERE sample_id=%s", (sample['media_path'], sid))
        denied_client, _ = _media_client(env, [])
        with denied_client:
            assert denied_client.get(url).status_code == 403
