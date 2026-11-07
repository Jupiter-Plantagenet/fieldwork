"""Round-5 milestone 4: dedup vs ALL tf_flowers, grouping, blind annotation sheets, seal.

prepare: perceptual-hash every accepted Commons sample and every tf_flowers image (all
         3,670 archive JPEGs, i.e. train/validation/consumed holdout/excluded); exclude a
         candidate whose phash-dct64/v1 Hamming distance to ANY tf_flowers image is <= 10
         (prespecified, more conservative than the in-dataset 6) or whose Flickr photo id
         equals a tf_flowers photo id. Groups = union of (normalised author) and
         (Commons-internal phash <= 6) components. Renders anonymised, class-shuffled 3x3
         contact sheets for two blind AI annotators (ids are random; no category, title,
         author or filename is shown). The id key is written only to the steward area.
seal:    joins both annotators' labels, keeps items where BOTH equal the Commons category
         class, builds the child dataset version (v1 inherited unchanged + new protected
         population tagged `commons-r5`), review + freeze through the product path, writes
         the sealed per-item population to the steward area and ONLY aggregates + digests
         to evidence. Also moves the consumed round-4 plan to `invalidated` (post-exposure
         tuning), keeping its retained result as history.
"""
import collections
import copy
import hashlib
import json
import random
import secrets
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, ImageOps
from round5_common import (ANNOTATION, C5, CLASS_DIRS, DS, EVIDENCE, RIGHTS5, STEWARD, STEWARD_LABEL, admin_dsn, context, request_store,
                           set_registry_env, write_json)
from fieldwork import annotations, holdout
from fieldwork.data import canonical, digest
from fieldwork.protected_population import freeze_child, population_members, population_support
from fieldwork.rights import RightsService
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.splits import PHASH, _UF, near_duplicate_edges, phash
from fieldwork.store import Store

import numpy as np

CROSS_MAX = 10
INTERNAL_MAX = 6
NEW_TAG = 'commons-r5'
OLD_TAG = 'tf_flowers-r4-consumed (plan 86385e00, historical; never re-used as unseen)'
TILE = 360
LABELS = CLASS_DIRS + ['other_unsure']


def commons_samples(op, ws, dataset):
    with op.connect() as c:
        b = c.execute("SELECT batch_id FROM fw_intake_batches WHERE workspace=%s AND rights_dataset_id=%s AND state='complete' ORDER BY started_utc LIMIT 1",
                      (ws, dataset)).fetchone()['batch_id']
        return b, c.execute('SELECT * FROM fw_samples WHERE workspace=%s AND first_batch=%s ORDER BY sample_id', (ws, b)).fetchall()


def tf_images():
    root = DS / 'extracted'
    return sorted(p for p in root.rglob('*.jpg'))


def prepare():
    ctx = context()
    ws = ctx['workspace_id']
    op = Store(dsn=admin_dsn())
    batch, rows = commons_samples(op, ws, ctx['rights_dataset_commons'])
    rights = {a['member_id']: a for a in json.loads((RIGHTS5 / 'rights-manifest.json').read_text(encoding='utf-8'))['assets']}
    tf = tf_images()
    tf_flickr = {p.name.split('_', 1)[0] for p in tf}
    tf_hash = np.array([phash(p) for p in tf], dtype=np.uint64)
    cand = []
    for r in rows:
        a = rights[r['source_member']]
        h = phash(r['media_path'])
        dmin = int(np.bitwise_count(tf_hash ^ np.uint64(h)).min())
        reasons = []
        if dmin <= CROSS_MAX:
            reasons.append('NEAR_DUPLICATE_OF_TF_FLOWERS_IMAGE')
        if set(a['flickr_ids']) & tf_flickr:
            reasons.append('SAME_FLICKR_PHOTO_AS_TF_FLOWERS')
        cand.append({'sample_id': str(r['sample_id']), 'member': r['source_member'], 'media': r['media_path'], 'sha256': r['raw_sha256'],
                     'pixel_sha256': r['pixel_sha256'], 'category_class': a['category_class'], 'author_group': a['author_group'],
                     'phash': h, 'min_hamming_to_tf_flowers': dmin, 'exclusion_reasons': reasons})
    kept = [x for x in cand if not x['exclusion_reasons']]
    ids = [x['sample_id'] for x in kept]
    edges = near_duplicate_edges(ids, [x['phash'] for x in kept], INTERNAL_MAX)
    uf = _UF(ids)
    by_author = collections.defaultdict(list)
    for x in kept:
        by_author[x['author_group']].append(x['sample_id'])
    for members in by_author.values():
        for m in members[1:]:
            uf.union(members[0], m)
    for a, b, _ in edges:
        uf.union(a, b)
    for x in kept:
        x['group'] = 'G-' + uf.find(x['sample_id'])
    rng = random.Random(secrets.randbits(64))   # sheet order is not reproducible on purpose (blinding); the key is sealed
    order = kept[:]
    rng.shuffle(order)
    sheets_dir = ANNOTATION / 'sheets'
    sheets_dir.mkdir(parents=True, exist_ok=False)
    key, sheets = {}, []
    try:
        font = ImageFont.truetype('arial.ttf', 40)
    except OSError:
        font = ImageFont.load_default()
    for s in range(0, len(order), 9):
        sid = f'S{s // 9 + 1:03d}'
        canvas = Image.new('RGB', (3 * TILE + 40, 3 * TILE + 40), (255, 255, 255))
        d = ImageDraw.Draw(canvas)
        tiles = {}
        for i, x in enumerate(order[s:s + 9]):
            tid = 'T' + secrets.token_hex(4)
            with Image.open(x['media']) as im:
                im = ImageOps.exif_transpose(im).convert('RGB')
                im.thumbnail((TILE - 10, TILE - 10), Image.Resampling.LANCZOS)
            ox, oy = 10 + (i % 3) * (TILE + 10), 10 + (i // 3) * (TILE + 10)
            canvas.paste(im, (ox + (TILE - im.width) // 2, oy + (TILE - im.height) // 2))
            d.rectangle((ox, oy, ox + 52, oy + 50), fill=(0, 0, 0))
            d.text((ox + 12, oy + 3), str(i + 1), fill=(255, 255, 0), font=font)
            tiles[str(i + 1)] = tid
            key[tid] = x['sample_id']
        canvas.save(sheets_dir / f'{sid}.png')
        sheets.append({'sheet': sid, 'tiles': tiles})
    STEWARD.mkdir(parents=True, exist_ok=True)
    write_json(STEWARD / 'candidates-r5.json', {'intake_batch': str(batch), 'candidates': cand, 'edges': edges})
    write_json(STEWARD / 'annotation-key.json', {'tile_to_sample': key, 'sheets': sheets})
    write_json(ANNOTATION / 'sheet-index.json', {'sheets': [{'sheet': s['sheet'], 'tiles': len(s['tiles'])} for s in sheets]})
    groups = collections.defaultdict(set)
    for x in kept:
        groups[x['category_class']].add(x['group'])
    agg = {'phash': PHASH, 'cross_dataset_max_hamming_excluded': CROSS_MAX, 'internal_near_dup_max_hamming': INTERNAL_MAX,
           'tf_flowers_images_hashed': len(tf), 'tf_flowers_flickr_ids': len(tf_flickr), 'commons_accepted_samples': len(cand),
           'excluded': dict(collections.Counter(r for x in cand for r in x['exclusion_reasons'])),
           'min_hamming_histogram_0_to_16': {str(k): sum(1 for x in cand if x['min_hamming_to_tf_flowers'] == k) for k in range(17)},
           'kept_for_annotation': len(kept), 'kept_by_category_class': dict(collections.Counter(x['category_class'] for x in kept)),
           'groups_by_category_class': {k: len(v) for k, v in groups.items()}, 'internal_near_dup_edges': len(edges),
           'sheets': len(sheets), 'tiles_per_sheet': 9}
    write_json(EVIDENCE / 'holdout/r5-dedup-and-annotation-prep.json', agg)
    print(json.dumps(agg, indent=1))


def read_labels(path, sheets):
    out = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        for pos, lab in r['labels'].items():
            lab = lab.strip().lower()
            if lab not in LABELS:
                lab = 'other_unsure'
            out[sheets[r['sheet']][str(pos)]] = lab
    return out


def seal():
    ctx = context()
    ws = ctx['workspace_id']
    set_registry_env()
    op = Store(dsn=admin_dsn())
    req = request_store(ws)
    service = RightsService(req, load_trusted_registry)
    keydoc = json.loads((STEWARD / 'annotation-key.json').read_text())
    sheets = {s['sheet']: s['tiles'] for s in keydoc['sheets']}
    labels = {}
    for who in ('A', 'B'):
        lab = read_labels(ANNOTATION / f'labels-{who}.jsonl', sheets)
        labels[who] = {keydoc['tile_to_sample'][t]: v for t, v in lab.items()}
    cdoc = json.loads((STEWARD / 'candidates-r5.json').read_text())
    kept = [x for x in cdoc['candidates'] if not x['exclusion_reasons']]
    rows, stats = [], collections.Counter()
    pair = collections.Counter()
    for x in kept:
        a, b = labels['A'].get(x['sample_id']), labels['B'].get(x['sample_id'])
        cat = x['category_class']
        if a is None or b is None:
            stats['missing_label'] += 1
            x['annotation'] = {'A': a, 'B': b, 'decision': 'excluded:missing_label'}
            continue
        pair[(a, b)] += 1
        both = a == b == cat
        x['annotation'] = {'A': a, 'B': b, 'category': cat, 'decision': 'kept' if both else 'excluded:' + (
            'annotators_disagree' if a != b else ('both_other_unsure' if a == 'other_unsure' else 'both_agree_other_class'))}
        stats[x['annotation']['decision']] += 1
        if both:
            rows.append(x)
    n = sum(pair.values())
    agree = sum(v for (a, b), v in pair.items() if a == b)
    # Cohen's kappa over the 6-way label space.
    pa = collections.Counter(a for (a, b), v in pair.items() for _ in range(v))
    pb = collections.Counter(b for (a, b), v in pair.items() for _ in range(v))
    pe = sum(pa[k] * pb[k] for k in LABELS) / (n * n) if n else 0
    kappa = (agree / n - pe) / (1 - pe) if n and pe < 1 else None
    per_class = {}
    for cls in CLASS_DIRS:
        xs = [x for x in kept if x['category_class'] == cls and 'category' in x.get('annotation', {})]
        per_class[cls] = {'annotated': len(xs), 'A_equals_category': sum(x['annotation']['A'] == cls for x in xs),
                          'B_equals_category': sum(x['annotation']['B'] == cls for x in xs),
                          'A_equals_B': sum(x['annotation']['A'] == x['annotation']['B'] for x in xs),
                          'kept_both_equal_category': sum(x['annotation']['decision'] == 'kept' for x in xs)}
    # Child version: v1 inherited unchanged + new tagged protected population.
    with op.connect() as c:
        v1 = c.execute("SELECT id,manifest FROM fw_versions WHERE workspace=%s AND state='frozen' AND manifest->>'scope'='real-rights-cleared' AND manifest->>'version_id'=%s",
                       (ws, '01a0f1aa-90cd-4875-9060-8c8f0204520b')).fetchone()
    parent = v1['manifest']
    m = {k: copy.deepcopy(v) for k, v in parent.items() if k not in ('version_id', 'review_digest', 'parent_digest', 'support', 'rights_decision_digests_sha256', 'digest')}
    m['dataset'] = 'tf_flowers + commons-r5 protected holdout'
    m['parent_version_id'] = v1['id']
    m['parent_version_digest'] = parent['digest']
    m['rights_dataset_ids'] = [ctx['rights_dataset_eligible'], ctx['rights_dataset_commons']]
    m['rights'] = parent['rights'] + ' Protected holdout commons-r5: per-file Wikimedia Commons CC0 / PD / CC BY (no BY-SA), signed AI-steward local_private_training decisions.'
    for s in m['samples']:
        s['rights_dataset_id'] = ctx['rights_dataset_eligible']
        if s['split'] == 'holdout':
            s['holdout_population'] = OLD_TAG
    label_idx = {c: i for i, c in enumerate(CLASS_DIRS)}
    for x in sorted(rows, key=lambda x: x['sample_id']):
        m['samples'].append({'id': x['sample_id'], 'label': label_idx[x['category_class']], 'split': 'holdout', 'group': x['group'],
                             'file': x['media'], 'sha256': x['sha256'], 'pixel_sha256': x['pixel_sha256'], 'source_member': x['member'],
                             'rights_dataset_id': ctx['rights_dataset_commons'], 'holdout_population': NEW_TAG})
    m['samples'].sort(key=lambda s: s['id'])
    m['protected_populations'] = {OLD_TAG: {'state': 'consumed (round 4), historical'},
                                  NEW_TAG: {'source': 'Wikimedia Commons', 'labels': 'two blind AI annotators (simulated, not human) both equal Commons category',
                                            'groups': 'normalised author U Commons-internal phash<=6', 'dedup': f'excluded phash<={CROSS_MAX} vs all 3,670 tf_flowers images; same Flickr id; intake raw/pixel identity'}}
    m['digest'] = digest(canonical(m))
    v = annotations.create(op, ws, ctx['actors']['steward'], m)
    r = annotations.review_version(op, ws, v['id'], ctx['actors']['reviewer'], v['revision'], v['digest'],
                                   'AI-simulated reviewer: child version inherits v1 unchanged; new protected population from blind double annotation; ' + STEWARD_LABEL)
    frozen = freeze_child(op, ws, v['id'], r['revision'], rights_service=service, actor=ctx['actors']['steward'], parent_manifest=parent, new_tag=NEW_TAG)
    with op.connect() as c:
        fm = c.execute('SELECT manifest FROM fw_versions WHERE workspace=%s AND id=%s', (ws, v['id'])).fetchone()['manifest']
    members, pdig = population_members(fm, NEW_TAG)
    sealed = STEWARD / 'sealed'
    sealed.mkdir(parents=True, exist_ok=True)
    (sealed / 'population-r5.json').write_bytes(canonical({'classes': 5, 'population_digest': pdig, 'members': members}))
    (sealed / 'annotation-r5.json').write_bytes(canonical([{k: x[k] for k in ('sample_id', 'member', 'category_class', 'group', 'annotation')}
                                                            for x in kept if 'annotation' in x]))
    (sealed / 'version-v2.json').write_bytes(canonical(fm))
    seal_files = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(sealed.iterdir())}
    seal_digest = hashlib.sha256(canonical({'version_digest': fm['digest'], 'population_digest': pdig, 'files': seal_files})).hexdigest()
    # Post-exposure tuning is about to start: the consumed round-4 plan can no longer stand as unseen.
    holdout.invalidate_for_tuning(op, ws, '86385e00-5722-414a-b7ff-5ea8354543b7',
                                  'round-5 recipe tuning after exposure; superseded by new disjoint protected population ' + NEW_TAG)
    with op.connect() as c:
        old_plan = c.execute('SELECT plan_id,state,exposures,invalidated_reason,result_sha256 FROM fw_holdout_plans WHERE plan_id=%s',
                             ('86385e00-5722-414a-b7ff-5ea8354543b7',)).fetchone()
    view = annotations.get(op, ws, v['id'])
    leaks = [s for s in view['manifest']['samples'] if s['split'] == 'holdout' or 'file' in s]
    summary = {'version_id': v['id'], 'version_digest': fm['digest'], 'parent_version_id': v1['id'], 'parent_version_digest': parent['digest'],
               'freeze_state': frozen['state'], 'population_tag': NEW_TAG, 'population_digest': pdig, 'population_count': len(members),
               'population_support': population_support(fm, NEW_TAG), 'seal_files_sha256': seal_files, 'seal_digest': seal_digest,
               'rights_decision_commitments': fm['rights_decision_commitments'],
               'annotation': {'annotated_items': n, 'raw_agreement': agree / n if n else None, 'cohen_kappa_6way': kappa,
                              'decisions': dict(stats), 'per_class': per_class,
                              'annotators': 'two blind AI annotator subagent roles (A, B); simulated, NOT human annotators'},
               'old_plan_after_invalidation': {k: str(v) for k, v in old_plan.items()},
               'version_view': {'samples_shown': len(view['manifest']['samples']), 'holdout_or_file_leaks': len(leaks)}}
    write_json(EVIDENCE / 'holdout/r5-seal.json', summary)
    (EVIDENCE / 'holdout/r5-seal-digest.txt').write_text(seal_digest + '\n')
    print(json.dumps({k: summary[k] for k in ('version_id', 'version_digest', 'population_count', 'population_digest', 'seal_digest', 'freeze_state')}, indent=1))
    print(json.dumps({'annotation': summary['annotation'], 'support': summary['population_support']}, indent=1))


if __name__ == '__main__':
    {'prepare': prepare, 'seal': seal}[sys.argv[1]]()
