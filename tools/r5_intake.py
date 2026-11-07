"""Round-5 milestone 3: intake of the untrusted Commons archive through the real safe path.

fieldwork.intake.run_intake: bounded extraction into a new quarantine dir, isolated
decoder child, raw/pixel dedup against the WHOLE workspace catalog (all tf_flowers
samples incl. the consumed round-4 holdout), and the signed local_private_training
rights check against the Commons inventory. Same archive is then imported a second
time to show 0 new sample IDs.
"""
import collections
import json

from round5_common import C5, EVIDENCE, MEDIA5, QUARANTINE5, RIGHTS5, admin_dsn, context, request_store, set_registry_env, write_json
from fieldwork.intake import run_intake
from fieldwork.rights import RightsService
from fieldwork.rights_decision import DecisionRejected
from fieldwork.rights_registry import load_trusted_registry
from fieldwork.store import Store

LABEL = {'daisy': 0, 'dandelion': 1, 'roses': 2, 'sunflowers': 3, 'tulips': 4}


def main():
    ctx = context()
    ws = ctx['workspace_id']
    set_registry_env()
    req = request_store(ws)
    service = RightsService(req, load_trusted_registry)
    op = Store(dsn=admin_dsn())
    dataset = ctx['rights_dataset_commons']
    rights = {a['member_id']: a for a in json.loads((RIGHTS5 / 'rights-manifest.json').read_text(encoding='utf-8'))['assets']}

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
        a = rights.get(member_id)
        return LABEL[a['category_class']] if a else None

    with op.connect() as c:
        before = c.execute('SELECT count(*) n FROM fw_samples WHERE workspace=%s', (ws,)).fetchone()['n']
    common = dict(quarantine_root=QUARANTINE5, media_root=MEDIA5, rights_check=rights_check, rights_dataset_id=dataset,
                  report_dir=C5 / 'intake-reports', label_of=label_of)
    archive = C5 / 'archive/commons_r5.tar'
    first = run_intake(op, ws, ctx['actors']['steward'], archive, **common)
    with op.connect() as c:
        mid = c.execute('SELECT count(*) n FROM fw_samples WHERE workspace=%s', (ws,)).fetchone()['n']
    second = run_intake(op, ws, ctx['actors']['steward'], archive, **common)
    with op.connect() as c:
        after = c.execute('SELECT count(*) n FROM fw_samples WHERE workspace=%s', (ws,)).fetchone()['n']
        linked_to_tf = c.execute('''SELECT count(*) n FROM fw_intake_members m JOIN fw_samples s ON s.workspace=m.workspace AND s.sample_id=m.linked_sample_id
            WHERE m.workspace=%s AND m.batch_id=%s AND m.disposition='duplicate' AND s.rights_dataset_id<>%s''', (ws, first['batch_id'], dataset)).fetchone()['n']
    keep = ('batch_id', 'archive', 'archive_sha256', 'source_total', 'accepted', 'rejected', 'duplicate', 'noop', 'reconciles',
            'reason_counts', 'archive_level_rejection', 'decoder', 'decoder_restarts', 'decoder_peak_rss_bytes', 'elapsed_s', 'report_sha256')
    accepted_by_class = collections.Counter(m['claimed_label'] for m in first['members'] if m['disposition'] == 'accepted')
    summary = {'catalog_before': before, 'catalog_after_first': mid, 'catalog_after_second': after,
               'first': {k: first[k] for k in keep}, 'second': {k: second[k] for k in keep},
               'second_intake_new_sample_ids': after - mid,
               'duplicates_linked_to_tf_flowers_samples': linked_to_tf,
               'accepted_by_claimed_class': {str(k): v for k, v in sorted(accepted_by_class.items())}}
    write_json(EVIDENCE / 'intake/commons-intake-summary.json', summary)
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
