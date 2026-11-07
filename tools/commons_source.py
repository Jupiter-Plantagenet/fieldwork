"""Round-5 milestone 1: source a NEW protected-holdout candidate population from Wikimedia Commons.

Usage: python -B tools/commons_source.py crawl|download

crawl:    category crawl (fixed seed list below, written before any download), Commons API
          imageinfo + extmetadata per file, licence classification, per-class author-capped
          deterministic selection. Writes candidates/candidates.json (steward side).
download: fetch the 500px Commons thumbnail of each selected file into a NEW directory on
          D: (untrusted bytes; bounded size, content-type and magic checks; never executed),
          record SHA-256 per asset, and build the intake archive commons_r5.tar.

Licence policy (prespecified): accept CC0, public domain (`pd`) and CC BY (any version,
incl. ported jurisdictions). Exclude CC BY-SA (as round 4), any other licence, missing
licence/author, NonFree, any non-empty Restrictions field, ambiguous multi-class files
and non-JPEG/PNG originals. Groups (for the protected population) = normalised author,
plus near-duplicate clusters computed later (tools/r5_population.py).
"""
import hashlib
import html
import io
import json
import random
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser

from round5_common import CANDIDATES, CLASS_DIRS, DOWNLOADS, EVIDENCE, USER_AGENT, C5, write_json

API = 'https://commons.wikimedia.org/w/api.php'
THUMB_WIDTH = 500
PER_CLASS_TARGET = 150
AUTHOR_CAP = 4
SEED = 20261031
MAX_BYTES = 20 * 1024 * 1024
EXCLUDE_SUBCAT = re.compile(r'(?i)\b(art|illustration|drawing|painting|sculpture|stamp|herbarium|microscop|pollen|seedling|leaves|leaf|root|'
                            r'bark|text|map|audio|video|wideo|diagram|book|journal|named after|symbol|logo|food|harvest|festival|maze|'
                            r'disease|disorder|documents|information board|award|people|animals|seed|historical|textures|prickles|low quality|'
                            r'black and white|extracted|dried|petals|cultivation|floristry|in art)\b')
# Fixed before any download: (category, depth). depth 1 = also files of direct subcategories not matching EXCLUDE_SUBCAT.
# (v2 seed list: the first attempt's per-country crawl was abandoned because of API rate limits before any download;
#  its cached responses are not used for selection.)
SEEDS = {
    'daisy': [('Bellis perennis', 0), ('Bellis perennis (flowers)', 0), ('Bellis perennis (habitat)', 0), ('Quality images of Bellis perennis', 0),
              ('Leucanthemum vulgare', 0), ('Leucanthemum vulgare (flowers)', 0), ('Leucanthemum vulgare (habitat)', 0),
              ('Quality images of Leucanthemum vulgare', 0)],
    'dandelion': [('Taraxacum officinale', 0), ('Taraxacum officinale (flowers)', 0), ('Taraxacum officinale (fruit)', 0),
                  ('Taraxacum officinale (habitat)', 0), ('Dandelions', 0), ('Blown dandelions', 0), ('Dandelions in the Netherlands', 0),
                  ('Taraxacum', 0)],
    'roses': [('Rosa (flowers)', 0), ('Roses by color', 1), ('Close-ups of pink roses', 0), ('Quality images of Rosa', 0), ('Rose gardens', 0),
              ('Rosebushes', 0), ('Rose bunches', 0), ('Bokeh photographs of roses', 0), ('Water droplets on roses', 0),
              ('Unidentified Rosa', 0), ('Miniature roses', 0), ('Rose buds', 0)],
    'sunflowers': [('Sunflowers', 0), ('Helianthus annuus', 0), ('Helianthus annuus (flowers)', 0), ('Close-up photographs of sunflowers', 0),
                   ('Close-up photographs of Helianthus flowers', 0), ('Sunflower fields', 0), ('Sunflowers at sunset', 0)],
    'tulips': [('Tulips', 0), ('Tulipa gesneriana', 0), ('Tulips by color', 1), ('Tulip fields', 0), ('Tulip gardens', 0),
               ('Tulips with double flowers', 0), ('Water drops on tulips', 0), ('Tulipa', 0), ('Bokeh photographs of tulips', 0)],
}
FILE_CAP_PER_CATEGORY = 250
META_FIELDS = 'License|LicenseShortName|LicenseUrl|Artist|Credit|UsageTerms|AttributionRequired|Copyrighted|Restrictions|NonFree|DateTimeOriginal'
CC_BY = re.compile(r'^cc-by-(\d(\.\d)?)(-[a-z]{2,3})?$')
FLICKR = re.compile(r'flickr\.com/photos/[^/"\s]+/(\d{6,})')


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, d):
        self.parts.append(d)


def html_text(s):
    p = _Text()
    p.feed(s or '')
    return re.sub(r'\s+', ' ', html.unescape(''.join(p.parts))).strip()


_last = [0.0]


def api(params):
    params = dict(params, format='json', formatversion='2', maxlag='5')
    url = API + '?' + urllib.parse.urlencode(params)
    cache = CANDIDATES / 'api-cache' / (hashlib.sha256(url.encode()).hexdigest() + '.json')
    if cache.exists():
        return json.loads(cache.read_text(encoding='utf-8'))
    for attempt in range(10):
        wait = 1.0 - (time.monotonic() - _last[0])
        if wait > 0:
            time.sleep(wait)
        _last[0] = time.monotonic()
        try:
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
            d = json.loads(body.decode('utf-8'))
            if 'error' in d:
                if d['error'].get('code') == 'maxlag':
                    print('maxlag', flush=True); time.sleep(5 * (attempt + 1)); continue
                raise RuntimeError(d['error'].get('code'))
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(body)
            return d
        except urllib.error.HTTPError as exc:
            ra = exc.headers.get('Retry-After') if exc.headers else None
            print('http', exc.code, 'retry-after', ra, 'attempt', attempt, flush=True)
            if attempt == 9:
                raise
            time.sleep(min(300, max(int(ra) if ra and ra.isdigit() else 0, 20 * (attempt + 1))))
        except (OSError, ValueError) as exc:
            print('neterr', type(exc).__name__, flush=True)
            if attempt == 9:
                raise
            time.sleep(3 * (attempt + 1))


def members(category, kind):
    out, cont = [], {}
    while True:
        d = api({'action': 'query', 'list': 'categorymembers', 'cmtitle': 'Category:' + category, 'cmtype': kind, 'cmlimit': '500', **cont})
        print('cat', kind, category, len(out), flush=True)
        out += [m['title'] for m in d['query']['categorymembers']]
        if 'continue' not in d:
            return out
        cont = {'cmcontinue': d['continue']['cmcontinue']}


def files_with_info(category):
    """generator=categorymembers + prop=imageinfo(extmetadata): listing and metadata in one request."""
    out, cont = {}, {}
    while True:
        d = api({'action': 'query', 'generator': 'categorymembers', 'gcmtitle': 'Category:' + category, 'gcmtype': 'file', 'gcmlimit': '50',
                 'prop': 'imageinfo', 'iiprop': 'url|size|mime|sha1|extmetadata|user|timestamp', 'iiurlwidth': str(THUMB_WIDTH),
                 'iiextmetadatafilter': META_FIELDS, 'iiextmetadatalanguage': 'en', **cont})
        for p in (d.get('query') or {}).get('pages', []):
            if p.get('imageinfo'):
                out[p['title']] = {'pageid': p['pageid'], **p['imageinfo'][0]}
        print('files', category, len(out), flush=True)
        if 'continue' not in d or len(out) >= FILE_CAP_PER_CATEGORY:
            return out
        cont = {k: v for k, v in d['continue'].items()}


def classify_licence(meta):
    def v(k):
        return (meta.get(k) or {}).get('value')
    lic = (v('License') or '').strip().lower()
    short = html_text(v('LicenseShortName') or '')
    url = (v('LicenseUrl') or '').strip()
    author = html_text(v('Artist') or '')
    reasons = []
    if str(v('NonFree') or '').lower() == 'true':
        reasons.append('NON_FREE')
    if html_text(v('Restrictions') or ''):
        reasons.append('RESTRICTIONS_PRESENT')
    if lic.startswith('cc-by-sa') or 'by-sa' in lic or 'BY-SA' in short.upper():
        reasons.append('LICENSE_CONFLICT_BY_SA')
        kind = 'cc-by-sa'
    elif CC_BY.match(lic):
        kind = 'cc-by'
        if not url.startswith(('https://creativecommons.org/licenses/by/', 'http://creativecommons.org/licenses/by/')):
            reasons.append('CC_BY_LICENSE_URL_UNCLEAR')
    elif lic == 'cc0':
        kind = 'cc0'
    elif lic == 'pd':
        kind = 'pd'
    else:
        kind = lic or 'missing'
        reasons.append('LICENSE_NOT_ACCEPTED:' + (lic or 'missing'))
    if kind in ('cc-by', 'cc0', 'pd') and not author:
        reasons.append('AUTHOR_MISSING')
    return {'license_id': lic, 'license_short_name': short, 'license_url': url, 'license_kind': kind, 'author': author,
            'credit_text': html_text(v('Credit') or '')[:500], 'usage_terms': html_text(v('UsageTerms') or ''),
            'attribution_required': v('AttributionRequired'), 'copyrighted': v('Copyrighted'), 'exclusion_reasons': reasons}


def norm_author(a):
    a = re.sub(r'(?i)\b(own work|photo(graph)?( by)?|by|from|wikimedia commons|commons|user:)\b', ' ', a)
    return re.sub(r'[^a-z0-9]+', ' ', a.lower()).strip()[:120] or 'unknown'


def crawl():
    started = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    found = defaultdict(set)
    info = {}
    crawl_log = []
    for cls in CLASS_DIRS:
        for cat, depth in SEEDS[cls]:
            cats = [cat]
            if depth == 1:
                subs = [s[len('Category:'):] for s in members(cat, 'subcat')]
                cats += [s for s in subs if not EXCLUDE_SUBCAT.search(s)]
                crawl_log.append({'class': cls, 'category': cat, 'subcats_total': len(subs), 'subcats_used': len(cats) - 1})
            for c in cats:
                fs = files_with_info(c)
                for t, ii in fs.items():
                    found[t].add(cls)
                    info[t] = ii
                crawl_log.append({'class': cls, 'category': c, 'files': len(fs)})
        print(cls, sum(1 for t, cs in found.items() if cls in cs), flush=True)
    titles = sorted(found)
    rows = []
    for t in titles:
        ii = info.get(t)
        r = {'title': t, 'classes_from_categories': sorted(found[t])}
        if not ii:
            r.update(exclusion_reasons=['NO_IMAGEINFO']); rows.append(r); continue
        lic = classify_licence(ii.get('extmetadata') or {})
        reasons = list(lic['exclusion_reasons'])
        if len(found[t]) != 1:
            reasons.append('MULTI_CLASS_CATEGORY')
        if ii.get('mime') not in ('image/jpeg', 'image/png'):
            reasons.append('MIME_NOT_ACCEPTED:' + str(ii.get('mime')))
        if min(ii.get('width') or 0, ii.get('height') or 0) < 200:
            reasons.append('TOO_SMALL')
        blob = json.dumps(ii.get('extmetadata') or {})
        r.update(pageid=ii['pageid'], file_page_url=ii.get('descriptionurl'), original_url=ii.get('url'), original_sha1=ii.get('sha1'),
                 original_bytes=ii.get('size'), width=ii.get('width'), height=ii.get('height'), mime=ii.get('mime'),
                 thumb_url=ii.get('thumburl'), thumb_width=ii.get('thumbwidth'), thumb_height=ii.get('thumbheight'),
                 uploader=ii.get('user'), upload_timestamp=ii.get('timestamp'), flickr_ids=sorted(set(FLICKR.findall(blob))),
                 **{k: v for k, v in lic.items() if k != 'exclusion_reasons'}, author_group=norm_author(lic['author']),
                 exclusion_reasons=reasons)
        rows.append(r)
    eligible = [r for r in rows if not r['exclusion_reasons']]
    rng = random.Random(SEED)
    selected = []
    for cls in CLASS_DIRS:
        pool = sorted((r for r in eligible if r['classes_from_categories'] == [cls]), key=lambda r: r['pageid'])
        rng.shuffle(pool)
        per_author = Counter()
        take = []
        for r in pool:
            if per_author[r['author_group']] >= AUTHOR_CAP:
                continue
            per_author[r['author_group']] += 1
            take.append(r)
            if len(take) >= PER_CLASS_TARGET:
                break
        for r in take:
            r['category_class'] = cls
        selected += take
    sel_ids = {r['pageid'] for r in selected}
    for r in rows:
        r['selected_for_download'] = r.get('pageid') in sel_ids
    doc = {'schema': 'fieldwork.commons-candidates/v1', 'api': API, 'crawl_started_utc': started,
           'crawl_finished_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'user_agent': USER_AGENT,
           'seeds': SEEDS, 'exclude_subcat_regex': EXCLUDE_SUBCAT.pattern, 'file_cap_per_category': FILE_CAP_PER_CATEGORY,
           'thumb_width': THUMB_WIDTH, 'per_class_target': PER_CLASS_TARGET, 'author_cap_per_class': AUTHOR_CAP, 'selection_seed': SEED,
           'crawl_log': crawl_log, 'rows': rows}
    write_json(CANDIDATES / 'candidates.json', doc)
    stats = summarize(rows)
    write_json(EVIDENCE / 'rights/commons-crawl-stats.json', {k: v for k, v in doc.items() if k != 'rows'} | {'stats': stats})
    print(json.dumps(stats, indent=1))


def summarize(rows):
    st = {'files_seen': len(rows), 'license_kind': dict(Counter(r.get('license_kind', 'n/a') for r in rows)),
          'exclusion_reason_counts': dict(Counter(x.split(':')[0] for r in rows for x in r['exclusion_reasons'])),
          'eligible': sum(1 for r in rows if not r['exclusion_reasons']),
          'eligible_by_class': dict(Counter(r['classes_from_categories'][0] for r in rows if not r['exclusion_reasons'])),
          'selected_by_class': dict(Counter(r['category_class'] for r in rows if r.get('selected_for_download'))),
          'selected_authors_by_class': {c: len({r['author_group'] for r in rows if r.get('category_class') == c and r.get('selected_for_download')}) for c in CLASS_DIRS},
          'selected_license_kind': dict(Counter(r['license_kind'] for r in rows if r.get('selected_for_download')))}
    return st


def download():
    doc = json.loads((CANDIDATES / 'candidates.json').read_text(encoding='utf-8'))
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    sel = [r for r in doc['rows'] if r.get('selected_for_download')]
    log = []
    for n, r in enumerate(sel):
        dest = DOWNLOADS / f'{r["pageid"]}.bin'
        rec = {'pageid': r['pageid'], 'thumb_url': r['thumb_url']}
        if dest.exists():
            data = dest.read_bytes()
            rec['cached'] = True
        else:
            data = None
            for attempt in range(8):
                try:
                    time.sleep(1.0)
                    req = urllib.request.Request(r['thumb_url'], headers={'User-Agent': USER_AGENT})
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        final = resp.geturl()
                        ctype = resp.headers.get('Content-Type', '')
                        data = resp.read(MAX_BYTES + 1)
                        rec.update(http_status=resp.status, final_url=final, content_type=ctype, etag=resp.headers.get('ETag'))
                    break
                except urllib.error.HTTPError as exc:
                    ra = exc.headers.get('Retry-After') if exc.headers else None
                    rec['last_error'] = f'HTTP{exc.code}'
                    print('http', exc.code, 'retry-after', ra, r['pageid'], flush=True)
                    if exc.code not in (429, 500, 502, 503, 504):
                        break
                    time.sleep(min(300, max(int(ra) if ra and ra.isdigit() else 0, 20 * (attempt + 1))))
                except OSError as exc:
                    rec['last_error'] = type(exc).__name__
                    time.sleep(5 * (attempt + 1))
            if data is None:
                rec['outcome'] = 'DOWNLOAD_FAILED'; log.append(rec); continue
            host = urllib.parse.urlparse(rec['final_url']).hostname
            if host not in ('upload.wikimedia.org', 'thumb.wikimedia.org'):
                rec['outcome'] = 'REDIRECT_HOST_REJECTED'; log.append(rec); continue
            if len(data) > MAX_BYTES:
                rec['outcome'] = 'TOO_LARGE'; log.append(rec); continue
            if not (data[:3] == b'\xff\xd8\xff' or data[:8] == b'\x89PNG\r\n\x1a\n'):
                rec['outcome'] = 'MAGIC_REJECTED'; log.append(rec); continue
            dest.write_bytes(data)
        rec['sha256'] = hashlib.sha256(data).hexdigest()
        rec['bytes'] = len(data)
        rec['ext'] = '.jpg' if data[:3] == b'\xff\xd8\xff' else '.png'
        rec['outcome'] = 'OK'
        log.append(rec)
        if n % 25 == 0:
            print('downloaded', n, len(sel), flush=True)
    ok = {x['pageid']: x for x in log if x['outcome'] == 'OK'}
    # Intake archive: member commons_r5/<pageid><ext>; written outside the downloads dir.
    archive = C5 / 'archive' / 'commons_r5.tar'
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'w') as tf:
        for pid in sorted(ok):
            data = (DOWNLOADS / f'{pid}.bin').read_bytes()
            ti = tarfile.TarInfo(f'commons_r5/{pid}{ok[pid]["ext"]}')
            ti.size = len(data)
            ti.mtime = 0
            tf.addfile(ti, io.BytesIO(data))
    write_json(CANDIDATES / 'download-log.json', {'schema': 'fieldwork.commons-download/v1', 'records': log,
               'archive': str(archive), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()})
    agg = {'attempted': len(sel), 'outcomes': dict(Counter(x['outcome'] for x in log)),
           'ok_bytes_total': sum(x['bytes'] for x in ok.values()), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
           'archive_bytes': archive.stat().st_size}
    write_json(EVIDENCE / 'rights/commons-download-stats.json', agg)
    print(json.dumps(agg, indent=1))


if __name__ == '__main__':
    {'crawl': crawl, 'download': download}[sys.argv[1]]()
