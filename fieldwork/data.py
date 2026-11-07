"""Author-generated RGB fixtures. NOT flower data or usefulness evidence."""
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageDraw


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def generate(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    if (root / 'manifest.json').exists():
        m = json.loads((root / 'manifest.json').read_text())
        verify(root, m)
        return m
    samples = []
    colors = ['#c44343', '#c9a832', '#44854e', '#417cbd', '#9767ac']
    for label, color in enumerate(colors):
        for i in range(9):
            sid = f'SYN-{label}-{i}'
            image = Image.new('RGB', (144, 144), '#edf0e7')
            draw = ImageDraw.Draw(image)
            draw.rectangle((12+i, 16+i, 110+i, 114+i), fill=color)
            draw.ellipse((30+i*2, 40, 55+i*2, 65+i), fill='#ffffff')
            draw.line((i+4, 130, 130, 125-i), fill=color, width=3)
            file = sid + '.png'
            image.save(root / file)
            raw = (root / file).read_bytes()
            samples.append(dict(id=sid, label=label, split='train' if i<6 else 'validation' if i<8 else 'holdout', group=sid, file=file, sha256=digest(raw), pixel_sha256=digest(image.tobytes())))
    m = dict(schema=1, scope='synthetic-execution-only', rights='Author-generated geometric RGB fixtures; local execution proof only. No flower usefulness or holdout acceptance.', classes=['Crimson', 'Ochre', 'Leaf', 'Azure', 'Violet'], samples=samples)
    m['digest'] = digest(canonical(m))
    with (root / 'manifest.json').open('xb') as out:
        out.write(canonical(m))
    return m


def verify(root, m):
    # This legacy decoder/training path is ONLY for trusted authored fixtures.
    # A scope label or signed intake result never enables real-image execution.
    if m.get('scope') != 'synthetic-execution-only':
        raise ValueError('REAL_DATA_RIGHTS_REQUIRED')
    body = {k:v for k,v in m.items() if k != 'digest'}
    if digest(canonical(body)) != m['digest']:
        raise ValueError('manifest digest')
    for row in m['samples']:
        if digest((Path(root) / row['file']).read_bytes()) != row['sha256']:
            raise ValueError('sample digest')
    if len({s['group'] for s in m['samples']}) != len(m['samples']):
        raise ValueError('group overlap')
    return m['digest']
