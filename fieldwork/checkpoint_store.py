"""Controller-owned logical immutable checkpoints, anchored by database digest.
Not a substitute for separate OS filesystem identities / power-loss certification.
"""
import os,shutil,uuid
from pathlib import Path
from .data import digest


def promote(source,root):
    from .ml import validate_checkpoint
    source=Path(source);root=Path(root);root.mkdir(parents=True,exist_ok=True)
    validate_checkpoint(source);expected=digest((source/'manifest.json').read_bytes());target=root/expected
    if target.exists():
        # Review F2: a reused digest directory may be an old orphan. Refresh its mtime so
        # the 24 h GC grace restarts; publish() also re-validates it after its INSERT.
        validate_checkpoint(target,expected);os.utime(target,None);return target,expected
    stage=root/('.staging-'+uuid.uuid4().hex);stage.mkdir()
    try:
        for name in ['state.safetensors','state.json','manifest.json']:
            data=(source/name).read_bytes()
            with (stage/name).open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        validate_checkpoint(stage,expected)
        from .fsops import durable_rename
        try:durable_rename(stage,target)
        except FileExistsError:validate_checkpoint(target,expected);os.utime(target,None)
        validate_checkpoint(target,expected)
        for file in target.iterdir():file.chmod(0o444)
        return target,expected
    finally:
        if stage.exists():shutil.rmtree(stage)
