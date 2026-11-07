"""Keep the shared physical slot held until real Docker cleanup is proven.

A dead Docker CLI is not evidence that its daemon container stopped. The real
runner removes its private launch receipt only after positive owned cleanup.
Generic workers must defer reconciliation while any such receipt remains.
"""
from pathlib import Path


def model_cleanup_pending(root=None):
    base=Path(root) if root is not None else Path(__file__).resolve().parents[1]
    registry=base/'.local/real-data/model-private/.model-container-receipts'
    try:
        registry.stat()
        if registry.is_symlink() or not registry.is_dir():return True
        return any(registry.glob('.model-*.cleanup.json'))
    except FileNotFoundError:
        return False
    except OSError:
        return True
