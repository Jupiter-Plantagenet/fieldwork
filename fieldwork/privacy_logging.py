"""Private daily log handler used by the managed API launcher."""
from __future__ import annotations

import logging.handlers
import os
import uuid
from pathlib import Path


class PrivateTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """Rotate daily without deleting old bytes and enforce private file mode."""

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.namer=self._unique_rotation_name

    @staticmethod
    def _unique_rotation_name(default_name):
        path=Path(default_name)
        from .privacy_lifecycle import _check_c_ancestry
        _check_c_ancestry(path,allow_missing_leaf=True)
        if path.exists():
            return default_name+'.'+uuid.uuid4().hex
        return default_name

    def _open(self):
        stream=super()._open()
        try:
            if os.name!='nt':
                os.chmod(self.baseFilename,0o600)
            else:
                from .scoped_authority import check_private
                check_private(Path(self.baseFilename))
        except Exception:
            stream.close()
            raise
        return stream
