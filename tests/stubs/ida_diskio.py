import os
import tempfile

_dir = os.path.join(tempfile.gettempdir(), "unknowncyber-tests", "idauser")
os.makedirs(_dir, exist_ok=True)


def get_user_idadir():
    return _dir
