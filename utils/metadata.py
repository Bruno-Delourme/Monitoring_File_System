import os
import stat

from utils.file_hash import file_hash


def normalize_path(path):
    """
    Convertit un chemin en chemin absolu propre.
    """
    return os.path.abspath(os.path.expanduser(path))


def get_file_metadata(path):
    """
    Retourne les métadonnées d'un fichier.
    Si le fichier n'existe pas, retourne exists=False.
    """
    path = normalize_path(path)

    if not os.path.exists(path):
        return {
            "path": path,
            "exists": False,
            "mode": None,
            "uid": None,
            "gid": None,
            "mtime": None,
            "sha256": None
        }

    try:
        st = os.stat(path)
        return {
            "path": path,
            "exists": True,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mtime": int(st.st_mtime),
            "sha256": file_hash(path)
        }
    except (OSError, PermissionError):
        return {
            "path": path,
            "exists": False,
            "mode": None,
            "uid": None,
            "gid": None,
            "mtime": None,
            "sha256": None
        }