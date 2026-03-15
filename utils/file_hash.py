import hashlib


def file_hash(path):
    """
    Calcule le hash SHA256 du fichier.
    Retourne None en cas d'erreur.
    """
    h = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None