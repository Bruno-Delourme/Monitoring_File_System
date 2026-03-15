"""
Tests unitaires pour monitor.py.
À lancer depuis la racine du projet : pytest tests/ -v
"""
import json
import os
import tempfile
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# S'assurer que le projet est sur le path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import monitor
from utils.metadata import normalize_path, get_file_metadata


@pytest.fixture
def temp_dir():
    """Dossier temporaire pour les tests."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def temp_config_file():
    """Fichier config.json temporaire pour ne pas écraser la config réelle."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        yield path
    finally:
        if os.path.exists(path):
            os.unlink(path)


class TestLoadConfig:
    """Tests pour load_config()."""

    def test_load_config_missing_file(self):
        """Si le fichier config n'existe pas, retourne dict vide."""
        with patch.object(monitor, "CONFIG_FILE", "/chemin/inexistant/config.json"):
            result = monitor.load_config()
        assert result == {}

    def test_load_config_valid(self, temp_config_file):
        with open(temp_config_file, "w", encoding="utf-8") as f:
            json.dump({"watch_directory": "/tmp", "filename": "test.txt"}, f)
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            result = monitor.load_config()
        assert result["watch_directory"] == "/tmp"
        assert result["filename"] == "test.txt"


class TestSaveConfig:
    """Tests pour save_config()."""

    def test_save_config_creates_file(self, temp_config_file):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({"key": "value"})
        with open(temp_config_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data == {"key": "value"}


class TestGetMonitoredFilePath:
    """Tests pour get_monitored_file_path()."""

    def test_get_monitored_file_path_empty_config(self, temp_config_file):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({})
            result = monitor.get_monitored_file_path()
        assert result is None

    def test_get_monitored_file_path_with_config(self, temp_config_file, temp_dir):
        watch_dir = normalize_path(temp_dir)
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({
                "watch_directory": watch_dir,
                "filename": "fichier.txt"
            })
            result = monitor.get_monitored_file_path()
        expected = normalize_path(os.path.join(watch_dir, "fichier.txt"))
        assert result == expected


class TestSetupWatch:
    """Tests pour setup_watch()."""

    def test_setup_watch_nonexistent_dir(self, temp_config_file):
        """Si le dossier n'existe pas, la config n'est pas enregistrée."""
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({})
            monitor.setup_watch("/dossier/qui/nexiste/pas", "fichier.txt")
            config = monitor.load_config()
        assert config == {}

    def test_setup_watch_valid_dir(self, temp_config_file, temp_dir):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.setup_watch(temp_dir, "cible.txt")
            config = monitor.load_config()
        assert config["watch_directory"] == normalize_path(temp_dir)
        assert config["filename"] == "cible.txt"
        assert "file_metadata" in config


class TestRemoveWatch:
    """Tests pour remove_watch()."""

    def test_remove_watch_empty_config(self, temp_config_file):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({})
            monitor.remove_watch()
            config = monitor.load_config()
        assert config == {}

    def test_remove_watch_clears_config(self, temp_config_file, temp_dir):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({
                "watch_directory": temp_dir,
                "filename": "x.txt",
                "file_metadata": {}
            })
            monitor.remove_watch()
            config = monitor.load_config()
        assert config == {}


class TestListWatch:
    """Tests pour list_watch() - vérifie qu'il ne plante pas."""

    def test_list_watch_no_config(self, temp_config_file, capsys):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({})
            monitor.list_watch()
        out = capsys.readouterr().out
        assert "Aucune surveillance" in out

    def test_list_watch_with_config(self, temp_config_file, temp_dir, capsys):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({
                "watch_directory": temp_dir,
                "filename": "f.txt"
            })
            monitor.list_watch()
        out = capsys.readouterr().out
        assert "Configuration" in out or "surveillance" in out.lower()
        assert "f.txt" in out


class TestChmodFile:
    """Tests pour chmod_file()."""

    def test_chmod_file_nonexistent(self, temp_config_file, capsys):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.chmod_file("/fichier/inexistant/xyz", "644")
        out = capsys.readouterr().out
        assert "ERREUR" in out or "introuvable" in out.lower()

    def test_chmod_file_valid(self, temp_dir, temp_config_file, capsys):
        fpath = os.path.join(temp_dir, "fichier.txt")
        Path(fpath).write_text("hello")
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.chmod_file(fpath, "600")
        st = os.stat(fpath)
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o600


class TestMonitorHandler:
    """Tests pour MonitorHandler."""

    def test_is_monitored_file_true(self, temp_config_file, temp_dir):
        path = normalize_path(os.path.join(temp_dir, "cible.txt"))
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({
                "watch_directory": temp_dir,
                "filename": "cible.txt"
            })
            handler = monitor.MonitorHandler()
        assert handler._is_monitored_file(path) is True

    def test_is_monitored_file_false(self, temp_config_file, temp_dir):
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({
                "watch_directory": temp_dir,
                "filename": "autre.txt"
            })
            handler = monitor.MonitorHandler()
        other_path = os.path.join(temp_dir, "cible.txt")
        assert handler._is_monitored_file(other_path) is False

    def test_compare_and_alert_file_appeared(self, temp_config_file, temp_dir):
        """Fichier qui apparaît : doit détecter et mettre à jour les métadonnées."""
        fpath = os.path.join(temp_dir, "nouveau.txt")
        Path(fpath).write_text("contenu")
        with patch.object(monitor, "CONFIG_FILE", temp_config_file):
            monitor.save_config({
                "watch_directory": temp_dir,
                "filename": "nouveau.txt",
                "file_metadata": None
            })
            handler = monitor.MonitorHandler()
            handler.compare_and_alert(fpath)
            config = monitor.load_config()
        assert config.get("file_metadata") is not None
        assert config["file_metadata"].get("exists") is True
