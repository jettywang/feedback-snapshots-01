import hashlib
import json
import os
import pathlib

import multivolumefile
import pytest

import py7zr
from py7zr.cli import Cli


def _make_volumes(target: pathlib.Path, volume_size: int = 2048) -> pathlib.Path:
    """Create an archive large enough to span several volumes."""
    target = target / "backup"
    target.mkdir()
    src = target / "src"
    src.mkdir()
    # Incompressible payloads keep the archive from collapsing into one volume.
    (src / "a.bin").write_bytes(os.urandom(6000))
    (src / "b.bin").write_bytes(os.urandom(5000))
    (src / "c.txt").write_bytes(b"offline backup\n" * 20)
    with multivolumefile.MultiVolume(target / "backup.7z", mode="wb", volume=volume_size, ext_digits=4) as mv:
        with py7zr.SevenZipFile(mv, "w") as archive:
            archive.writeall(src, "src")
    return src


def _catalog(directory: pathlib.Path, basename: str = "backup.7z") -> list[py7zr.VolumeEntry]:
    entries = []
    for child in sorted(directory.iterdir()):
        if child.name.startswith(basename + "."):
            entries.append(
                py7zr.VolumeEntry(child.name, child.stat().st_size, hashlib.sha256(child.read_bytes()).hexdigest())
            )
    return entries


def _volume_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "backup"


def _volumes_for(tmp_path: pathlib.Path):
    _make_volumes(tmp_path)
    volumes_dir = _volume_dir(tmp_path)
    return volumes_dir, _catalog(volumes_dir)


@pytest.mark.misc
def test_load_volumes_extracts_without_merging(tmp_path):
    src = _make_volumes(tmp_path)
    volumes_dir = _volume_dir(tmp_path)
    catalog = _catalog(volumes_dir)
    assert len(catalog) > 1
    merged = volumes_dir / "merged.7z"
    before = {p.name: p.read_bytes() for p in volumes_dir.iterdir() if p.name.startswith("backup.7z.")}

    with py7zr.load_volumes(volumes_dir, catalog) as volumes:
        assert volumes.verification.ok
        assert volumes.verification.reason() is None
        assert volumes.verification.describe() == f"verified {len(catalog)} volume(s), {sum(e.size for e in catalog)} bytes"
        with py7zr.SevenZipFile(volumes, "r") as archive:
            assert sorted(archive.getnames()) == ["src", "src/a.bin", "src/b.bin", "src/c.txt"]
            assert archive.archiveinfo().filename == volumes.name
            archive.extractall(tmp_path / "out")

    assert (tmp_path / "out" / "src" / "a.bin").read_bytes() == (src / "a.bin").read_bytes()
    assert (tmp_path / "out" / "src" / "b.bin").read_bytes() == (src / "b.bin").read_bytes()
    assert (tmp_path / "out" / "src" / "c.txt").read_bytes() == (src / "c.txt").read_bytes()
    assert not merged.exists()
    assert {p.name: p.read_bytes() for p in volumes_dir.iterdir() if p.name.startswith("backup.7z.")} == before


@pytest.mark.misc
def test_load_volumes_reports_missing_volume(tmp_path):
    volumes_dir, catalog = _volumes_for(tmp_path)
    removed = catalog[1].name
    (volumes_dir / removed).unlink()
    untouched = {p.name: p.read_bytes() for p in volumes_dir.iterdir() if p.name.startswith("backup.7z.")}

    with pytest.raises(py7zr.VolumeSetIncompleteError) as excinfo:
        with py7zr.load_volumes(volumes_dir, catalog):
            pytest.fail("incomplete set must not yield a stream")

    verification = excinfo.value.verification
    assert verification.reason() == "missing"
    assert verification.missing == [removed]
    assert verification.altered == []
    assert removed in verification.describe()
    assert {p.name: p.read_bytes() for p in volumes_dir.iterdir() if p.name.startswith("backup.7z.")} == untouched


@pytest.mark.misc
def test_load_volumes_reports_replaced_volume(tmp_path):
    volumes_dir, catalog = _volumes_for(tmp_path)
    replaced = catalog[1].name
    (volumes_dir / replaced).write_bytes(b"X" * catalog[1].size)

    with pytest.raises(py7zr.VolumeSetAlteredError) as excinfo:
        with py7zr.load_volumes(volumes_dir, catalog):
            pytest.fail("altered set must not yield a stream")

    verification = excinfo.value.verification
    assert verification.reason() == "altered"
    assert verification.altered == [replaced]
    assert verification.missing == []
    assert replaced in verification.describe()


@pytest.mark.misc
def test_load_volumes_reports_unexpected_volume(tmp_path):
    volumes_dir, catalog = _volumes_for(tmp_path)
    extra = volumes_dir / "backup.7z.9999"
    extra.write_bytes(b"not in catalog")

    with pytest.raises(py7zr.VolumeSetUnexpectedError) as excinfo:
        with py7zr.load_volumes(volumes_dir, catalog, basename="backup.7z"):
            pytest.fail("extra volume must not be ignored")

    assert excinfo.value.verification.reason() == "unexpected"
    assert excinfo.value.verification.unexpected == [extra.name]


@pytest.mark.misc
def test_load_volumes_ignores_unrelated_files(tmp_path):
    volumes_dir, catalog = _volumes_for(tmp_path)
    (volumes_dir / "notes.txt").write_text("not a volume")
    with py7zr.load_volumes(volumes_dir, catalog) as volumes:
        assert volumes.verification.ok


@pytest.mark.misc
def test_load_volumes_ignores_path_swap_after_verification(tmp_path):
    """A path swap cannot feed new bytes to extraction: the inode is pinned."""
    volumes_dir, catalog = _volumes_for(tmp_path)
    victim = volumes_dir / catalog[1].name
    verified_bytes = victim.read_bytes()

    with py7zr.load_volumes(volumes_dir, catalog) as volumes:
        outside = volumes_dir / "outside.bin"
        outside.write_bytes(b"Y" * catalog[1].size)
        os.replace(outside, victim)
        with py7zr.SevenZipFile(volumes, "r") as archive:
            archive.extractall(tmp_path / "out")
        volumes.seek(sum(entry.size for entry in catalog[:1]))
        assert volumes.read(catalog[1].size) == verified_bytes


@pytest.mark.misc
def test_load_volumes_detects_inplace_change_after_verification(tmp_path):
    volumes_dir, catalog = _volumes_for(tmp_path)
    victim = volumes_dir / catalog[1].name

    with py7zr.load_volumes(volumes_dir, catalog) as volumes:
        with victim.open("r+b") as handle:
            handle.seek(0)
            handle.write(b"Z")
        with pytest.raises(py7zr.VolumeSetAlteredError):
            py7zr.SevenZipFile(volumes, "r")


@pytest.mark.misc
def test_load_volumes_rejects_bad_catalog(tmp_path):
    volumes_dir, _ = _volumes_for(tmp_path)
    with pytest.raises(ValueError):
        with py7zr.load_volumes(volumes_dir, []):
            pass
    with pytest.raises(ValueError):
        py7zr.VolumeEntry("backup.7z.0001", 1, "not-a-digest")
    with pytest.raises(ValueError):
        py7zr.VolumeEntry("../backup.7z.0001", 1, "0" * 64)
    with pytest.raises(ValueError):
        with py7zr.load_volumes(volumes_dir, [{"name": "backup.7z.0001"}]):
            pass
    with pytest.raises(ValueError):
        # A gap in the catalog itself must be rejected before touching disk.
        with py7zr.load_volumes(
            volumes_dir,
            [
                py7zr.VolumeEntry("backup.7z.0001", 1, "0" * 64),
                py7zr.VolumeEntry("backup.7z.0003", 1, "0" * 64),
            ],
        ):
            pass
    with pytest.raises(ValueError):
        with py7zr.load_volumes(
            volumes_dir,
            [
                py7zr.VolumeEntry("backup.7z.0001", 1, "0" * 64),
                py7zr.VolumeEntry("other.7z.0002", 1, "0" * 64),
            ],
        ):
            pass


@pytest.mark.misc
def test_volume_entry_round_trip():
    entry = py7zr.VolumeEntry("backup.7z.0001", 2048, "AB" * 32)
    assert entry.sha256 == "ab" * 32
    assert py7zr.VolumeEntry.from_dict(entry.to_dict()) == entry


def _write_catalog(tmp_path: pathlib.Path, entries) -> pathlib.Path:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps([entry.to_dict() for entry in entries]), encoding="utf-8")
    return path


@pytest.mark.cli
def test_cli_extracts_verified_volumes(tmp_path, capsys):
    _make_volumes(tmp_path)
    volumes_dir = _volume_dir(tmp_path)
    catalog = _write_catalog(tmp_path, _catalog(volumes_dir))
    cli = Cli()

    rc = cli.run(
        [
            "x",
            str(volumes_dir / "backup.7z.0001"),
            str(tmp_path / "out"),
            "--volumes",
            str(volumes_dir),
            "--catalog",
            str(catalog),
        ]
    )

    out, err = capsys.readouterr()
    assert rc == 0
    assert f"Verified {len(_catalog(volumes_dir))} volume(s)." in err
    assert (tmp_path / "out" / "src" / "a.bin").exists()


@pytest.mark.cli
def test_cli_reports_missing_volume(tmp_path, capsys):
    _make_volumes(tmp_path)
    volumes_dir = _volume_dir(tmp_path)
    entries = _catalog(volumes_dir)
    removed = entries[1].name
    (volumes_dir / removed).unlink()
    catalog = _write_catalog(tmp_path, entries)

    rc = Cli().run(
        [
            "x",
            str(volumes_dir / "backup.7z.0001"),
            str(tmp_path / "out"),
            "--volumes",
            str(volumes_dir),
            "--catalog",
            str(catalog),
        ]
    )

    out, err = capsys.readouterr()
    assert rc == 1
    assert "missing" in err
    assert removed in err
    assert not (tmp_path / "out").exists()


@pytest.mark.cli
def test_cli_reports_replaced_volume(tmp_path, capsys):
    _make_volumes(tmp_path)
    volumes_dir = _volume_dir(tmp_path)
    entries = _catalog(volumes_dir)
    replaced = entries[1].name
    (volumes_dir / replaced).write_bytes(b"X" * entries[1].size)
    catalog = _write_catalog(tmp_path, entries)

    rc = Cli().run(
        [
            "x",
            str(volumes_dir / "backup.7z.0001"),
            str(tmp_path / "out"),
            "--volumes",
            str(volumes_dir),
            "--catalog",
            str(catalog),
        ]
    )

    out, err = capsys.readouterr()
    assert rc == 1
    assert "altered" in err
    assert replaced in err
    assert not (tmp_path / "out").exists()


@pytest.mark.misc
def test_verified_volumes_open_independent_of_prior_position(tmp_path):
    """Callers may inspect the stream before handing it to SevenZipFile."""
    volumes_dir, catalog = _volumes_for(tmp_path)

    with py7zr.load_volumes(volumes_dir, catalog) as volumes:
        volumes.seek(0, os.SEEK_END)
        assert volumes.read(8) == b""
        with py7zr.SevenZipFile(volumes, "r") as archive:
            assert "src/a.bin" in archive.getnames()
            assert archive.testzip() is None
            archive.reset()
            archive.extractall(tmp_path / "out")

    assert (tmp_path / "out" / "src" / "a.bin").exists()
