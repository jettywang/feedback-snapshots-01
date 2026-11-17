from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

PAGE_SIZE = 512


def _connect(path: Path, secure_delete: bool) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA page_size={PAGE_SIZE}")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA secure_delete=ON" if secure_delete else "PRAGMA secure_delete=OFF")
    return connection


def _create(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT NOT NULL, score INTEGER)")
    connection.executemany(
        "INSERT INTO people (name, score) VALUES (?, ?)",
        [(f"name-{index}", index * 7) for index in range(1, 6)],
    )
    connection.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
    connection.executemany(
        "INSERT INTO notes (body) VALUES (?)",
        [(f"note-{index}-" + "x" * 90,) for index in range(10)],
    )
    connection.commit()


def create_databases(directory: Path) -> dict[str, Path]:
    """Create small before/after databases using only the standard library."""
    directory.mkdir(parents=True, exist_ok=True)

    before = directory / "before.sqlite"
    after = directory / "after.sqlite"
    secure = directory / "secure.sqlite"
    dropped = directory / "dropped.sqlite"
    reused = directory / "reused.sqlite"

    for path in (before, after, secure, dropped, reused):
        path.unlink(missing_ok=True)

    connection = _connect(before, secure_delete=False)
    _create(connection)
    connection.close()

    # Copy the pre-delete database, then delete one row and all of the notes.
    for target, secure_delete in ((after, False), (secure, True)):
        target.write_bytes(before.read_bytes())
        connection = _connect(target, secure_delete=secure_delete)
        connection.execute("DELETE FROM people WHERE id = 3")
        connection.execute("DELETE FROM notes")
        connection.commit()
        connection.close()

    dropped.write_bytes(before.read_bytes())
    connection = _connect(dropped, secure_delete=False)
    connection.execute("DROP TABLE notes")
    connection.commit()
    connection.close()

    reused.write_bytes(before.read_bytes())
    connection = _connect(reused, secure_delete=False)
    connection.execute("DELETE FROM notes")
    connection.commit()
    connection.execute("CREATE TABLE archive (id INTEGER PRIMARY KEY, body TEXT)")
    connection.executemany(
        "INSERT INTO archive (body) VALUES (?)",
        [(f"archive-{index}-" + "y" * 90,) for index in range(12)],
    )
    connection.commit()
    connection.close()

    return {
        "before": before,
        "after": after,
        "secure": secure,
        "dropped": dropped,
        "reused": reused,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate small SQLite databases for residual forensics tests.")
    parser.add_argument("directory", type=Path, help="Directory to write the databases to")
    args = parser.parse_args()

    for name, path in create_databases(args.directory).items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
