import argon2


argon2.PasswordHasher.from_parameters(argon2.profiles.RFC_9106_HIGH_MEMORY)
ph = argon2.PasswordHasher()

ph.hash("pw")
ph.hash("pw", salt=b"salt")
ph.hash(b"pw")
ph.hash(b"pw", salt=b"salt")
ph.verify("hash", "pw")
ph.verify(b"hash", "pw")
ph.verify(b"hash", b"pw")
ph.verify("hash", b"pw")

if ph.check_needs_rehash("hash") is True:
    ...

params: argon2.Parameters = argon2.profiles.get_default_parameters()


# Grouped migration contract (25.2.0)
class _Handle:
    def open(self) -> None:
        return None

    def read(self) -> str | bytes:
        return "pw"

    def close(self) -> None:
        return None


_store = argon2.InMemoryCommitStore()
_group = argon2.ImportGroup(
    group_id="g1",
    profile=argon2.profiles.CHEAPEST,
    items=(argon2.MigrationItem(key="acct", handle=_Handle()),),
)
_batch = argon2.import_groups([_group], _store)
_gr = _batch.group("g1")
if _batch.all_committed:
    _gr = _batch.groups[0]
if _gr.status is argon2.GroupStatus.COMMITTED:
    _keys: tuple[str, ...] = _gr.committed_keys
    _item: argon2.ItemResult = _gr.items[0]
    if _item.digest_verified is True:
        pass
_fp: str = argon2.digest_fingerprint("$argon2id$v=19$m=8,t=1,p=1$x$y")
