from pathlib import Path

import pytest

from referencing import Registry, Resource, exceptions
from referencing.jsonschema import DRAFT202012
from referencing.manifest import (
    DEFAULT_ALGORITHM,
    MANIFEST_VERSION,
    ContentMismatch,
    Entry,
    IdentityMismatch,
    Manifest,
    ManifestFormatError,
    ManifestImportError,
    MissingDependency,
    VerificationError,
    VerificationKind,
    canonical_content,
    content_digest,
    verify,
)

A = "https://example.com/a"
B = "https://example.com/b"

LOCAL_A = "a.json"
LOCAL_B = "b.json"


def schema(identity, **kwargs):
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": identity,
        **kwargs,
    }


def relocated(contents, identity):
    return dict(contents, **{"$id": identity})


def registry_of(*schemas):
    return Registry().with_contents(
        [(each["$id"], each) for each in schemas],
    )


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "a.json").write_text(
        '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
        ' "$id": "a.json",'
        ' "properties": {"b": {"$ref": "b.json"}}}',
        encoding="utf-8",
    )
    (tmp_path / "b.json").write_text(
        '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
        ' "$id": "b.json", "type": "string"}',
        encoding="utf-8",
    )
    return tmp_path


class TestContentDigest:
    def test_canonical(self):
        one = content_digest({"b": 2, "a": 1})
        two = content_digest({"a": 1, "b": 2})
        assert one == two
        assert one.startswith(f"{DEFAULT_ALGORITHM}:")

    def test_identity_is_excluded(self):
        assert content_digest(
            schema(A, type="string"),
        ) == content_digest(
            schema(B, type="string"),
        )
        assert canonical_content(schema(A, type="string")) == (
            '{"$schema":"https://json-schema.org/draft/2020-12/schema",'
            '"type":"string"}'
        )

    def test_other_changes_are_included(self):
        assert content_digest(schema(A, type="string")) != content_digest(
            schema(A, type="integer"),
        )

    def test_nested_identities_are_included(self):
        one = schema(A, **{"$defs": {"x": {"$id": "x"}}})
        two = schema(A, **{"$defs": {"x": {"$id": "y"}}})
        assert content_digest(one) != content_digest(two)

    def test_alternate_algorithm(self):
        assert content_digest({}, algorithm="sha512").startswith("sha512:")

    def test_unknown_algorithm(self):
        with pytest.raises(ValueError):
            content_digest({}, algorithm="nope")


class TestEntry:
    def test_from_resource(self):
        contents = schema(A)
        entry = Entry.from_resource(
            "https://example.com/slot",
            Resource.from_contents(contents),
        )
        assert entry.id == A
        assert entry.digest == content_digest(contents)

    def test_relative_identity_is_resolved(self):
        entry = Entry.from_resource(
            "https://example.com/dir/schema",
            Resource.from_contents(schema("child")),
        )
        assert entry.id == "https://example.com/dir/child"

    def test_bare_digest_uses_default_algorithm(self):
        digest = content_digest({})
        assert Entry(digest=digest[7:]).digest == digest

    def test_digest_mapping_forms(self):
        digest = content_digest({})
        algorithm, hexdigest = digest.split(":")
        as_mapping = Entry(digest={algorithm: hexdigest})
        assert as_mapping.digest == digest

    def test_invalid_digest(self):
        with pytest.raises(ValueError):
            Entry(digest="sha256:not-a-digest")


class TestManifestFromRegistry:
    def test_every_resource(self):
        registry = registry_of(schema(A), schema(B))
        manifest = Manifest.from_registry(registry)
        assert set(manifest) == {A, B}
        assert manifest.verify(registry).ok

    def test_includes_nested_subresources(self):
        contents = schema(
            A,
            **{"$defs": {"child": {"$id": "child", "type": "integer"}}},
        )
        registry = registry_of(contents)
        manifest = Manifest.from_registry(registry)
        assert set(manifest) == {A, "https://example.com/child"}
        assert manifest.verify(registry).ok

    def test_from_resources(self):
        resource = Resource.from_contents(schema(A))
        manifest = Manifest.from_resources([("urn:slot", resource)])
        assert set(manifest) == {"urn:slot"}
        assert manifest["urn:slot"].id == A


class TestManifestFiles:
    def test_bulk_import(self, root):
        manifest = Manifest.from_directory(root)
        assert set(manifest) == {LOCAL_A, LOCAL_B}
        assert manifest.files == {LOCAL_A: "a.json", LOCAL_B: "b.json"}
        assert manifest.verify().ok

    def test_local_cross_references_resolve(self, root):
        registry = Manifest.from_directory(root).to_registry()
        resolved = registry.resolver().lookup(LOCAL_A)
        assert resolved.contents["properties"]["b"] == {"$ref": "b.json"}
        b = resolved.resolver.lookup("b.json")
        assert b.contents["type"] == "string"

    def test_paths_without_identities_are_keyed_by_path(self, tmp_path):
        (tmp_path / "plain.json").write_text('{"foo": "bar"}')
        manifest = Manifest.from_directory(tmp_path)
        assert set(manifest) == {"plain.json"}
        assert manifest["plain.json"].id is None

    def test_exclude(self, root):
        Manifest.from_directory(root).to_file(root / "manifest.json")
        manifest = Manifest.from_directory(root, exclude=["manifest.json"])
        assert set(manifest) == {LOCAL_A, LOCAL_B}

    def test_from_files(self, root):
        manifest = Manifest.from_files([root / "a.json", root / "b.json"])
        assert set(manifest) == {LOCAL_A, LOCAL_B}
        assert manifest.verify().ok

    def test_duplicate_identities(self, tmp_path):
        for name in ["one.json", "two.json"]:
            (tmp_path / name).write_text(
                '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
                ' "$id": "https://example.com/same"}',
            )
        with pytest.raises(ManifestImportError):
            Manifest.from_directory(tmp_path)

    def test_not_a_directory(self, tmp_path):
        with pytest.raises(ManifestImportError):
            Manifest.from_directory(tmp_path / "nope")

    def test_invalid_json(self, tmp_path):
        (tmp_path / "bad.json").write_text("{nope")
        with pytest.raises(ManifestFormatError):
            Manifest.from_directory(tmp_path)


class TestSerialization:
    def test_round_trip(self, root):
        manifest = Manifest.from_directory(root)
        path = root / "manifest.json"
        manifest.to_file(path)
        again = Manifest.from_file(path)
        assert again.to_dict() == manifest.to_dict()
        assert again.verify().ok
        assert again.base == root

    def test_versions(self):
        manifest = Manifest.from_registry(registry_of(schema(A)))
        assert manifest.to_dict()["version"] == MANIFEST_VERSION

    def test_bare_string_entry(self):
        manifest = Manifest.from_dict({"urn:example": content_digest({})})
        assert manifest["urn:example"].id == "urn:example"

    def test_identity_alias(self):
        manifest = Manifest.from_dict(
            {"urn:example": {"digest": content_digest({}), "identity": A}},
        )
        assert manifest["urn:example"].id == A

    def test_nested_digest(self):
        digest = content_digest({})
        algorithm, hexdigest = digest.split(":")
        manifest = Manifest.from_dict(
            {"urn:example": {"digest": {algorithm: hexdigest}}},
        )
        assert manifest["urn:example"].digest == digest

    def test_list_form(self):
        manifest = Manifest.from_dict(
            {"resources": [{"uri": A, "digest": content_digest({})}]},
        )
        assert set(manifest) == {A}

    @pytest.mark.parametrize(
        "data",
        [
            {"version": 999, "resources": {}},
            {"resources": 12},
            {"resources": {"urn:example": {"nope": 1}}},
            {"resources": [{"digest": content_digest({})}]},
            {"resources": [1]},
            [],
        ],
    )
    def test_invalid(self, data):
        with pytest.raises(ManifestFormatError):
            Manifest.from_dict(data)

    def test_invalid_json(self):
        with pytest.raises(ManifestFormatError):
            Manifest.from_json("{nope")


class TestVerification:
    @pytest.fixture
    def manifest(self):
        return Manifest.from_registry(registry_of(schema(A), schema(B)))

    @pytest.fixture
    def registry(self):
        return registry_of(schema(A), schema(B))

    def test_ok(self, manifest, registry):
        result = manifest.verify(registry)
        assert result
        assert result.ok
        assert result.kind == VerificationKind.OK
        assert result.errors == ()
        assert result.registry is registry
        result.raise_for_errors()

    def test_content_changed(self, manifest, registry):
        changed = registry_of(schema(A, type="string"), schema(B))
        result = manifest.verify(changed)
        assert not result
        assert result.kind == VerificationKind.CONTENT
        assert result.content
        assert not result.identity
        assert not result.is_missing
        [failure] = result.content_changed
        assert failure.uri == A
        assert isinstance(failure, ContentMismatch)
        assert failure.expected == manifest[A].digest
        assert failure.actual == content_digest(schema(A, type="string"))

    def test_identity_changed(self, manifest, registry):
        other = "https://example.com/other"
        changed = registry.with_resource(
            A,
            Resource.from_contents(relocated(schema(A), other)),
        )
        result = manifest.verify(changed)
        assert result.kind == VerificationKind.IDENTITY
        assert result.identity
        assert not result.content
        assert not result.is_missing
        [failure] = result.identity_changed
        assert failure.uri == A
        assert isinstance(failure, IdentityMismatch)
        assert failure.expected == A
        assert failure.actual == other

    def test_identity_changed_only_is_not_content(self, manifest, registry):
        changed = registry.with_resource(
            A,
            Resource.from_contents(
                relocated(schema(A), "https://example.com/other"),
            ),
        )
        result = manifest.verify(changed)
        assert result.kind == VerificationKind.IDENTITY
        assert result.identity
        assert not result.content

    def test_missing(self, manifest, registry):
        result = manifest.verify(registry.remove(B))
        assert result.kind == VerificationKind.MISSING
        assert result.is_missing
        assert not result.content
        assert not result.identity
        assert result.missing == {B}
        [failure] = result.errors
        assert isinstance(failure, MissingDependency)
        assert failure.uri == B

    def test_multiple(self):
        c = "https://example.com/c"
        b = schema(B, description="b")
        manifest = Manifest.from_registry(
            registry_of(
                schema(A, description="a"),
                b,
                schema(c, description="c"),
            ),
        )
        changed = (
            registry_of(schema(A, description="a", type="string"), b)
            .with_resource(
                B,
                Resource.from_contents(
                    relocated(b, "https://example.com/other"),
                ),
            )
        )
        result = manifest.verify(changed)
        assert result.kind == VerificationKind.MULTIPLE
        assert result.content
        assert result.identity
        assert result.is_missing
        assert [failure.uri for failure in result.errors] == [A, B, c]

    def test_raise_for_errors(self, manifest, registry):
        result = manifest.verify(registry.remove(B))
        with pytest.raises(VerificationError) as caught:
            result.raise_for_errors()
        assert caught.value.result is result

    def test_registry_is_untouched(self, manifest, registry):
        before = dict(registry)
        result = manifest.verify(registry)
        assert result.registry is registry
        assert dict(registry) == before
        assert registry.resolver().lookup(B).contents == schema(B)

    def test_rejection_does_not_change_later_output(self, root):
        manifest = Manifest.from_directory(root)
        registry = manifest.to_registry()

        tampered = Resource.from_contents(
            schema(LOCAL_B, type="integer"),
        )
        rejected = manifest.verify(
            registry.with_resource(LOCAL_B, tampered),
        )
        assert rejected.kind == VerificationKind.CONTENT

        assert registry.resolver().lookup(LOCAL_B).contents["type"] == "string"
        assert manifest.verify(registry).ok

    def test_missing_local_file(self, root):
        manifest = Manifest.from_directory(root)
        (root / "b.json").unlink()
        result = manifest.verify()
        assert result.kind == VerificationKind.MISSING
        assert result.missing == {LOCAL_B}

    def test_module_level_verify(self, manifest, registry):
        assert verify(manifest, registry).ok


class TestRetrieval:
    def test_retrieves_verified_contents(self, root):
        manifest = Manifest.from_directory(root)
        registry = Registry(retrieve=manifest)
        assert registry.get_or_retrieve(
            LOCAL_B,
        ).value.contents["type"] == "string"

    def test_rejects_changed_contents(self, root):
        manifest = Manifest.from_directory(root)
        (root / "b.json").write_text(
            '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
            ' "$id": "b.json", "type": "integer"}',
            encoding="utf-8",
        )
        with pytest.raises(ContentMismatch):
            manifest.retrieve(LOCAL_B)

        registry = Registry(retrieve=manifest)
        with pytest.raises(exceptions.Unretrievable) as caught:
            registry.get_or_retrieve(LOCAL_B)
        assert isinstance(caught.value.__cause__, ContentMismatch)

    def test_rejects_changed_identity(self, root):
        manifest = Manifest.from_directory(root)
        (root / "b.json").write_text(
            '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
            ' "$id": "other.json", "type": "string"}',
            encoding="utf-8",
        )
        with pytest.raises(IdentityMismatch):
            manifest.retrieve(LOCAL_B)

        registry = Registry(retrieve=manifest)
        with pytest.raises(exceptions.Unretrievable) as caught:
            registry.get_or_retrieve(LOCAL_B)
        assert isinstance(caught.value.__cause__, IdentityMismatch)

    def test_unknown_uri(self, root):
        manifest = Manifest.from_directory(root)
        with pytest.raises(exceptions.NoSuchResource):
            manifest.retrieve("urn:unknown")

    def test_to_registry_is_offline(self, root):
        manifest = Manifest.from_directory(root)
        registry = manifest.to_registry()
        assert registry.resolver().lookup(LOCAL_A).contents["$id"] == LOCAL_A
        assert set(manifest) <= {each.rstrip("#") for each in registry}


class TestEntriesAndMapping:
    def test_mapping_interface(self):
        manifest = Manifest.from_registry(registry_of(schema(A)))
        assert len(manifest) == 1
        assert list(manifest) == [A]
        assert isinstance(manifest[A], Entry)
        assert manifest.entries == manifest.entries

    def test_opaque_default(self):
        contents = {"foo": "bar"}
        resource = Resource.from_contents(
            contents,
            default_specification=DRAFT202012,
        )
        entry = Entry.from_resource("urn:example", resource)
        assert entry.id is None
        assert entry.digest == content_digest(contents)


class TestNestedFiles:
    def test_subdirectory_relative_identities(self, tmp_path):
        nested = tmp_path / "nested"
        nested.mkdir()
        (nested / "a.json").write_text(
            '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
            ' "$id": "a.json", "type": "object"}',
        )
        (tmp_path / "top.json").write_text(
            '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
            ' "$id": "top.json",'
            ' "properties": {"a": {"$ref": "nested/a.json"}}}',
        )
        manifest = Manifest.from_directory(tmp_path)
        assert set(manifest) == {"nested/a.json", "top.json"}
        assert manifest["nested/a.json"].id == "nested/a.json"
        assert manifest.verify().ok

    def test_absolute_identity_is_used_as_key(self, tmp_path):
        (tmp_path / "file.json").write_text(
            '{"$schema": "https://json-schema.org/draft/2020-12/schema",'
            ' "$id": "https://example.com/absolute"}',
        )
        manifest = Manifest.from_directory(tmp_path)
        assert set(manifest) == {"https://example.com/absolute"}
        assert manifest["https://example.com/absolute"].path == "file.json"


class TestRegistryKeys:
    def test_declared_identity_wins_over_slot(self):
        contents = schema(A)
        manifest = Manifest.from_registry(
            Registry().with_contents([("urn:example:slot", contents)]),
        )
        assert list(manifest) == [A]
        assert manifest[A].id == A

    def test_slot_used_without_identity(self):
        manifest = Manifest.from_registry(
            Registry().with_resource(
                "urn:example:slot",
                Resource.opaque({"foo": "bar"}),
            ),
        )
        assert list(manifest) == ["urn:example:slot"]
        assert manifest["urn:example:slot"].id is None
