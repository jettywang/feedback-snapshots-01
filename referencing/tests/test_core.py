from rpds import HashTrieMap
import pytest

from referencing import Anchor, Registry, Resource, Specification, exceptions
from referencing.jsonschema import DRAFT202012

ID_AND_CHILDREN = Specification(
    name="id-and-children",
    id_of=lambda contents: contents.get("ID"),
    subresources_of=lambda contents: contents.get("children", []),
    anchors_in=lambda specification, contents: [
        Anchor(
            name=name,
            resource=specification.create_resource(contents=each),
        )
        for name, each in contents.get("anchors", {}).items()
    ],
    maybe_in_subresource=lambda segments, resolver, subresource: (
        resolver.in_subresource(subresource)
        if not len(segments) % 2
        and all(each == "children" for each in segments[::2])
        else resolver
    ),
)


def blow_up(uri):  # pragma: no cover
    """
    A retriever suitable for use in tests which expect it never to be used.
    """
    raise RuntimeError("This retrieve function expects to never be called!")


class TestRegistry:
    def test_with_resource(self):
        """
        Adding a resource to the registry then allows re-retrieving it.
        """

        resource = Resource.opaque(contents={"foo": "bar"})
        uri = "urn:example"
        registry = Registry().with_resource(uri=uri, resource=resource)
        assert registry[uri] is resource

    def test_with_resources(self):
        """
        Adding multiple resources to the registry is like adding each one.
        """

        one = Resource.opaque(contents={})
        two = Resource(contents={"foo": "bar"}, specification=ID_AND_CHILDREN)
        registry = Registry().with_resources(
            [
                ("http://example.com/1", one),
                ("http://example.com/foo/bar", two),
            ],
        )
        assert registry == Registry().with_resource(
            uri="http://example.com/1",
            resource=one,
        ).with_resource(
            uri="http://example.com/foo/bar",
            resource=two,
        )

    def test_matmul_resource(self):
        uri = "urn:example:resource"
        resource = ID_AND_CHILDREN.create_resource({"ID": uri, "foo": 12})
        registry = resource @ Registry()
        assert registry == Registry().with_resource(uri, resource)

    def test_matmul_many_resources(self):
        one_uri = "urn:example:one"
        one = ID_AND_CHILDREN.create_resource({"ID": one_uri, "foo": 12})

        two_uri = "urn:example:two"
        two = ID_AND_CHILDREN.create_resource({"ID": two_uri, "foo": 12})

        registry = [one, two] @ Registry()
        assert registry == Registry().with_resources(
            [(one_uri, one), (two_uri, two)],
        )

    def test_matmul_resource_without_id(self):
        resource = Resource.opaque(contents={"foo": "bar"})
        with pytest.raises(exceptions.NoInternalID) as e:
            resource @ Registry()
        assert e.value == exceptions.NoInternalID(resource=resource)

    def test_with_contents_from_json_schema(self):
        uri = "urn:example"
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
        registry = Registry().with_contents([(uri, schema)])

        expected = Resource(contents=schema, specification=DRAFT202012)
        assert registry[uri] == expected

    def test_with_contents_and_default_specification(self):
        uri = "urn:example"
        registry = Registry().with_contents(
            [(uri, {"foo": "bar"})],
            default_specification=Specification.OPAQUE,
        )
        assert registry[uri] == Resource.opaque({"foo": "bar"})

    def test_len(self):
        total = 5
        registry = Registry().with_contents(
            [(str(i), {"foo": "bar"}) for i in range(total)],
            default_specification=Specification.OPAQUE,
        )
        assert len(registry) == total

    def test_bool_empty(self):
        assert not Registry()

    def test_bool_not_empty(self):
        registry = Registry().with_contents(
            [(str(i), {"foo": "bar"}) for i in range(3)],
            default_specification=Specification.OPAQUE,
        )
        assert registry

    def test_iter(self):
        registry = Registry().with_contents(
            [(str(i), {"foo": "bar"}) for i in range(8)],
            default_specification=Specification.OPAQUE,
        )
        assert set(registry) == {str(i) for i in range(8)}

    def test_crawl_still_has_top_level_resource(self):
        resource = Resource.opaque({"foo": "bar"})
        uri = "urn:example"
        registry = Registry({uri: resource}).crawl()
        assert registry[uri] is resource

    def test_crawl_finds_a_subresource(self):
        child_id = "urn:child"
        root = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:root", "children": [{"ID": child_id, "foo": 12}]},
        )
        registry = root @ Registry()
        with pytest.raises(LookupError):
            registry[child_id]

        expected = ID_AND_CHILDREN.create_resource({"ID": child_id, "foo": 12})
        assert registry.crawl()[child_id] == expected

    def test_crawl_finds_anchors_with_id(self):
        resource = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:bar", "anchors": {"foo": 12}},
        )
        registry = resource @ Registry()

        assert registry.crawl().anchor(resource.id(), "foo").value == Anchor(
            name="foo",
            resource=ID_AND_CHILDREN.create_resource(12),
        )

    def test_crawl_finds_anchors_no_id(self):
        resource = ID_AND_CHILDREN.create_resource({"anchors": {"foo": 12}})
        registry = Registry().with_resource("urn:root", resource)

        assert registry.crawl().anchor("urn:root", "foo").value == Anchor(
            name="foo",
            resource=ID_AND_CHILDREN.create_resource(12),
        )

    def test_contents(self):
        resource = Resource.opaque({"foo": "bar"})
        uri = "urn:example"
        registry = Registry().with_resource(uri, resource)
        assert registry.contents(uri) == {"foo": "bar"}

    def test_getitem_strips_empty_fragments(self):
        uri = "http://example.com/"
        resource = ID_AND_CHILDREN.create_resource({"ID": uri + "#"})
        registry = resource @ Registry()
        assert registry[uri] == registry[uri + "#"] == resource

    def test_contents_strips_empty_fragments(self):
        uri = "http://example.com/"
        resource = ID_AND_CHILDREN.create_resource({"ID": uri + "#"})
        registry = resource @ Registry()
        assert (
            registry.contents(uri)
            == registry.contents(uri + "#")
            == {"ID": uri + "#"}
        )

    def test_contents_nonexistent_resource(self):
        registry = Registry()
        with pytest.raises(exceptions.NoSuchResource) as e:
            registry.contents("urn:example")
        assert e.value == exceptions.NoSuchResource(ref="urn:example")

    def test_crawled_anchor(self):
        resource = ID_AND_CHILDREN.create_resource({"anchors": {"foo": "bar"}})
        registry = Registry().with_resource("urn:example", resource)
        retrieved = registry.anchor("urn:example", "foo")
        assert retrieved.value == Anchor(
            name="foo",
            resource=ID_AND_CHILDREN.create_resource("bar"),
        )
        assert retrieved.registry == registry.crawl()

    def test_anchor_in_nonexistent_resource(self):
        registry = Registry()
        with pytest.raises(exceptions.NoSuchResource) as e:
            registry.anchor("urn:example", "foo")
        assert e.value == exceptions.NoSuchResource(ref="urn:example")

    def test_init(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        registry = Registry(
            {
                "http://example.com/1": one,
                "http://example.com/foo/bar": two,
            },
        )
        assert (
            registry
            == Registry()
            .with_resources(
                [
                    ("http://example.com/1", one),
                    ("http://example.com/foo/bar", two),
                ],
            )
            .crawl()
        )

    def test_dict_conversion(self):
        """
        Passing a `dict` to `Registry` gets converted to a `HashTrieMap`.

        So continuing to use the registry works.
        """

        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        registry = Registry(
            {"http://example.com/1": one},
        ).with_resource("http://example.com/foo/bar", two)
        assert (
            registry.crawl()
            == Registry()
            .with_resources(
                [
                    ("http://example.com/1", one),
                    ("http://example.com/foo/bar", two),
                ],
            )
            .crawl()
        )

    def test_no_such_resource(self):
        registry = Registry()
        with pytest.raises(exceptions.NoSuchResource) as e:
            registry["urn:bigboom"]
        assert e.value == exceptions.NoSuchResource(ref="urn:bigboom")

    def test_combine(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        three = ID_AND_CHILDREN.create_resource({"baz": "quux"})
        four = ID_AND_CHILDREN.create_resource({"anchors": {"foo": 12}})

        first = Registry({"http://example.com/1": one})
        second = Registry().with_resource("http://example.com/foo/bar", two)
        third = Registry(
            {
                "http://example.com/1": one,
                "http://example.com/baz": three,
            },
        )
        fourth = (
            Registry()
            .with_resource(
                "http://example.com/foo/quux",
                four,
            )
            .crawl()
        )
        assert first.combine(second, third, fourth) == Registry(
            [
                ("http://example.com/1", one),
                ("http://example.com/baz", three),
                ("http://example.com/foo/quux", four),
            ],
            anchors=HashTrieMap(
                {
                    ("http://example.com/foo/quux", "foo"): Anchor(
                        name="foo",
                        resource=ID_AND_CHILDREN.create_resource(12),
                    ),
                },
            ),
        ).with_resource("http://example.com/foo/bar", two)

    def test_combine_self(self):
        """
        Combining a registry with itself short-circuits.

        This is a performance optimization -- otherwise we do lots more work
        (in jsonschema this seems to correspond to making the test suite take
         *3x* longer).
        """

        registry = Registry({"urn:foo": "bar"})
        assert registry.combine(registry) is registry

    def test_combine_with_uncrawled_resources(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        three = ID_AND_CHILDREN.create_resource({"baz": "quux"})

        first = Registry().with_resource("http://example.com/1", one)
        second = Registry().with_resource("http://example.com/foo/bar", two)
        third = Registry(
            {
                "http://example.com/1": one,
                "http://example.com/baz": three,
            },
        )
        expected = Registry(
            [
                ("http://example.com/1", one),
                ("http://example.com/foo/bar", two),
                ("http://example.com/baz", three),
            ],
        )
        combined = first.combine(second, third)
        assert combined != expected
        assert combined.crawl() == expected

    def test_combine_with_single_retrieve(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        three = ID_AND_CHILDREN.create_resource({"baz": "quux"})

        def retrieve(uri):  # pragma: no cover
            pass

        first = Registry().with_resource("http://example.com/1", one)
        second = Registry(
            retrieve=retrieve,
        ).with_resource("http://example.com/2", two)
        third = Registry().with_resource("http://example.com/3", three)

        assert first.combine(second, third) == Registry(
            retrieve=retrieve,
        ).with_resources(
            [
                ("http://example.com/1", one),
                ("http://example.com/2", two),
                ("http://example.com/3", three),
            ],
        )
        assert second.combine(first, third) == Registry(
            retrieve=retrieve,
        ).with_resources(
            [
                ("http://example.com/1", one),
                ("http://example.com/2", two),
                ("http://example.com/3", three),
            ],
        )

    def test_combine_with_common_retrieve(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        three = ID_AND_CHILDREN.create_resource({"baz": "quux"})

        def retrieve(uri):  # pragma: no cover
            pass

        first = Registry(retrieve=retrieve).with_resource(
            "http://example.com/1",
            one,
        )
        second = Registry(
            retrieve=retrieve,
        ).with_resource("http://example.com/2", two)
        third = Registry(retrieve=retrieve).with_resource(
            "http://example.com/3",
            three,
        )

        assert first.combine(second, third) == Registry(
            retrieve=retrieve,
        ).with_resources(
            [
                ("http://example.com/1", one),
                ("http://example.com/2", two),
                ("http://example.com/3", three),
            ],
        )
        assert second.combine(first, third) == Registry(
            retrieve=retrieve,
        ).with_resources(
            [
                ("http://example.com/1", one),
                ("http://example.com/2", two),
                ("http://example.com/3", three),
            ],
        )

    def test_combine_conflicting_retrieve(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        three = ID_AND_CHILDREN.create_resource({"baz": "quux"})

        def foo_retrieve(uri):  # pragma: no cover
            pass

        def bar_retrieve(uri):  # pragma: no cover
            pass

        first = Registry(retrieve=foo_retrieve).with_resource(
            "http://example.com/1",
            one,
        )
        second = Registry().with_resource("http://example.com/2", two)
        third = Registry(retrieve=bar_retrieve).with_resource(
            "http://example.com/3",
            three,
        )

        with pytest.raises(Exception, match="conflict.*retriev"):
            first.combine(second, third)

    def test_remove(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        registry = Registry({"urn:foo": one, "urn:bar": two})
        assert registry.remove("urn:foo") == Registry({"urn:bar": two})

    def test_remove_uncrawled(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        registry = Registry().with_resources(
            [("urn:foo", one), ("urn:bar", two)],
        )
        assert registry.remove("urn:foo") == Registry().with_resource(
            "urn:bar",
            two,
        )

    def test_remove_with_anchors(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"anchors": {"foo": "bar"}})
        registry = (
            Registry()
            .with_resources(
                [("urn:foo", one), ("urn:bar", two)],
            )
            .crawl()
        )
        assert (
            registry.remove("urn:bar")
            == Registry()
            .with_resource(
                "urn:foo",
                one,
            )
            .crawl()
        )

    def test_remove_nonexistent_uri(self):
        with pytest.raises(exceptions.NoSuchResource) as e:
            Registry().remove("urn:doesNotExist")
        assert e.value == exceptions.NoSuchResource(ref="urn:doesNotExist")

    def test_retrieve(self):
        foo = Resource.opaque({"foo": "bar"})
        registry = Registry(retrieve=lambda uri: foo)
        assert registry.get_or_retrieve("urn:example").value == foo

    def test_retrieve_arbitrary_exception(self):
        foo = Resource.opaque({"foo": "bar"})

        def retrieve(uri):
            if uri == "urn:succeed":
                return foo
            raise Exception("Oh no!")

        registry = Registry(retrieve=retrieve)
        assert registry.get_or_retrieve("urn:succeed").value == foo
        with pytest.raises(exceptions.Unretrievable):
            registry.get_or_retrieve("urn:uhoh")

    def test_retrieve_no_such_resource(self):
        foo = Resource.opaque({"foo": "bar"})

        def retrieve(uri):
            if uri == "urn:succeed":
                return foo
            raise exceptions.NoSuchResource(ref=uri)

        registry = Registry(retrieve=retrieve)
        assert registry.get_or_retrieve("urn:succeed").value == foo
        with pytest.raises(exceptions.NoSuchResource):
            registry.get_or_retrieve("urn:uhoh")

    def test_retrieve_cannot_determine_specification(self):
        def retrieve(uri):
            return Resource.from_contents({})

        registry = Registry(retrieve=retrieve)
        with pytest.raises(exceptions.CannotDetermineSpecification):
            registry.get_or_retrieve("urn:uhoh")

    def test_retrieve_already_available_resource(self):
        foo = Resource.opaque({"foo": "bar"})
        registry = Registry({"urn:example": foo}, retrieve=blow_up)
        assert registry["urn:example"] == foo
        assert registry.get_or_retrieve("urn:example").value == foo

    def test_retrieve_first_checks_crawlable_resource(self):
        child = ID_AND_CHILDREN.create_resource({"ID": "urn:child", "foo": 12})
        root = ID_AND_CHILDREN.create_resource({"children": [child.contents]})
        registry = Registry(retrieve=blow_up).with_resource("urn:root", root)
        assert registry.crawl()["urn:child"] == child

    def test_resolver(self):
        one = Resource.opaque(contents={})
        registry = Registry({"http://example.com": one})
        resolver = registry.resolver(base_uri="http://example.com")
        assert resolver.lookup("#").contents == {}

    def test_resolver_with_root_identified(self):
        root = ID_AND_CHILDREN.create_resource({"ID": "http://example.com"})
        resolver = Registry().resolver_with_root(root)
        assert resolver.lookup("http://example.com").contents == root.contents
        assert resolver.lookup("#").contents == root.contents

    def test_resolver_with_root_unidentified(self):
        root = Resource.opaque(contents={})
        resolver = Registry().resolver_with_root(root)
        assert resolver.lookup("#").contents == root.contents

    def test_repr(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        registry = Registry().with_resources(
            [
                ("http://example.com/1", one),
                ("http://example.com/foo/bar", two),
            ],
        )
        assert repr(registry) == "<Registry (2 uncrawled resources)>"
        assert repr(registry.crawl()) == "<Registry (2 resources)>"

    def test_repr_mixed_crawled(self):
        one = Resource.opaque(contents={})
        two = ID_AND_CHILDREN.create_resource({"foo": "bar"})
        registry = (
            Registry(
                {"http://example.com/1": one},
            )
            .crawl()
            .with_resource(uri="http://example.com/foo/bar", resource=two)
        )
        assert repr(registry) == "<Registry (2 resources, 1 uncrawled)>"

    def test_repr_one_resource(self):
        registry = Registry().with_resource(
            uri="http://example.com/1",
            resource=Resource.opaque(contents={}),
        )
        assert repr(registry) == "<Registry (1 uncrawled resource)>"

    def test_repr_empty(self):
        assert repr(Registry()) == "<Registry (0 resources)>"

    def test_with_package_crawls_derived_resources(self):
        """
        A package's nested resources are discovered eagerly.
        """
        root = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "children": [{"ID": "urn:package:child", "foo": 12}],
            },
        )
        registry = Registry().with_package("pkg", [root])
        assert registry["urn:package:child"].contents == {
            "ID": "urn:package:child",
            "foo": 12,
        }
        assert list(registry.packages()) == ["pkg"]

    def test_with_package_accepts_mappings_and_resources(self):
        one = ID_AND_CHILDREN.create_resource({"ID": "urn:one"})
        two = ID_AND_CHILDREN.create_resource({"ID": "urn:two"})
        assert (
            Registry().with_package("pkg", {"urn:alias": one})["urn:alias"]
            == one
        )
        assert Registry().with_package("pkg", [one, two])["urn:two"] == two

    def test_with_package_without_ids(self):
        resource = Resource.opaque(contents={})
        with pytest.raises(exceptions.NoInternalID) as e:
            Registry().with_package("pkg", [resource])
        assert e.value == exceptions.NoInternalID(resource=resource)

    def test_with_package_existing_name_replaces(self):
        old = ID_AND_CHILDREN.create_resource({"ID": "urn:root", "foo": "old"})
        new = ID_AND_CHILDREN.create_resource({"ID": "urn:root", "foo": "new"})
        registry = Registry().with_package("pkg", [old])
        replaced = registry.with_package("pkg", [new])
        assert replaced["urn:root"].contents == {
            "ID": "urn:root",
            "foo": "new",
        }

    def test_replace_nonexistent_package(self):
        with pytest.raises(exceptions.NoSuchPackage) as e:
            Registry().replace("pkg", [])
        assert e.value == exceptions.NoSuchPackage(name="pkg")

    def test_withdraw_nonexistent_package(self):
        with pytest.raises(exceptions.NoSuchPackage) as e:
            Registry().withdraw("pkg")
        assert e.value == exceptions.NoSuchPackage(name="pkg")

    def test_replace_withdraws_derived_resources(self):
        old = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "anchors": {"version": "old"},
                "children": [
                    {"ID": "urn:package:legacy", "anchors": {"only": "old"}},
                ],
            },
        )
        new = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "anchors": {"version": "new"},
                "children": [
                    {"ID": "urn:package:current", "anchors": {"only": "new"}},
                ],
            },
        )
        registry = Registry().with_package("pkg", [old])
        replaced = registry.replace("pkg", [new])

        resolver = replaced.resolver()
        assert resolver.lookup("urn:package:root#version").contents == "new"
        assert resolver.lookup("urn:package:current#only").contents == "new"

        with pytest.raises(exceptions.NoSuchResource):
            replaced["urn:package:legacy"]
        with pytest.raises(exceptions.Unresolvable):
            resolver.lookup("urn:package:legacy#only")
        assert replaced.is_withdrawn("urn:package:legacy")

    def test_replace_keeps_shared_dependency(self):
        """
        A resource another package also legitimately uses is not withdrawn.
        """
        shared = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:shared", "anchors": {"shared": "yes"}},
        )
        old = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "children": [{"ID": "urn:package:legacy"}],
            },
        )
        other = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:other", "children": [shared.contents]},
        )
        new = ID_AND_CHILDREN.create_resource({"ID": "urn:package:root"})

        registry = (
            Registry()
            .with_package("shared", [shared])
            .with_package("other", [other])
            .with_package("pkg", [old])
        )
        replaced = registry.replace("pkg", [new])

        assert replaced["urn:shared"] == shared
        assert replaced["urn:other"].contents["ID"] == "urn:other"
        resolver = replaced.resolver()
        assert resolver.lookup("urn:shared#shared").contents == "yes"
        with pytest.raises(exceptions.NoSuchResource):
            replaced["urn:package:legacy"]

    def test_replace_keeps_base_registry_resources(self):
        shared = ID_AND_CHILDREN.create_resource({"ID": "urn:shared"})
        old = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "children": [shared.contents],
            },
        )
        registry = Registry().with_resource(
            "urn:shared",
            shared,
        ).with_package("pkg", [old])
        replaced = registry.replace(
            "pkg",
            [ID_AND_CHILDREN.create_resource({"ID": "urn:package:root"})],
        )
        assert replaced["urn:shared"] == shared

    def test_replace_does_not_resurrect_withdrawn_resource(self):
        """
        Even if ``retrieve`` could produce a withdrawn URI, it is not used.
        """
        old = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:package:root", "children": [{"ID": "urn:legacy"}]},
        )
        retrieved = ID_AND_CHILDREN.create_resource({"ID": "urn:legacy"})

        def retrieve(uri):  # pragma: no cover
            if uri == "urn:legacy":
                return retrieved
            raise exceptions.NoSuchResource(ref=uri)

        registry = Registry(retrieve=retrieve).with_package("pkg", [old])
        replaced = registry.replace(
            "pkg",
            [ID_AND_CHILDREN.create_resource({"ID": "urn:package:root"})],
        )
        with pytest.raises(exceptions.NoSuchResource):
            replaced.get_or_retrieve("urn:legacy")

    def test_replace_returns_new_snapshot(self):
        """
        The old registry (and resolvers built from it) are unaffected.
        """
        old = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:package:root", "anchors": {"version": "old"}},
        )
        new = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:package:root", "anchors": {"version": "new"}},
        )
        registry = Registry().with_package("pkg", [old])
        resolver = registry.resolver()
        replaced = registry.replace("pkg", [new])

        assert resolver.lookup("urn:package:root#version").contents == "old"
        assert replaced.resolver().lookup(
            "urn:package:root#version",
        ).contents == "new"
        assert list(registry.packages()) == ["pkg"]
        assert registry["urn:package:root"] == old

    def test_withdraw(self):
        old = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "children": [{"ID": "urn:package:legacy"}],
            },
        )
        registry = Registry().with_package("pkg", [old])
        withdrawn = registry.withdraw("pkg")

        assert list(withdrawn.packages()) == []
        with pytest.raises(exceptions.NoSuchResource):
            withdrawn["urn:package:root"]
        with pytest.raises(exceptions.NoSuchResource):
            withdrawn["urn:package:legacy"]

    def test_replace_aliases(self):
        old = ID_AND_CHILDREN.create_resource({"ID": "urn:package:root"})
        registry = Registry().with_package("pkg", [old])
        new = ID_AND_CHILDREN.create_resource({"ID": "urn:package:root"})
        assert registry.replace_package("pkg", [new])[
            "urn:package:root"
        ] == new
        assert list(registry.withdraw_package("pkg").packages()) == []

    def test_crawl_does_not_reintroduce_withdrawn_resource(self):
        """
        Crawling a resource cannot bypass an explicit package withdrawal.
        """
        old = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:package:root", "children": [{"ID": "urn:legacy"}]},
        )
        registry = Registry().with_package("pkg", [old]).withdraw("pkg")
        raiser = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:other", "children": [{"ID": "urn:legacy"}]},
        )
        assert (
            registry.with_resource("urn:other", raiser)
            .crawl()
            .get("urn:legacy")
            is None
        )

    def test_adding_withdrawn_resource_explicitly_revives_it(self):
        old = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:package:root", "children": [{"ID": "urn:legacy"}]},
        )
        registry = Registry().with_package("pkg", [old]).withdraw("pkg")
        revived = registry.with_resource(
            "urn:legacy",
            ID_AND_CHILDREN.create_resource({"ID": "urn:legacy"}),
        )
        assert not revived.is_withdrawn("urn:legacy")
        assert revived["urn:legacy"].contents == {"ID": "urn:legacy"}

    def test_package_replacement_end_to_end(self):
        """
        Shared and package-private indirect references are handled differently.

        The old resolver keeps interpreting in-flight requests, while a
        resolver built from the replacement sees its new anchors and the
        shared dependency, and the retracted private resource is explicitly
        unavailable.
        """
        shared = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:shared",
                "anchors": {"shared": "value"},
                "children": [{"ID": "urn:shared:detail", "foo": "detail"}],
            },
        )
        old = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "anchors": {"version": "legacy"},
                "children": [
                    {"ID": "urn:package:private", "anchors": {"only": "old"}},
                    # A legitimate reuse of a shared dependency.
                    shared.contents,
                ],
            },
        )
        new = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "anchors": {"version": "current"},
                "children": [
                    {"ID": "urn:package:private", "anchors": {"only": "new"}},
                    shared.contents,
                ],
            },
        )

        registry = (
            Registry()
            .with_package("shared", [shared])
            .with_package("package", [old])
        )
        in_flight = registry.resolver()
        replaced = registry.replace("package", [new])
        fresh = replaced.resolver()

        assert in_flight.lookup(
            "urn:package:root#version",
        ).contents == "legacy"
        assert fresh.lookup("urn:package:root#version").contents == "current"

        assert fresh.lookup("urn:shared#shared").contents == "value"
        assert fresh.lookup("urn:shared:detail").contents["foo"] == "detail"

        # The replacement's own private resource is a new version.
        assert fresh.lookup("urn:package:private#only").contents == "new"
        # The old resolver still has its version of the private resource.
        assert in_flight.lookup("urn:package:private#only").contents == "old"

    def test_withdrawn_private_resource_is_explicitly_unavailable(self):
        old = ID_AND_CHILDREN.create_resource(
            {
                "ID": "urn:package:root",
                "children": [{"ID": "urn:package:private"}],
            },
        )
        new = ID_AND_CHILDREN.create_resource({"ID": "urn:package:root"})
        replaced = (
            Registry().with_package("package", [old]).replace("package", [new])
        )

        with pytest.raises(exceptions.NoSuchResource):
            replaced["urn:package:private"]
        with pytest.raises(exceptions.Unresolvable):
            replaced.resolver().lookup("urn:package:private")
        assert replaced.is_withdrawn("urn:package:private")

    def test_combine_merges_same_named_package(self):
        first = Registry().with_package(
            "pkg",
            [ID_AND_CHILDREN.create_resource({"ID": "urn:one"})],
        )
        second = Registry().with_package(
            "pkg",
            [ID_AND_CHILDREN.create_resource({"ID": "urn:two"})],
        )
        combined = first.combine(second)
        assert list(combined.packages()) == ["pkg"]
        withdrawn = combined.withdraw("pkg")
        with pytest.raises(exceptions.NoSuchResource):
            withdrawn["urn:one"]
        with pytest.raises(exceptions.NoSuchResource):
            withdrawn["urn:two"]

    def test_with_package_accepts_list_of_uri_pairs(self):
        resource = ID_AND_CHILDREN.create_resource({"ID": "urn:internal"})
        registry = Registry().with_package("pkg", [("urn:alias", resource)])
        assert registry["urn:alias"] == resource
        assert registry["urn:internal"] == resource

    def test_replace_does_not_remove_taken_over_resource(self):
        """
        A resource another package also refers to is not withdrawn.

        Registration is first-wins: a later package referring to a URI which
        is already present records a shared dependency rather than taking
        ownership of it.
        """
        old = ID_AND_CHILDREN.create_resource({"ID": "urn:root", "v": "old"})
        shared = ID_AND_CHILDREN.create_resource({"ID": "urn:root", "v": "s"})
        registry = (
            Registry()
            .with_package("first", [old])
            .with_package("second", [shared])
        )
        after = registry.replace(
            "first",
            [ID_AND_CHILDREN.create_resource({"ID": "urn:root", "v": "x"})],
        )
        assert after["urn:root"].contents["v"] == "old"
        assert "urn:root" not in after._withdrawn

    def test_replace_withdraws_when_only_first_package_owned_resource(self):
        old = ID_AND_CHILDREN.create_resource({"ID": "urn:root", "v": "old"})
        registry = Registry().with_package("first", [old])
        after = registry.replace(
            "first",
            [ID_AND_CHILDREN.create_resource({"ID": "urn:root", "v": "x"})],
        )
        assert after["urn:root"].contents["v"] == "x"

    def test_replace_reloads_withdrawn_uri(self):
        """
        A replacement which reintroduces a withdrawn URI makes it available.
        """
        old = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:package:root", "children": [{"ID": "urn:legacy"}]},
        )
        new = ID_AND_CHILDREN.create_resource(
            {"ID": "urn:package:root", "children": [{"ID": "urn:legacy"}]},
        )
        replaced = Registry().with_package("pkg", [old]).replace("pkg", [new])
        assert replaced["urn:legacy"] == ID_AND_CHILDREN.create_resource(
            {"ID": "urn:legacy"},
        )


class TestResource:
    def test_from_contents_from_json_schema(self):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
        resource = Resource.from_contents(schema)
        assert resource == Resource(contents=schema, specification=DRAFT202012)

    def test_from_contents_with_no_discernible_information(self):
        """
        Creating a resource with no discernible way to see what
        specification it belongs to (e.g. no ``$schema`` keyword for JSON
        Schema) raises an error.
        """

        with pytest.raises(exceptions.CannotDetermineSpecification):
            Resource.from_contents({"foo": "bar"})

    def test_from_contents_with_no_discernible_information_and_default(self):
        resource = Resource.from_contents(
            {"foo": "bar"},
            default_specification=Specification.OPAQUE,
        )
        assert resource == Resource.opaque(contents={"foo": "bar"})

    def test_from_contents_unneeded_default(self):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
        resource = Resource.from_contents(
            schema,
            default_specification=Specification.OPAQUE,
        )
        assert resource == Resource(
            contents=schema,
            specification=DRAFT202012,
        )

    def test_non_mapping_from_contents(self):
        resource = Resource.from_contents(
            True,
            default_specification=ID_AND_CHILDREN,
        )
        assert resource == Resource(
            contents=True,
            specification=ID_AND_CHILDREN,
        )

    def test_from_contents_with_fallback(self):
        resource = Resource.from_contents(
            {"foo": "bar"},
            default_specification=Specification.OPAQUE,
        )
        assert resource == Resource.opaque(contents={"foo": "bar"})

    def test_id_delegates_to_specification(self):
        specification = Specification(
            name="",
            id_of=lambda contents: "urn:fixedID",
            subresources_of=lambda contents: [],
            anchors_in=lambda specification, contents: [],
            maybe_in_subresource=(
                lambda segments, resolver, subresource: resolver
            ),
        )
        resource = Resource(
            contents={"foo": "baz"},
            specification=specification,
        )
        assert resource.id() == "urn:fixedID"

    def test_id_strips_empty_fragment(self):
        uri = "http://example.com/"
        root = ID_AND_CHILDREN.create_resource({"ID": uri + "#"})
        assert root.id() == uri

    def test_subresources_delegates_to_specification(self):
        resource = ID_AND_CHILDREN.create_resource({"children": [{}, 12]})
        assert list(resource.subresources()) == [
            ID_AND_CHILDREN.create_resource(each) for each in [{}, 12]
        ]

    def test_subresource_with_different_specification(self):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
        resource = ID_AND_CHILDREN.create_resource({"children": [schema]})
        assert list(resource.subresources()) == [
            DRAFT202012.create_resource(schema),
        ]

    def test_anchors_delegates_to_specification(self):
        resource = ID_AND_CHILDREN.create_resource(
            {"anchors": {"foo": {}, "bar": 1, "baz": ""}},
        )
        assert list(resource.anchors()) == [
            Anchor(name="foo", resource=ID_AND_CHILDREN.create_resource({})),
            Anchor(name="bar", resource=ID_AND_CHILDREN.create_resource(1)),
            Anchor(name="baz", resource=ID_AND_CHILDREN.create_resource("")),
        ]

    def test_pointer_to_mapping(self):
        resource = Resource.opaque(contents={"foo": "baz"})
        resolver = Registry().resolver()
        assert resource.pointer("/foo", resolver=resolver).contents == "baz"

    def test_pointer_to_array(self):
        resource = Resource.opaque(contents={"foo": {"bar": [3]}})
        resolver = Registry().resolver()
        assert resource.pointer("/foo/bar/0", resolver=resolver).contents == 3

    def test_root_pointer(self):
        contents = {"foo": "baz"}
        resource = Resource.opaque(contents=contents)
        resolver = Registry().resolver()
        assert resource.pointer("", resolver=resolver).contents == contents

    def test_opaque(self):
        contents = {"foo": "bar"}
        assert Resource.opaque(contents) == Resource(
            contents=contents,
            specification=Specification.OPAQUE,
        )


class TestResolver:
    def test_lookup_exact_uri(self):
        resource = Resource.opaque(contents={"foo": "baz"})
        resolver = Registry({"http://example.com/1": resource}).resolver()
        resolved = resolver.lookup("http://example.com/1")
        assert resolved.contents == resource.contents

    def test_lookup_subresource(self):
        root = ID_AND_CHILDREN.create_resource(
            {
                "ID": "http://example.com/",
                "children": [
                    {"ID": "http://example.com/a", "foo": 12},
                ],
            },
        )
        registry = root @ Registry()
        resolved = registry.resolver().lookup("http://example.com/a")
        assert resolved.contents == {"ID": "http://example.com/a", "foo": 12}

    def test_lookup_anchor_with_id(self):
        root = ID_AND_CHILDREN.create_resource(
            {
                "ID": "http://example.com/",
                "anchors": {"foo": 12},
            },
        )
        registry = root @ Registry()
        resolved = registry.resolver().lookup("http://example.com/#foo")
        assert resolved.contents == 12

    def test_lookup_anchor_without_id(self):
        root = ID_AND_CHILDREN.create_resource({"anchors": {"foo": 12}})
        resolver = Registry().with_resource("urn:example", root).resolver()
        resolved = resolver.lookup("urn:example#foo")
        assert resolved.contents == 12

    def test_lookup_unknown_reference(self):
        resolver = Registry().resolver()
        ref = "http://example.com/does/not/exist"
        with pytest.raises(exceptions.Unresolvable) as e:
            resolver.lookup(ref)
        assert e.value == exceptions.Unresolvable(ref=ref)

    def test_lookup_non_existent_pointer(self):
        resource = Resource.opaque({"foo": {}})
        resolver = Registry({"http://example.com/1": resource}).resolver()
        ref = "http://example.com/1#/foo/bar"
        with pytest.raises(exceptions.Unresolvable) as e:
            resolver.lookup(ref)
        assert e.value == exceptions.PointerToNowhere(
            ref="/foo/bar",
            resource=resource,
        )
        assert str(e.value) == "'/foo/bar' does not exist within {'foo': {}}"

    def test_lookup_non_existent_pointer_to_array_index(self):
        resource = Resource.opaque([1, 2, 4, 8])
        resolver = Registry({"http://example.com/1": resource}).resolver()
        ref = "http://example.com/1#/10"
        with pytest.raises(exceptions.Unresolvable) as e:
            resolver.lookup(ref)
        assert e.value == exceptions.PointerToNowhere(
            ref="/10",
            resource=resource,
        )

    def test_lookup_pointer_to_empty_string(self):
        resolver = Registry().resolver_with_root(Resource.opaque({"": {}}))
        assert resolver.lookup("#/").contents == {}

    def test_lookup_non_existent_pointer_to_empty_string(self):
        resource = Resource.opaque({"foo": {}})
        resolver = Registry().resolver_with_root(resource)
        with pytest.raises(
            exceptions.Unresolvable,
            match="^'/' does not exist within {'foo': {}}.*'#'",
        ) as e:
            resolver.lookup("#/")
        assert e.value == exceptions.PointerToNowhere(
            ref="/",
            resource=resource,
        )

    def test_lookup_non_existent_anchor(self):
        root = ID_AND_CHILDREN.create_resource({"anchors": {}})
        resolver = Registry().with_resource("urn:example", root).resolver()
        resolved = resolver.lookup("urn:example")
        assert resolved.contents == root.contents

        ref = "urn:example#noSuchAnchor"
        with pytest.raises(exceptions.Unresolvable) as e:
            resolver.lookup(ref)
        assert "'noSuchAnchor' does not exist" in str(e.value)
        assert e.value == exceptions.NoSuchAnchor(
            ref="urn:example",
            resource=root,
            anchor="noSuchAnchor",
        )

    def test_lookup_invalid_JSON_pointerish_anchor(self):
        resolver = Registry().resolver_with_root(
            ID_AND_CHILDREN.create_resource(
                {
                    "ID": "http://example.com/",
                    "foo": {"bar": 12},
                },
            ),
        )

        valid = resolver.lookup("#/foo/bar")
        assert valid.contents == 12

        with pytest.raises(exceptions.InvalidAnchor) as e:
            resolver.lookup("#foo/bar")
        assert " '#/foo/bar'" in str(e.value)

    def test_lookup_retrieved_resource(self):
        resource = Resource.opaque(contents={"foo": "baz"})
        resolver = Registry(retrieve=lambda uri: resource).resolver()
        resolved = resolver.lookup("http://example.com/")
        assert resolved.contents == resource.contents

    def test_lookup_failed_retrieved_resource(self):
        """
        Unretrievable exceptions are also wrapped in Unresolvable.
        """

        uri = "http://example.com/"

        registry = Registry(retrieve=blow_up)
        with pytest.raises(exceptions.Unretrievable):
            registry.get_or_retrieve(uri)

        resolver = registry.resolver()
        with pytest.raises(exceptions.Unresolvable):
            resolver.lookup(uri)

    def test_repeated_lookup_from_retrieved_resource(self):
        """
        A (custom-)retrieved resource is added to the registry returned by
        looking it up.
        """
        resource = Resource.opaque(contents={"foo": "baz"})
        once = [resource]

        def retrieve(uri):
            return once.pop()

        resolver = Registry(retrieve=retrieve).resolver()
        resolved = resolver.lookup("http://example.com/")
        assert resolved.contents == resource.contents

        resolved = resolved.resolver.lookup("http://example.com/")
        assert resolved.contents == resource.contents

    def test_repeated_anchor_lookup_from_retrieved_resource(self):
        resource = Resource.opaque(contents={"foo": "baz"})
        once = [resource]

        def retrieve(uri):
            return once.pop()

        resolver = Registry(retrieve=retrieve).resolver()
        resolved = resolver.lookup("http://example.com/")
        assert resolved.contents == resource.contents

        resolved = resolved.resolver.lookup("#")
        assert resolved.contents == resource.contents

    # FIXME: The tests below aren't really representable in the current
    #        suite, though we should probably think of ways to do so.

    def test_in_subresource(self):
        root = ID_AND_CHILDREN.create_resource(
            {
                "ID": "http://example.com/",
                "children": [
                    {
                        "ID": "child/",
                        "children": [{"ID": "grandchild"}],
                    },
                ],
            },
        )
        registry = root @ Registry()

        resolver = registry.resolver()
        first = resolver.lookup("http://example.com/")
        assert first.contents == root.contents

        with pytest.raises(exceptions.Unresolvable):
            first.resolver.lookup("grandchild")

        sub = first.resolver.in_subresource(
            ID_AND_CHILDREN.create_resource(first.contents["children"][0]),
        )
        second = sub.lookup("grandchild")
        assert second.contents == {"ID": "grandchild"}

    def test_in_pointer_subresource(self):
        root = ID_AND_CHILDREN.create_resource(
            {
                "ID": "http://example.com/",
                "children": [
                    {
                        "ID": "child/",
                        "children": [{"ID": "grandchild"}],
                    },
                ],
            },
        )
        registry = root @ Registry()

        resolver = registry.resolver()
        first = resolver.lookup("http://example.com/")
        assert first.contents == root.contents

        with pytest.raises(exceptions.Unresolvable):
            first.resolver.lookup("grandchild")

        second = first.resolver.lookup("#/children/0")
        third = second.resolver.lookup("grandchild")
        assert third.contents == {"ID": "grandchild"}

    def test_dynamic_scope(self):
        one = ID_AND_CHILDREN.create_resource(
            {
                "ID": "http://example.com/",
                "children": [
                    {
                        "ID": "child/",
                        "children": [{"ID": "grandchild"}],
                    },
                ],
            },
        )
        two = ID_AND_CHILDREN.create_resource(
            {
                "ID": "http://example.com/two",
                "children": [{"ID": "two-child/"}],
            },
        )
        registry = [one, two] @ Registry()

        resolver = registry.resolver()
        first = resolver.lookup("http://example.com/")
        second = first.resolver.lookup("#/children/0")
        third = second.resolver.lookup("grandchild")
        fourth = third.resolver.lookup("http://example.com/two")
        assert list(fourth.resolver.dynamic_scope()) == [
            ("http://example.com/child/grandchild", fourth.resolver._registry),
            ("http://example.com/child/", fourth.resolver._registry),
            ("http://example.com/", fourth.resolver._registry),
        ]
        assert list(third.resolver.dynamic_scope()) == [
            ("http://example.com/child/", third.resolver._registry),
            ("http://example.com/", third.resolver._registry),
        ]
        assert list(second.resolver.dynamic_scope()) == [
            ("http://example.com/", second.resolver._registry),
        ]
        assert list(first.resolver.dynamic_scope()) == []


class TestSpecification:
    def test_create_resource(self):
        specification = Specification(
            name="",
            id_of=lambda contents: "urn:fixedID",
            subresources_of=lambda contents: [],
            anchors_in=lambda specification, contents: [],
            maybe_in_subresource=(
                lambda segments, resolver, subresource: resolver
            ),
        )
        resource = specification.create_resource(contents={"foo": "baz"})
        assert resource == Resource(
            contents={"foo": "baz"},
            specification=specification,
        )
        assert resource.id() == "urn:fixedID"

    def test_detect_from_json_schema(self):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
        specification = Specification.detect(schema)
        assert specification == DRAFT202012

    def test_detect_with_no_discernible_information(self):
        with pytest.raises(exceptions.CannotDetermineSpecification):
            Specification.detect({"foo": "bar"})

    def test_detect_with_non_URI_schema(self):
        with pytest.raises(exceptions.CannotDetermineSpecification):
            Specification.detect({"$schema": 37})

    def test_detect_with_no_discernible_information_and_default(self):
        specification = Specification.OPAQUE.detect({"foo": "bar"})
        assert specification is Specification.OPAQUE

    def test_detect_unneeded_default(self):
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema"}
        specification = Specification.OPAQUE.detect(schema)
        assert specification == DRAFT202012

    def test_non_mapping_detect(self):
        with pytest.raises(exceptions.CannotDetermineSpecification):
            Specification.detect(True)

    def test_non_mapping_detect_with_default(self):
        specification = ID_AND_CHILDREN.detect(True)
        assert specification is ID_AND_CHILDREN

    def test_detect_with_fallback(self):
        specification = Specification.OPAQUE.detect({"foo": "bar"})
        assert specification is Specification.OPAQUE

    def test_repr(self):
        assert (
            repr(ID_AND_CHILDREN) == "<Specification name='id-and-children'>"
        )


class TestOpaqueSpecification:
    THINGS = [{"foo": "bar"}, True, 37, "foo", object()]

    @pytest.mark.parametrize("thing", THINGS)
    def test_no_id(self, thing):
        """
        An arbitrary thing has no ID.
        """

        assert Specification.OPAQUE.id_of(thing) is None

    @pytest.mark.parametrize("thing", THINGS)
    def test_no_subresources(self, thing):
        """
        An arbitrary thing has no subresources.
        """

        assert list(Specification.OPAQUE.subresources_of(thing)) == []

    @pytest.mark.parametrize("thing", THINGS)
    def test_no_anchors(self, thing):
        """
        An arbitrary thing has no anchors.
        """

        assert list(Specification.OPAQUE.anchors_in(thing)) == []


@pytest.mark.parametrize(
    "cls",
    [Anchor, Registry, Resource, Specification, exceptions.PointerToNowhere],
)
def test_nonsubclassable(cls):
    with pytest.raises(Exception, match="(?i)subclassing"):

        class Boom(cls):  # pragma: no cover
            pass
