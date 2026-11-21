import itertools

import pytest

from referencing import Resource, exceptions


def pairs(choices):
    return sorted(
        itertools.combinations(choices, 2),
        key=lambda error: str(type(error)),
    )


TRUE = Resource.opaque(True)


thunks = (
    lambda: exceptions.CannotDetermineSpecification(TRUE),
    lambda: exceptions.NoSuchResource("urn:example:foo"),
    lambda: exceptions.NoInternalID(TRUE),
    lambda: exceptions.InvalidAnchor(resource=TRUE, anchor="foo", ref="a#b"),
    lambda: exceptions.NoSuchAnchor(resource=TRUE, anchor="foo", ref="a#b"),
    lambda: exceptions.PointerToNowhere(resource=TRUE, ref="urn:example:foo"),
    lambda: exceptions.Unresolvable("urn:example:foo"),
    lambda: exceptions.Unretrievable("urn:example:foo"),
    lambda: exceptions.RetrievalDenied(
        ref="urn:example:target",
        source="platform.example",
        target="untrusted.example",
    ),
)


@pytest.mark.parametrize("one, two", pairs(each() for each in thunks))
def test_eq_incompatible_types(one, two):
    assert one != two


@pytest.mark.parametrize("thunk", thunks)
def test_hash(thunk):
    assert thunk() in {thunk()}  # noqa: FURB171


def test_retrieval_denied_is_a_no_such_resource():
    denied = exceptions.RetrievalDenied(
        ref="urn:example:target",
        source="platform.example",
        target="untrusted.example",
    )
    assert isinstance(denied, exceptions.NoSuchResource)


def test_retrieval_denied_equality_includes_all_fields():
    denied = exceptions.RetrievalDenied(
        ref="urn:example:target",
        source="platform.example",
        target="untrusted.example",
    )
    assert denied == exceptions.RetrievalDenied(
        ref="urn:example:target",
        source="platform.example",
        target="untrusted.example",
    )
    assert denied != exceptions.RetrievalDenied(
        ref="urn:example:target",
        source="partner.example",
        target="untrusted.example",
    )


def test_retrieval_denied_message():
    denied = exceptions.RetrievalDenied(
        ref="https://untrusted.example/schema",
        source="platform.example",
        target="untrusted.example",
    )
    message = str(denied)
    assert "untrusted.example" in message
    assert "platform.example" in message
    assert "trust policy" in message


def test_retrieval_denied_message_with_reason():
    denied = exceptions.RetrievalDenied(
        ref="https://untrusted.example/schema",
        source="platform.example",
        target="untrusted.example",
        reason="partner is suspended",
    )
    assert str(denied).endswith("partner is suspended")
