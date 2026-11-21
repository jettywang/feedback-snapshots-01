import copy
import itertools
import pickle

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
)


@pytest.mark.parametrize("one, two", pairs(each() for each in thunks))
def test_eq_incompatible_types(one, two):
    assert one != two


@pytest.mark.parametrize("thunk", thunks)
def test_hash(thunk):
    assert thunk() in {thunk()}  # noqa: FURB171


class TestResolutionFailure:
    @pytest.mark.parametrize(
        "error, stage, category",
        [
            (
                exceptions.Unresolvable("urn:example:foo"),
                exceptions.ResolutionStage.RETRIEVAL,
                exceptions.FailureCategory.RETRIEVAL_UNAVAILABLE,
            ),
            (
                exceptions.Unretrievable("urn:example:foo"),
                exceptions.ResolutionStage.RETRIEVAL,
                exceptions.FailureCategory.RETRIEVAL_UNAVAILABLE,
            ),
            (
                exceptions.PointerToNowhere(
                    resource=TRUE,
                    ref="/foo",
                ),
                exceptions.ResolutionStage.POINTER,
                exceptions.FailureCategory.POINTER_NOT_FOUND,
            ),
            (
                exceptions.NoSuchAnchor(
                    resource=TRUE,
                    anchor="foo",
                    ref="a#b",
                ),
                exceptions.ResolutionStage.ANCHOR,
                exceptions.FailureCategory.ANCHOR_NOT_FOUND,
            ),
            (
                exceptions.InvalidAnchor(
                    resource=TRUE,
                    anchor="foo",
                    ref="a#b",
                ),
                exceptions.ResolutionStage.ANCHOR,
                exceptions.FailureCategory.ANCHOR_NOT_FOUND,
            ),
        ],
    )
    def test_from_exception(self, error, stage, category):
        failure = exceptions.ResolutionFailure.from_exception(error)
        assert failure.category is category
        assert failure.stage is stage
        assert failure.original is error
        assert failure.__cause__ is error

    def test_from_exception_follows_cause_chain(self):
        inner = exceptions.Unretrievable("urn:example:foo")
        outer = exceptions.Unresolvable("urn:example:foo")

        try:
            try:
                raise inner
            except exceptions.Unretrievable as caused:
                raise outer from caused
        except exceptions.Unresolvable as error:
            failure = exceptions.ResolutionFailure.from_exception(error)

        assert failure.stage is exceptions.ResolutionStage.RETRIEVAL
        assert failure.__cause__ is outer
    def test_from_exception_rejects_unknown(self):
        with pytest.raises(TypeError, match="ValueError"):
            exceptions.ResolutionFailure.from_exception(ValueError("boom"))

    def test_from_exception_with_explicit_stage(self):
        error = ValueError("boom")
        failure = exceptions.ResolutionFailure.from_exception(
            error,
            stage=exceptions.ResolutionStage.ANCHOR,
        )
        assert failure.category is exceptions.FailureCategory.ANCHOR_NOT_FOUND
        assert failure.stage is exceptions.ResolutionStage.ANCHOR
        assert failure.__cause__ is error

    def test_specification_failure_is_retrieval_category(self):
        error = exceptions.CannotDetermineSpecification(TRUE)
        failure = exceptions.ResolutionFailure.from_exception(error)
        assert failure.category is (
            exceptions.FailureCategory.RETRIEVAL_UNAVAILABLE
        )
        assert failure.stage is exceptions.ResolutionStage.SPECIFICATION

    def test_message_omits_details(self):
        error = exceptions.NoSuchAnchor(
            resource=TRUE,
            anchor="customer-codename",
            ref="urn:customer:codename",
        )
        failure = exceptions.ResolutionFailure.from_exception(error)
        assert str(failure) == "anchor_not_found"
        assert "customer" not in repr(failure)
        assert "customer" not in str(failure.args)

    def test_equality_and_hash(self):
        error = ValueError("boom")
        one = exceptions.ResolutionFailure(
            category=exceptions.FailureCategory.POINTER_NOT_FOUND,
            stage=exceptions.ResolutionStage.POINTER,
            original=error,
        )
        two = exceptions.ResolutionFailure(
            category=exceptions.FailureCategory.POINTER_NOT_FOUND,
            stage=exceptions.ResolutionStage.POINTER,
        )
        assert one == two
        assert hash(one) == hash(two)

    def test_inequality(self):
        one = exceptions.ResolutionFailure(
            category=exceptions.FailureCategory.POINTER_NOT_FOUND,
            stage=exceptions.ResolutionStage.POINTER,
        )
        two = exceptions.ResolutionFailure(
            category=exceptions.FailureCategory.ANCHOR_NOT_FOUND,
            stage=exceptions.ResolutionStage.ANCHOR,
        )
        assert one != two
        assert one != "pointer_not_found"

    @pytest.mark.parametrize("copying", [copy.copy, copy.deepcopy])
    def test_copy_omits_original(self, copying):
        failure = exceptions.ResolutionFailure(
            category=exceptions.FailureCategory.ANCHOR_NOT_FOUND,
            stage=exceptions.ResolutionStage.ANCHOR,
            original=ValueError("customer codename"),
        )

        copied = copying(failure)
        assert copied.category is failure.category
        assert copied.stage is failure.stage
        assert copied.__cause__ is None
        assert "codename" not in str(copied)

    def test_pickle_omits_original(self):
        failure = exceptions.ResolutionFailure(
            category=exceptions.FailureCategory.ANCHOR_NOT_FOUND,
            stage=exceptions.ResolutionStage.ANCHOR,
            original=ValueError("customer codename"),
        )

        data = pickle.dumps(failure)
        assert b"codename" not in data

        unpickled = pickle.loads(data)
        assert unpickled.category is failure.category
        assert unpickled.stage is failure.stage
        assert unpickled.__cause__ is None
