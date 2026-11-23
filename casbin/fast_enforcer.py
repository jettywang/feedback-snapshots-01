import logging
from typing import Sequence

from casbin.attribute import AttributeView
from casbin.enforcer import Enforcer
from casbin.model import Model, FastModel, fast_policy_filter, FunctionMap
from casbin.persist.adapters import FileAdapter
from casbin.util.log import configure_logging


class FastEnforcer(Enforcer):
    _cache_key_order: Sequence[int] = None

    def __init__(
        self,
        model=None,
        adapter=None,
        enable_log=False,
        logging_config: dict = None,
        cache_key_order: Sequence[int] = None,
    ):
        self._cache_key_order = cache_key_order
        super().__init__(model, adapter, enable_log, logging_config)

    def new_model(self, path="", text=""):
        """creates a model."""
        if self._cache_key_order is None:
            m = Model()
        else:
            m = FastModel(self._cache_key_order)
        if len(path) > 0:
            m.load_model(path)
        else:
            m.load_model_from_text(text)

        return m

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        if self._split_attribute_inputs(rvals)[1] is not None:
            # A held view is a request, not a policy filter key: applying the
            # fast path here would derive keys from the view object instead.
            return self.enforce_with_attributes(*rvals)

        if self._cache_key_order is None:
            result, _ = self.enforce_ex(*rvals)
        else:
            keys = [rvals[x] for x in self._cache_key_order]
            with fast_policy_filter(self.model.model["p"]["p"].policy, *keys):
                result, _ = self.enforce_ex(*rvals)

        return result

    def enforce_ex_with_attributes(self, *rvals, attributes=None):
        """evaluates one request against one consistent attribute view.

        The policy filter and the matcher both read the same view.  Deriving
        the filter keys from the live objects while the matcher reads a captured
        value is exactly how a fast path can silently keep an old attribute, so
        the keys are taken from the view that is about to be evaluated: a change
        to the business object between the filter and the matcher cannot make
        the two disagree.
        """
        if self._cache_key_order is None:
            return super().enforce_ex_with_attributes(*rvals, attributes=attributes)
        return self._enforce_with_filter(rvals, attributes)

    def enforce_with_attributes(self, *rvals, attributes=None):
        """decides one request against a caller-supplied attribute view."""
        return self.enforce_ex_with_attributes(*rvals, attributes=attributes)[0]

    def enforce_with_attribute_view(self, *rvals, attributes=None):
        """alias of enforce_with_attributes()."""
        return self.enforce_with_attributes(*rvals, attributes=attributes)

    def enforce_ex_with_attribute_view(self, *rvals, attributes=None):
        """alias of enforce_ex_with_attributes()."""
        return self.enforce_ex_with_attributes(*rvals, attributes=attributes)

    def _enforce_with_filter(self, rvals, attributes):
        """evaluates the filtered policy, with filter keys from the view itself."""
        context, embedded, rvals = self._split_attribute_inputs(rvals)

        if attributes is None:
            view = embedded
        else:
            view = self._coerce_attribute_view(attributes)

        if view is None:
            view = AttributeView.capture(*rvals)
        elif rvals and len(view) != len(rvals):
            raise RuntimeError("invalid request size")

        rtype = context.rtype if context is not None else "r"
        tokens = self.model["r"][rtype].tokens
        if view.tokens != tuple(tokens):
            view = view.bind(tokens)

        # ``_cache_key_order`` indexes the request definition, and ``view`` has
        # just been bound to it, so a key is the captured value at that index.
        keys = [view[index] for index in self._cache_key_order]
        with fast_policy_filter(self.model.model["p"]["p"].policy, *keys):
            return self._evaluate_with_view(context, view)
