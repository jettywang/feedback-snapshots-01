from django.urls import path, re_path

from sesame.capabilities import Capability, require_capability
from sesame.decorators import authenticate
from sesame.views import LoginView

from .views import show_capability, show_user

# Two distinct, action-scoped verification contracts. Neither creates a
# session: each only authorizes its own business action.
view_quote = Capability("quote:view")
accept_quote = Capability("quote:accept")

urlpatterns = [
    # For test_decorators.TestAuthenticate
    path("authenticate/", authenticate(show_user)),
    path("authenticate/not_required/", authenticate(required=False)(show_user)),
    path("authenticate/permanent/", authenticate(permanent=True)(show_user)),
    path("authenticate/no_override/", authenticate(override=False)(show_user)),
    path("authenticate/scope/", authenticate(scope="scope")(show_user)),
    re_path(
        r"authenticate/scope/arg/([a-z]+)/",
        authenticate(scope="arg:{}")(show_user),
    ),
    re_path(
        r"authenticate/scope/kwarg/(?P<kwarg>[a-z]+)/",
        authenticate(scope="kwarg:{kwarg}")(show_user),
    ),
    # For test_views.TestLoginView — a normal, session-establishing login link.
    path("login/", LoginView.as_view()),
    path("login/no_redirect/", LoginView.as_view(next_page=None)),
    # For test_capabilities — two business routes protected by capabilities.
    path("quote/view/", view_quote.require(show_capability)),
    path("quote/accept/", accept_quote.require(show_capability)),
    # Same, using the function-style contract factory.
    path(
        "quote/confirm/<int:quote_id>/",
        require_capability("quote:confirm:{quote_id}")(show_capability),
    ),
    # For test_middleware.TestMiddleware
    re_path("", show_user),  # catchall pattern
]
