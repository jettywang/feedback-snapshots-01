"""
Router binding for the audited ViewSet.

The detail routes are produced by a normal SimpleRouter registration.
The collection route needs GET (public) and POST (restricted) on the SAME
url pattern. DRF forbids decorating the reserved ``list`` name with
``@action`` and the default list Route only maps GET, so a small router
subclass replaces that Route with one built through the same
``ViewSet.as_view(action_map, **initkwargs)`` machinery the router itself
uses -- now binding both HTTP methods and carrying the action-level
``permission_classes`` override.
"""
from rest_framework.routers import Route, SimpleRouter

from .permissions import TracingPublicReadAuthenticatedWrite
from .views import ReportViewSet


class SharedCollectionRouter(SimpleRouter):
    """Router that emits one collection pattern mapping GET and POST."""

    def get_routes(self, viewset):
        routes = super().get_routes(viewset)
        merged = Route(
            url=r'^{prefix}{trailing_slash}$',
            mapping={
                'get': 'list',
                'post': 'submit_report',
            },
            name='{basename}-list',
            detail=False,
            initkwargs={
                'suffix': 'List',
                'permission_classes': [TracingPublicReadAuthenticatedWrite],
            },
        )
        # Swap the stock list Route (get->list/post->create) for the merged
        # one; every other Route (detail + dynamic actions) is untouched.
        return [merged if (isinstance(route, Route) and not route.detail)
                else route for route in routes]


router = SharedCollectionRouter()
router.register('reports', ReportViewSet, basename='report')

urlpatterns = router.urls
