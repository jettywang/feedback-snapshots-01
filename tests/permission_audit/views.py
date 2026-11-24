"""
Audited ViewSet.

Three routing situations are exercised here, all produced by a real
router registration (see urls.py):

1. ``reports/`` -- ONE url pattern whose method map binds GET (public read,
   ``list``) and POST (restricted write, ``submit_report``). DRF forbids
   ``@action`` on the reserved ``list`` name, so ``SharedCollectionRouter``
   emits the merged Route via the same ``ViewSet.as_view`` call the router
   uses internally. One Route carries one ``permission_classes`` list, so
   the shared policy branches on HTTP method instead of per-handler classes.
2. ``reports/{pk}/`` -- the default-inherited detail route (retrieve / update
   / partial_update / destroy), guarded only by the class-level policy. Each
   handler calls ``self.get_object()`` so the object layer runs.
3. ``reports/{pk}/publish/`` -- a detail extra action that loads the object
   itself with ``get_object_or_404`` instead of ``self.get_object()``, so
   ``check_object_permissions`` is never evaluated; ``archive`` is the
   control case that does call ``self.get_object()``.
"""
from django.shortcuts import get_object_or_404
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Report
from .permissions import (
    TracingAllowAny,
    TracingIsStaff,
    TracingPublicReadAuthenticatedWrite,
)

# Records every business-method entry so tests can prove whether the handler
# received the object and which handler actually ran for a given HTTP method.
BUSINESS_CALL_LOG = []


def reset_business_log():
    BUSINESS_CALL_LOG.clear()


class ReportViewSet(viewsets.GenericViewSet):
    """
    Class default = AllowAny. This is the deliberately permissive baseline
    that the rollout checklist in README.md tightens step by step.
    """

    queryset = Report.objects.all()

    # Class-level default. Every route inherits this unless an @action passes
    # its own ``permission_classes`` kwarg, which overrides it per route.
    permission_classes = [TracingAllowAny]

    # ------------------------------------------------------------------
    # Same-URL collection route: GET public read, POST restricted write.
    # ``list`` is a plain handler (bound to GET on ^reports/$); the router
    # subclass in urls.py merges POST -> ``submit_report`` into the same
    # pattern and supplies the action-level permission_classes override.
    def list(self, request, *args, **kwargs):
        BUSINESS_CALL_LOG.append({
            'handler': 'list',
            'got_object': False,
            'kwargs': dict(kwargs),
        })
        data = [{'id': report.pk, 'title': report.title}
                for report in self.get_queryset()]
        return Response(data)

    def submit_report(self, request, *args, **kwargs):
        # Restricted sibling on the SAME url pattern, merged by the router
        # subclass in urls.py. The shared permission policy distinguishes
        # GET vs POST via HTTP method.
        BUSINESS_CALL_LOG.append({
            'handler': 'submit_report',
            'got_object': False,
            'kwargs': dict(kwargs),
        })
        report = Report.objects.create(title=request.data.get('title', 'new'))
        return Response({'id': report.pk}, status=201)

    # ------------------------------------------------------------------
    # Default-inherited detail route: retrieve / update / destroy rely on
    # self.get_object(), which runs check_object_permissions().
    # ------------------------------------------------------------------
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        BUSINESS_CALL_LOG.append({
            'handler': 'retrieve',
            'got_object': True,
            'obj_pk': instance.pk,
            'kwargs': dict(kwargs),
        })
        return Response({'id': instance.pk, 'title': instance.title})

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        BUSINESS_CALL_LOG.append({
            'handler': 'partial_update' if partial else 'update',
            'got_object': True,
            'obj_pk': instance.pk,
            'kwargs': dict(kwargs),
        })
        instance.title = request.data.get('title', instance.title)
        instance.save()
        return Response({'id': instance.pk, 'title': instance.title})

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        BUSINESS_CALL_LOG.append({
            'handler': 'destroy',
            'got_object': True,
            'obj_pk': instance.pk,
            'kwargs': dict(kwargs),
        })
        instance.delete()
        return Response(status=204)

    # ------------------------------------------------------------------
    # Detail extra action that loads the object ITSELF with get_object_or_404
    # instead of self.get_object(). Result: check_object_permissions() is
    # never called, so has_object_permission is silently skipped even though
    # a staff policy is declared on the action.
    # ------------------------------------------------------------------
    @action(
        detail=True,
        methods=['post'],
        permission_classes=[TracingIsStaff],
    )
    def publish(self, request, *args, **kwargs):
        instance = get_object_or_404(self.get_queryset(), pk=kwargs['pk'])
        BUSINESS_CALL_LOG.append({
            'handler': 'publish',
            'got_object': True,
            'obj_pk': instance.pk,
            'loaded_via': 'get_object_or_404',
            'kwargs': dict(kwargs),
        })
        instance.confidential = False
        instance.save()
        return Response({'id': instance.pk, 'published': True})

    # Contrast action: same staff policy, but goes through self.get_object()
    # so the object-level check really runs.
    @action(
        detail=True,
        methods=['post'],
        permission_classes=[TracingIsStaff],
    )
    def archive(self, request, *args, **kwargs):
        instance = self.get_object()
        BUSINESS_CALL_LOG.append({
            'handler': 'archive',
            'got_object': True,
            'obj_pk': instance.pk,
            'loaded_via': 'self.get_object',
            'kwargs': dict(kwargs),
        })
        return Response({'id': instance.pk, 'archived': True})
