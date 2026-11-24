from rest_framework.routers import SimpleRouter

from tests.employee.views import EmployeeRecordViewSet, ProjectViewSet

router = SimpleRouter()
router.register('projects', ProjectViewSet, basename='project')
router.register('employee-records', EmployeeRecordViewSet, basename='employee-record')

urlpatterns = router.urls
