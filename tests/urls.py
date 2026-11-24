from django.urls import include, path

urlpatterns = [
    path('employee/', include('tests.employee.urls')),
]
