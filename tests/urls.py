from django.urls import include, path

urlpatterns = [
    path('api/field-visibility/', include('tests.field_visibility_demo.urls')),
]
