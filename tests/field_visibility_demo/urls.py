from django.urls import path

from .views import CaseRecordDetail, CaseRecordList

urlpatterns = [
    path('cases/', CaseRecordList.as_view(), name='case-list'),
    path('cases/<int:pk>/', CaseRecordDetail.as_view(), name='case-detail'),
]
