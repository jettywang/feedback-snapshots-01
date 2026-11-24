from .harness import ApprovalReceiptDemo, build_urlpatterns

demo = ApprovalReceiptDemo()
urlpatterns = build_urlpatterns(demo)
