"""
Schema 生成可见性 vs 真实 API 请求 对照演示（独立可运行，不依赖 DB）。

角色：
  anon     匿名
  partner  合作方用户（partner 组）
  admin    内部管理员（is_staff=True）

三组生成：public=True（管理命令模式）、带 partner 请求、带 admin 请求。
真实请求：每个 operation × 每个角色，走 DRF 完整 dispatch（认证+权限+对象权限）。
"""
import re
import sys
import types

# 离线环境缺少可选依赖，注入仅满足本演示的最小实现
_inf = types.ModuleType('inflection')
_inf.pluralize = lambda word: word + 's'
sys.modules.setdefault('inflection', _inf)

_uri = types.ModuleType('uritemplate')
_uri.variables = lambda tpl: re.findall(r'{(\w+)}', tpl)
sys.modules.setdefault('uritemplate', _uri)

import django
from django.conf import settings

settings.configure(
    DEBUG=True,
    DATABASES={},
    INSTALLED_APPS=['django.contrib.contenttypes', 'django.contrib.auth', 'rest_framework'],
    ROOT_URLCONF=__name__,
    SECRET_KEY='demo',
)
django.setup()

from django.contrib.auth.models import AnonymousUser
from django.urls import include, path
from rest_framework import permissions, routers, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.schemas.openapi import SchemaGenerator
from rest_framework.test import APIRequestFactory


# ---------- 权限：合作方 ----------
class IsPartnerOrAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if user.is_staff:
            return True
        return user.groups.filter(name='partner').exists()


class IsPartnerObject(BasePermission):
    """对象级权限：合作方只能访问 owner=partner 的对象；schema 阶段不会执行。"""
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        return obj['owner'] == 'partner'


# ---------- 数据 / 序列化 ----------
class ItemSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(max_length=50)


ITEMS = {1: {'id': 1, 'name': 'partner-item', 'owner': 'partner'},
         2: {'id': 2, 'name': 'internal-item', 'owner': 'staff'}}


# ---------- ViewSets ----------
class PublicViewSet(viewsets.ViewSet):
    """公开目录：AllowAny。"""
    permission_classes = [permissions.AllowAny]
    serializer_class = ItemSerializer

    def list(self, request):
        return Response([{'id': 1, 'name': 'catalog'}])

    def create(self, request):
        return Response({'id': 1}, status=status.HTTP_201_CREATED)


class ItemsViewSet(viewsets.ViewSet):
    """商品：合作方/管理员可读，写入仅管理员；retrieve 还叠加对象级权限。"""
    permission_classes = [IsPartnerOrAdmin, IsPartnerObject]

    def get_permissions(self):
        if self.action in ('create', 'update', 'partial_update', 'destroy'):
            return [permissions.IsAdminUser()]
        return super().get_permissions()

    def list(self, request):
        return Response(ITEMS.values())

    def retrieve(self, request, pk=None):
        item = ITEMS[int(pk)]
        self.check_object_permissions(request, item)  # 对象级权限，真实请求才跑
        return Response(item)

    def create(self, request):
        return Response({'id': 3}, status=status.HTTP_201_CREATED)

    def update(self, request, pk=None):
        return Response(ITEMS[int(pk)])

    def partial_update(self, request, pk=None):
        return Response(ITEMS[int(pk)])

    def destroy(self, request, pk=None):
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAdminUser])
    def bulk_reload(self, request):
        """内部维护动作：仅管理员。"""
        return Response({'reloaded': True})


class InternalViewSet(viewsets.ViewSet):
    """纯内部路由：IsAdminUser，任何合作方上下文都不应出现在对外 schema。"""
    permission_classes = [permissions.IsAdminUser]

    def list(self, request):
        return Response([{'secret': 1}])

    @action(detail=True, methods=['post'])
    def rotate_key(self, request, pk=None):
        return Response({'rotated': True})


class HiddenSchemaViewSet(viewsets.ViewSet):
    """通过 schema=None 在枚举阶段彻底剔除（与权限无关，public 模式也没有）。"""
    schema = None
    permission_classes = [permissions.AllowAny]

    def list(self, request):
        return Response([{'legacy': True}])


router = routers.SimpleRouter()
router.register('public', PublicViewSet, basename='public')
router.register('items', ItemsViewSet, basename='items')
router.register('internal', InternalViewSet, basename='internal')
router.register('legacy', HiddenSchemaViewSet, basename='legacy')
urlpatterns = [path('api/', include(router.urls))]


# ---------- 用户构造（不入库：仅实现权限类会访问的属性） ----------
class _GroupQuery:
    def __init__(self, names):
        self.names = set(names)

    def filter(self, name=None):
        class _Q:
            def exists(_self):
                return name in self.names
        return _Q()


class FakeUser:
    is_authenticated = True
    is_anonymous = False

    def __init__(self, is_staff=False, groups=()):
        self.is_staff = is_staff
        self.groups = _GroupQuery(groups)


def make_user(is_staff=False, groups=()):
    return FakeUser(is_staff=is_staff, groups=groups)


ROLES = {
    'anon': AnonymousUser(),
    'partner': make_user(groups=['partner']),
    'admin': make_user(is_staff=True),
}

factory = APIRequestFactory()


def build_request(method, path, user):
    django_req = getattr(factory, method.lower())(path, data={'name': 'x'}, format='json')
    req = Request(django_req)
    if not isinstance(user, AnonymousUser):
        django_req._force_auth_user = user  # 触发 ForcedAuthentication
    return req


# ---------- A. 三组 schema 生成 ----------
def gen(public, user=None):
    generator = SchemaGenerator(patterns=urlpatterns)
    request = None if public else build_request('get', '/api/', user)
    schema = generator.get_schema(request=request, public=public)
    return {(p, m.upper()): op['operationId'] for p, ms in schema['paths'].items() for m, op in ms.items()}


generated = {
    'public=True (管理命令/generateschema)': gen(True),
    'request=partner': gen(False, ROLES['partner']),
    'request=admin': gen(False, ROLES['admin']),
}


# ---------- B. 真实 API 请求矩阵 ----------
def real_call(method, path, view_kwargs=None):
    rows = {}
    for role, user in ROLES.items():
        req = build_request(method, path, user)
        # dispatch 需要 Django 原生 request；强制认证属性挂在底层 request 上，
        # initialize_request 重新包装时会识别 ForcedAuthentication
        from django.urls import resolve
        match = resolve(path)
        view = match.func
        try:
            resp = view(req._request, **(view_kwargs or {}))
            rows[role] = resp.status_code
        except Exception as exc:
            rows[role] = type(exc).__name__
    return rows


# 每个 operation 的真实请求探针
probes = [
    ('GET',    '/api/public/', None),
    ('POST',   '/api/public/', None),
    ('GET',    '/api/items/', None),
    ('POST',   '/api/items/', None),
    ('GET',    '/api/items/1/', {'pk': '1'}),   # partner 对象
    ('GET',    '/api/items/2/', {'pk': '2'}),   # staff 对象
    ('PUT',    '/api/items/1/', {'pk': '1'}),
    ('PATCH',  '/api/items/1/', {'pk': '1'}),
    ('DELETE', '/api/items/1/', {'pk': '1'}),
    ('POST',   '/api/items/bulk_reload/', None),
    ('GET',    '/api/internal/', None),
    ('POST',   '/api/internal/1/rotate_key/', {'pk': '1'}),
    ('GET',    '/api/legacy/', None),
]

real_matrix = {(m, p): real_call(m, p, kw) for m, p, kw in probes}


if __name__ == '__main__':
    # ---------- 输出 ----------
    def op_key(path, method):
        return (path, method)


    print('=' * 96)
    print('A. 三种生成上下文下，operation 是否进入 schema（operationId）')
    print('=' * 96)
    # 模板 operation（生成器产出）+ 枚举层硬剔除的路由（任何上下文都不进 schema）
    enum_excluded = [('/api/legacy/', 'GET')]
    all_ops = sorted({k for d in generated.values() for k in d} | set(enum_excluded))
    header = f"{'METHOD':7} {'PATH':34} | {'public':32} | {'partner ctx':32} | {'admin ctx':32}"
    print(header)
    print('-' * len(header))
    for path, method in sorted(all_ops, key=lambda x: (x[0], x[1])):
        cells = []
        for label, d in generated.items():
            cells.append(d.get((path, method), '— 隐藏 —'))
        print(f"{method:7} {path:34} | {cells[0]:32} | {cells[1]:32} | {cells[2]:32}")

    print()
    print('=' * 96)
    print('B. 真实 API 请求结果（HTTP 状态码 / 异常）对照')
    print('=' * 96)
    h2 = f"{'METHOD':7} {'PATH':34} | {'anon':18} | {'partner':18} | {'admin':18}"
    print(h2)
    print('-' * len(h2))
    for method, path, _ in probes:
        r = real_matrix[(method, path)]
        print(f"{method:7} {path:34} | {str(r['anon']):18} | {str(r['partner']):18} | {str(r['admin']):18}")

    print()
    print('=' * 96)
    print('C. 关键分歧：生成器结论 vs 合作方真实可达性（模板路径与具体探针归一化匹配）')
    print('=' * 96)


    def template_re(tpl):
        escaped = re.escape(tpl).replace('\\{', '{').replace('\\}', '}')
        return re.compile('^' + re.sub(r'\{\w+\}', '[^/]+', escaped) + '$')


    for label, d in generated.items():
        print(f'\n[{label}]')
        for (tpl, method), op_id in sorted(d.items()):
            rx = template_re(tpl)
            probe = next((v for (m, p), v in real_matrix.items() if m == method and rx.match(p)), None)
            partner_real = probe['partner'] if probe else 'n/a'
            print(f'  schema 可见 {method:6} {tpl:20} ({op_id:24}) -> partner 真实请求: {partner_real}')
