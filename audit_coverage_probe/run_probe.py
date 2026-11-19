import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

import django

django.setup()

from django.db import connection, models
from django.db.models.signals import post_delete, post_save, pre_save

from auditlog.models import LogEntry
from auditlog.registry import auditlog
from probe.models import (
    Article,
    Base,
    Child,
    Excluded,
    Item,
    ItemProxy,
    Secret,
    Tag,
)

print("=" * 70)
print("A. 注册表快照 (auditlog.get_models())")
print("=" * 70)
for m in auditlog.get_models():
    opts = auditlog._registry[m]
    print(
        f"  {m._meta.label:35s} proxy={m._meta.proxy!s:5s} "
        f"auto_created={m._meta.auto_created!s:5s} "
        f"m2m_fields={sorted(opts['m2m_fields'])} "
        f"exclude_fields={opts['exclude_fields']}"
    )
print(f"\n  ItemProxy in registry : {auditlog.contains(ItemProxy)}")
print(f"  Excluded  in registry : {auditlog.contains(Excluded)}")
print(f"  Through   in registry : {auditlog.contains(Article.tags.through)}")

print()
print("=" * 70)
print("B. 信号连接快照 (可观察信号)")
print("=" * 70)
def exact_receivers(sig, model):
    # receivers 条目为 (lookup_key, weakref, is_async), lookup_key[1] 是 sender 的 id
    return [k for k, *_ in sig.receivers if k[1] == id(model)]


for model in [Item, ItemProxy, Base, Child, Article, Tag, Excluded, Secret, Article.tags.through]:
    n_post = len(exact_receivers(post_save, model))
    n_pre = len(exact_receivers(pre_save, model))
    n_del = len(exact_receivers(post_delete, model))
    print(
        f"  sender={model._meta.label:25s} "
        f"post_save={n_post} pre_save={n_pre} post_delete={n_del}"
    )

print()
print("=" * 70)
print("C. 行为实验 (每个动作后打印新增 LogEntry)")
print("=" * 70)


def snapshot():
    return set(LogEntry.objects.values_list("pk", flat=True))


def report(label, before):
    new = LogEntry.objects.exclude(pk__in=before).order_by("pk")
    print(f"\n--- {label} -> {new.count()} 条 LogEntry")
    for e in new:
        print(
            f"    [{e.pk}] ct={e.content_type.app_label}.{e.content_type.model} "
            f"action={e.get_action_display()} obj_pk={e.object_pk} "
            f"changes={e.changes}"
        )


b = snapshot()
it = Item.objects.create(name="x")
report("Item.create", b)
b = snapshot()
it.name = "y"
it.save()
report("Item.update", b)
b = snapshot()
it.delete()
report("Item.delete", b)

b = snapshot()
p = ItemProxy.objects.create(name="px")
report("ItemProxy.create (经代理保存)", b)
b = snapshot()
p.name = "py"
p.save()
report("ItemProxy.update (经代理保存)", b)
b = snapshot()
Item.objects.filter(pk=p.pk).update(name="pz")
report("Item queryset.update (对照: 无信号)", b)

b = snapshot()
c = Child.objects.create(base_field="b1", child_field="c1")
report("Child.create (MTI)", b)
b = snapshot()
c.child_field = "c2"
c.save()
report("Child.update (MTI)", b)
b = snapshot()
c.delete()
report("Child.delete (MTI)", b)

b = snapshot()
t = Tag.objects.create(label="t1")
a = Article.objects.create(title="a1")
report("Tag.create + Article.create", b)
b = snapshot()
a.tags.add(t)
report("Article.tags.add (m2m)", b)
b = snapshot()
a.tags.remove(t)
report("Article.tags.remove (m2m)", b)

b = snapshot()
e = Excluded.objects.create(note="n1")
e.note = "n2"
e.save()
e.delete()
report("Excluded create+update+delete (排除模型)", b)

b = snapshot()
s = Secret.objects.create(username="u1", password="pw1")
report("Secret.create (exclude_fields=[password])", b)
b = snapshot()
s.password = "pw2"
s.username = "u2"
s.save()
report("Secret.update (password 应不出现在 changes)", b)

print()
print("=" * 70)
print("D. 运行时注册的模型")
print("=" * 70)


def make_runtime_model():
    class RuntimeModel(models.Model):
        note = models.CharField(max_length=50)

        class Meta:
            app_label = "probe"
            db_table = "probe_runtimemodel"

    return RuntimeModel


RuntimeModel = make_runtime_model()
with connection.schema_editor() as se:
    se.execute("DROP TABLE IF EXISTS probe_runtimemodel")
    se.create_model(RuntimeModel)

print(f"  contains(RuntimeModel) 注册前: {auditlog.contains(RuntimeModel)}")
b = snapshot()
RuntimeModel.objects.create(note="r1")
report("RuntimeModel.create (未注册)", b)

auditlog.register(RuntimeModel)
print(f"  contains(RuntimeModel) 注册后: {auditlog.contains(RuntimeModel)}")
b = snapshot()
RuntimeModel.objects.create(note="r2")
report("RuntimeModel.create (运行时 register 后)", b)

auditlog.unregister(RuntimeModel)
b = snapshot()
RuntimeModel.objects.create(note="r3")
report("RuntimeModel.create (unregister 后)", b)

print()
print("=" * 70)
print("E. 全量 LogEntry 汇总 (content_type x action)")
print("=" * 70)
from django.db.models import Count

for row in (
    LogEntry.objects.values("content_type__app_label", "content_type__model", "action")
    .annotate(n=Count("id"))
    .order_by("content_type__model", "action")
):
    print(
        f"  {row['content_type__app_label']}.{row['content_type__model']:20s} "
        f"action={row['action']} n={row['n']}"
    )
