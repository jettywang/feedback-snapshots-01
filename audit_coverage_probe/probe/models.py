from django.db import models


class Item(models.Model):
    name = models.CharField(max_length=50)


class ItemProxy(Item):
    class Meta:
        proxy = True


class Base(models.Model):
    base_field = models.CharField(max_length=50)


class Child(Base):
    child_field = models.CharField(max_length=50)


class Tag(models.Model):
    label = models.CharField(max_length=50)


class Article(models.Model):
    title = models.CharField(max_length=50)
    tags = models.ManyToManyField(Tag)


class Excluded(models.Model):
    note = models.CharField(max_length=50)


class Secret(models.Model):
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=50)
