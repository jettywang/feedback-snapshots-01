from __future__ import annotations

from dissect.shellitem.lnk.lnk import Lnk, c_lnk
from dissect.shellitem.lnk.property_store import (
    PropertyStorage,
    PropertyStore,
    PropertyType,
    PropertyValue,
    SerializedPropertyStorage,
    SerializedPropertyStore,
    SerializedPropertyValue,
    TypedPropertyValue,
)

__all__ = [
    "Lnk",
    "PropertyStorage",
    "PropertyStore",
    "PropertyType",
    "PropertyValue",
    "SerializedPropertyStorage",
    "SerializedPropertyStore",
    "SerializedPropertyValue",
    "TypedPropertyValue",
    "c_lnk",
]
