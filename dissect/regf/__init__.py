from __future__ import annotations

from dissect.regf.exceptions import (
    Error,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.regf.mounted import (
    AliasConflict,
    GptVolumeIdentity,
    IdentityRecord,
    MbrVolumeIdentity,
    MountedDevicesAnalysis,
    MountedDevicesCorrelation,
    MountedDeviceValue,
    ReferenceHop,
    TextDeviceIdentity,
    analyze_mounted_devices,
    correlate_mounted_devices,
)
from dissect.regf.regf import RegistryHive

__all__ = [
    "AliasConflict",
    "Error",
    "GptVolumeIdentity",
    "IdentityRecord",
    "MbrVolumeIdentity",
    "MountedDeviceValue",
    "MountedDevicesAnalysis",
    "MountedDevicesCorrelation",
    "ReferenceHop",
    "RegistryHive",
    "RegistryKeyNotFoundError",
    "RegistryValueNotFoundError",
    "TextDeviceIdentity",
    "analyze_mounted_devices",
    "correlate_mounted_devices",
]
