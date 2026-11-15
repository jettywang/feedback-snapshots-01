"""BEK (BitLocker External Key) candidate matching.

A recovery service may hold multiple BEK files and needs to know which BEK belongs to
which BitLocker protector. This module matches the startup keys in a BEK structure to
the VMK protectors of a volume, purely based on the structures on both sides: the
identifier of the external info datum in the BEK and the identifier of the VMK info
datum on the volume. File names and display labels are never used for matching.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from dissect.fve.bde.c_bde import FVE_DATUM_ROLE
from dissect.fve.bde.information import Dataset, ExternalInfoDatum, KeyDatum

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO
    from uuid import UUID

    from dissect.fve.bde.information import Datum, VmkInfoDatum


class BekStatus(enum.Enum):
    """Status of a BEK candidate."""

    #: The BEK identifier matches a VMK protector, the key has not been verified yet.
    MATCHED = "matched"
    #: The existing VMK/FVEK authentication and type validation succeeded.
    UNLOCKED = "unlocked"
    #: The identifier matched a VMK protector, but the key failed authentication.
    KEY_MISMATCH = "key_mismatch"
    #: No VMK protector with this identifier exists on the volume.
    NO_MATCH = "no_match"
    #: Duplicate external info, this identifier and key were already seen.
    DUPLICATE = "duplicate"
    #: Unsupported datum structure, no usable external key.
    UNSUPPORTED = "unsupported"


class BekCandidate:
    """A candidate match between a BEK startup key and a VMK protector of a volume.

    Keeps track of the BEK identifier, the volume identifier and the VMK protector
    that the candidate matched (and, once unlocked, was actually used).
    """

    def __init__(
        self,
        bek_identifier: UUID | None,
        volume_identifier: UUID,
        vmk: VmkInfoDatum | None = None,
        key: KeyDatum | None = None,
        status: BekStatus = BekStatus.NO_MATCH,
    ):
        self.bek_identifier = bek_identifier
        self.volume_identifier = volume_identifier
        self.vmk = vmk
        self.key = key
        self.status = status

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} bek_identifier={self.bek_identifier} "
            f"volume_identifier={self.volume_identifier} status={self.status.name}>"
        )


def read_bek(fh: BinaryIO) -> Iterator[tuple[Datum, KeyDatum | None]]:
    """Read the startup key datums from a BEK structure.

    Yields tuples of the startup key datum and its external key datum. The external
    key datum is ``None`` if the startup key datum has an unsupported structure.
    """
    dataset = Dataset(fh)
    for datum in dataset.find_datum(FVE_DATUM_ROLE.STARTUP_KEY, None):
        key = datum.external_key() if isinstance(datum, ExternalInfoDatum) else None
        yield datum, key
