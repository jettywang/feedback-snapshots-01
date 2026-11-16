from __future__ import annotations


class Error(Exception):
    pass


class BrokenIndexError(Error):
    pass


class BrokenMftError(Error):
    pass


class FilenameNotAvailableError(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class MftNotAvailableError(Error):
    pass


class MftUnreachableError(BrokenMftError):
    """Raised when an MFT record can not be reached from the currently confirmed ``$MFT`` runs.

    The fragmented ``$MFT`` is opened incrementally: the initial ``$MFT`` record only describes the first
    part of its own data, and every subsequent ``$ATTRIBUTE_LIST`` entry may only point at an MFT record that
    lies within the runs confirmed so far. This error records the bootstrap stage at which resolution failed,
    together with the range of the ``$MFT`` that was confirmed at that point, instead of silently reading
    zeroes from an as yet unmapped part of the volume.

    Args:
        message: Human readable description of the failure.
        stage: The bootstrap stage that failed (e.g. the index of the ``$ATTRIBUTE_LIST`` entry being resolved).
        segment: The MFT segment number that could not be reached, if known.
        confirmed_runs: The runlist that was confirmed at the time of the failure, in cluster units.
    """

    def __init__(
        self,
        message: str,
        stage: str | int | None = None,
        segment: int | None = None,
        confirmed_runs: list[tuple[int | None, int]] | None = None,
    ):
        super().__init__(message)
        self.stage = stage
        self.segment = segment
        self.confirmed_runs = confirmed_runs or []

    @property
    def confirmed_clusters(self) -> int:
        """Return the number of ``$MFT`` clusters covered by the confirmed runs."""
        return sum(run_length for _, run_length in self.confirmed_runs)

    @property
    def confirmed_vcn_range(self) -> tuple[int, int]:
        """Return the inclusive VCN range covered by the confirmed runs."""
        return (0, self.confirmed_clusters - 1) if self.confirmed_clusters else (0, -1)


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAReparsePointError(Error):
    pass


class VolumeNotAvailableError(Error):
    pass
