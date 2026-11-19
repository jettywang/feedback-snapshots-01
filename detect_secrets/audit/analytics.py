"""
The analytics module produces a machine-readable breakdown of true and false positives
for a given audited baseline.
"""
from collections import defaultdict
from typing import Any
from typing import cast
from typing import Dict
from typing import List

from ..core import baseline
from ..core.plugins.util import get_mapping_from_secret_type_to_class
from ..core.potential_secret import PotentialSecret
from .common import get_baseline_from_file


def calculate_statistics_for_baseline(
    filename: str,
    **kwargs: Any,
) -> 'StatisticsAggregator':
    """
    :raises: InvalidBaselineError
    """
    secrets = get_baseline_from_file(filename)

    aggregator = StatisticsAggregator()
    for _, secret in secrets:
        # TODO: gather real secrets?
        # TODO: do we need repo_info?
        aggregator.record_secret(secret)
    aggregator.record_merge_status(_get_merge_status_from_file(filename))

    return aggregator


def _get_merge_status_from_file(filename: str) -> Dict[str, Any]:
    """
    Reads the merge metadata written by `audit --merge`.

    Older baselines (and baselines that were never merged) have no such
    metadata. Their statistics keep their original format, with no inferred
    signature status.
    """
    data = baseline.load_from_file(filename)
    return cast(Dict[str, Any], data.get('audit_merge') or {})


class StatisticsAggregator:
    def __init__(self) -> None:
        framework = {
            'stats': StatisticsCounter,
        }

        self.data: Dict[str, Any] = defaultdict(
            lambda: {
                key: value()
                for key, value in framework.items()
            },
        )
        self.conflicts: List[Dict[str, Any]] = []
        self.merge_metadata_present = False

    def record_merge_status(self, metadata: Dict[str, Any]) -> None:
        if not metadata:
            return

        self.merge_metadata_present = True
        self.conflicts = cast(List[Dict[str, Any]], metadata.get('conflicts') or [])

    @property
    def is_signed_off(self) -> bool:
        return not self.conflicts

    def record_secret(self, secret: PotentialSecret) -> None:
        # NOTE: We don't do anything with verified secrets, because this function
        # is solely to measure statistics on labelled results.
        counter = self._get_plugin_counter(secret.type)
        if secret.is_secret is True:
            counter.correct += 1
        elif secret.is_secret is False:
            counter.incorrect += 1
        else:
            counter.unknown += 1

    def _get_plugin_counter(self, secret_type: str) -> 'StatisticsCounter':
        return cast(StatisticsCounter, self.data[secret_type]['stats'])

    def __str__(self) -> str:
        output = ''

        if not self.is_signed_off:
            output += self._unsigned_warning() + '\n\n'

        for secret_type, framework in self.data.items():
            output += f'Plugin: {get_mapping_from_secret_type_to_class()[secret_type].__name__}\n'
            for value in framework.values():
                output += f'Statistics: {value}\n\n'

        return output

    def json(self) -> Dict[str, Any]:
        output = {}
        for secret_type, framework in self.data.items():
            output[get_mapping_from_secret_type_to_class()[secret_type].__name__] = {
                key: value.json()
                for key, value in framework.items()
            }

        # Only merged baselines carry a signature status. For those, always
        # emit it explicitly, so consumers never have to infer it from a
        # missing key.
        if self.merge_metadata_present:
            output['signed_off'] = self.is_signed_off
            output['conflicts'] = self.conflicts
        return output

    def _unsigned_warning(self) -> str:
        return (
            'WARNING: This baseline is NOT SIGNED OFF. '
            f'{len(self.conflicts)} unresolved conflict(s) from the merge require a third '
            'reviewer. The statistics below exclude those unresolved conclusions.'
        )


class StatisticsCounter:
    def __init__(self) -> None:
        self.correct: int = 0
        self.incorrect: int = 0
        self.unknown: int = 0

    def __str__(self) -> str:
        return (
            f'True Positives: {self.correct}, False Positives: {self.incorrect}, '
            f'Unknown: {self.unknown}, Precision: {self.calculate_precision()}, '
            f'Recall: {self.calculate_recall()}'
        )

    def json(self) -> Dict[str, Any]:
        return {
            'raw': {
                'true-positives': self.correct,
                'false-positives': self.incorrect,
                'unknown': self.unknown,
            },
            'score': {
                'precision': self.calculate_precision(),
                'recall': self.calculate_recall(),
            },
        }

    def calculate_precision(self) -> float:
        precision = (
            round(float(self.correct) / (self.correct + self.incorrect), 4)
            if (self.correct and self.incorrect)
            else 0.0
        )

        return precision

    def calculate_recall(self) -> float:
        # NOTE(2020-11-08|domanchi): This isn't the formal definition of `recall`, however,
        # this is the definition that we're going to attribute to it.
        #
        # Rationale: If we follow the formal definition of `recall` (i.e. TP / (TP + FN)),
        # we would need some way to measure false negatives. However, this is impossible
        # since we don't know what we don't know. The only way to get proper "recall" is
        # to measure this against a known set of secrets, and see how effective our rules
        # are against them.
        #
        # This is a common problem with Machine Learning. One way to address this is by
        # splitting the labelled data you have into a "test set" and a "training set",
        # train your model on the test set, and test it's performance on its counterpart.
        # This works great for RegexBasedDetectors, but not so much for more heuristic
        # scanners (e.g. entropy scanning, or keyword scanning). The primary reason is
        # that no labelled data that we can compile will be a representative sample of
        # the different types of secrets out there. And as such, we'd be overfitting it
        # to whatever sample set we attempt this with.
        #
        # There is however, an alternative method. If we know these ratios for a certain
        # configuration, then change the configuration to be more liberal, we would expect
        # our *precision* to decrease, and our *recall* to increase (i.e. catching more
        # false positives, in hopes to reduce false negatives). Then, we can work to
        # **increase** our precision with this same data set, which is a much more
        # measurable way to do this than "decreasing false negatives".
        #
        # Essentially, if we make our scans more liberal (catching more things), but
        # our precision stays the same, we would be catching more real secrets. This
        # definition of `recall` allows us to do this.
        recall = (
            round(float(self.correct) / (self.correct + self.unknown), 4)
            if (self.correct + self.unknown)
            else 0.0
        )

        return recall
