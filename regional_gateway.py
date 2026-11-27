"""Regional aggregation gateway for partner-facing Prometheus scrapes.

Two views are served over one shared ``CollectorRegistry``:

* an internal view that passes series through untouched, and
* a public view that projects away the ``site`` label so partners only see
  per-region aggregates.

Projection can make distinct source series collide.  Collisions are resolved
per metric type:

* histograms with identical bucket boundaries are summed bucket-by-bucket;
* histograms whose bucket boundaries differ (e.g. a boundary only one site
  has enabled) are rejected as a group -- never silently merged;
* gauges (and unknown-typed metrics) only merge when an aggregation rule is
  declared for the metric name; otherwise the colliding group is rejected,
  even if every source reports the same value;
* counters are summed; any other type with a collision is rejected.

Every scrape of either view carries self-describing integrity metrics so a
consumer can verify it received a complete representation:

* ``regional_gateway_scrape_source_series`` -- sample lines read from the
  shared registry;
* ``regional_gateway_scrape_emitted_series`` -- sample lines in this body
  (excluding the integrity families themselves);
* ``regional_gateway_scrape_merged_series`` -- source lines absorbed by
  aggregation;
* ``regional_gateway_scrape_rejected_series{reason=...}`` -- source lines
  dropped because their projection group was rejected;
* ``regional_gateway_scrape_info{view,sha256}`` -- digest of the emitted
  series, for change detection across scrapes.

Invariant: source == emitted + merged + rejected.
"""

import hashlib
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from prometheus_client.exposition import make_wsgi_app
from prometheus_client.metrics_core import (
    GaugeMetricFamily,
    HistogramMetricFamily,
    Metric,
)
from prometheus_client.registry import CollectorRegistry
from prometheus_client.utils import floatToGoString

REASON_INCOMPATIBLE_BUCKETS = 'incompatible_bucket_boundaries'
REASON_UNDECLARED_GAUGE = 'undeclared_gauge_aggregation'
REASON_UNSUPPORTED_TYPE = 'unsupported_metric_type'

_GAUGE_RULES = ('sum', 'min', 'max', 'avg')


def _apply_rule(rule: str, values: List[float]) -> float:
    if rule == 'sum':
        return sum(values)
    if rule == 'min':
        return min(values)
    if rule == 'max':
        return max(values)
    if rule == 'avg':
        return sum(values) / len(values)
    raise ValueError('Unknown gauge aggregation rule: ' + rule)


def _project_labels(labels: Dict[str, str], drop_labels: Tuple[str, ...]) -> Dict[str, str]:
    return {k: v for k, v in labels.items() if k not in drop_labels}


def _label_key(labels: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
    return tuple(sorted(labels.items()))


class _RestrictedView:
    """Applies name[] filtering to a view, mirroring CollectorRegistry."""

    def __init__(self, view: 'RegionalGatewayView', names: Sequence[str]):
        self._view = view
        self._names = set(names)

    def collect(self) -> Iterable[Metric]:
        for metric in self._view.collect():
            restricted = metric._restricted_metric(self._names)
            if restricted:
                yield restricted


class RegionalGatewayView:
    """A collector presenting one view (internal or public) of a registry."""

    def __init__(self,
                 registry: CollectorRegistry,
                 view: str,
                 drop_labels: Tuple[str, ...] = (),
                 gauge_rules: Optional[Dict[str, str]] = None):
        self._registry = registry
        self._view = view
        self._drop_labels = tuple(drop_labels)
        self._gauge_rules = dict(gauge_rules or {})
        unknown = {
            name for name, rule in self._gauge_rules.items() if rule not in _GAUGE_RULES
        }
        if unknown:
            raise ValueError('Unknown gauge aggregation rules for: {}'.format(sorted(unknown)))

    def restricted_registry(self, names: Sequence[str]) -> '_RestrictedView':
        return _RestrictedView(self, names)

    def collect(self) -> Iterable[Metric]:
        emitted: List[Metric] = []
        source = 0
        merged = 0
        rejected: Counter = Counter()
        for metric in self._registry.collect():
            source += len(metric.samples)
            if not self._drop_labels or not any(
                    any(k in self._drop_labels for k in s.labels) for s in metric.samples):
                emitted.append(metric)
                continue
            out, m, r = self._project(metric)
            emitted.extend(out)
            merged += m
            rejected.update(r)
        emitted_count = sum(len(m.samples) for m in emitted)
        digest = self._digest(emitted)
        for metric in emitted:
            yield metric
        for metric in self._integrity_metrics(source, emitted_count, merged, rejected, digest):
            yield metric

    def _project(self, metric: Metric) -> Tuple[List[Metric], int, Counter]:
        if metric.type in ('histogram', 'gaugehistogram'):
            return self._project_histogram(metric)
        if metric.type in ('gauge', 'unknown'):
            return self._project_scalar(metric, gauge_like=True)
        if metric.type == 'counter':
            return self._project_scalar(metric, gauge_like=False)
        return self._project_other(metric)

    def _project_histogram(self, metric: Metric) -> Tuple[List[Metric], int, Counter]:
        # Reconstruct each source histogram from its bucket/count/sum samples.
        series: Dict[Tuple[Tuple[str, str], ...], dict] = {}
        order: List[Tuple[Tuple[str, str], ...]] = []
        extras: List[Sample] = []
        for s in metric.samples:
            if s.name == metric.name + '_bucket':
                key = _label_key({k: v for k, v in s.labels.items() if k != 'le'})
                entry = series.get(key)
                if entry is None:
                    entry = series[key] = {'labels': dict(s.labels), 'buckets': {}, 'count': None, 'sum': None, 'lines': 0}
                    entry['labels'].pop('le', None)
                    order.append(key)
                entry['buckets'][s.labels['le']] = s.value
                entry['lines'] += 1
            elif s.name == metric.name + '_count':
                key = _label_key(s.labels)
                entry = series.get(key)
                if entry is None:
                    entry = series[key] = {'labels': dict(s.labels), 'buckets': {}, 'count': None, 'sum': None, 'lines': 0}
                    order.append(key)
                entry['count'] = s.value
                entry['lines'] += 1
            elif s.name == metric.name + '_sum':
                key = _label_key(s.labels)
                entry = series.get(key)
                if entry is None:
                    entry = series[key] = {'labels': dict(s.labels), 'buckets': {}, 'count': None, 'sum': None, 'lines': 0}
                    order.append(key)
                entry['sum'] = s.value
                entry['lines'] += 1
            else:
                extras.append(s)

        groups: Dict[Tuple[Tuple[str, str], ...], List[dict]] = {}
        group_order: List[Tuple[Tuple[str, str], ...]] = []
        for key in order:
            entry = series[key]
            projected = _project_labels(entry['labels'], self._drop_labels)
            gkey = _label_key(projected)
            if gkey not in groups:
                groups[gkey] = []
                group_order.append(gkey)
            groups[gkey].append(entry)

        merged = 0
        rejected: Counter = Counter()
        out = Metric(metric.name, metric.documentation, metric.type, metric.unit)
        for gkey in group_order:
            members = groups[gkey]
            labels = dict(gkey)
            boundaries = [set(m['buckets']) for m in members]
            if any(b != boundaries[0] for b in boundaries[1:]):
                # A boundary only some sites enabled must not be silently merged.
                rejected[REASON_INCOMPATIBLE_BUCKETS] += sum(m['lines'] for m in members)
                continue
            source_lines = sum(m['lines'] for m in members)
            if len(members) == 1:
                member = members[0]
                for le, value in member['buckets'].items():
                    out.add_sample(metric.name + '_bucket', dict(labels, le=le), value)
                if member['count'] is not None:
                    out.add_sample(metric.name + '_count', labels, member['count'])
                if member['sum'] is not None:
                    out.add_sample(metric.name + '_sum', labels, member['sum'])
                continue
            les = sorted(boundaries[0], key=lambda le: float(le))
            for le in les:
                canonical = floatToGoString(float(le))
                value = sum(m['buckets'][le] for m in members)
                out.add_sample(metric.name + '_bucket', dict(labels, le=canonical), value)
            emitted_lines = len(les)
            if all(m['count'] is not None for m in members):
                out.add_sample(metric.name + '_count', labels, sum(m['count'] for m in members))
                emitted_lines += 1
            if all(m['sum'] is not None for m in members):
                out.add_sample(metric.name + '_sum', labels, sum(m['sum'] for m in members))
                emitted_lines += 1
            merged += source_lines - emitted_lines
        for s in extras:
            out.add_sample(s.name, _project_labels(s.labels, self._drop_labels), s.value, s.timestamp)
        return [out] if out.samples else [], merged, rejected

    def _project_scalar(self, metric: Metric, gauge_like: bool) -> Tuple[List[Metric], int, Counter]:
        groups: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], List[Sample]] = {}
        order: List[Tuple[str, Tuple[Tuple[str, str], ...]]] = []
        for s in metric.samples:
            key = (s.name, _label_key(_project_labels(s.labels, self._drop_labels)))
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(s)

        merged = 0
        rejected: Counter = Counter()
        out = Metric(metric.name, metric.documentation, metric.type, metric.unit)
        for name, label_key in order:
            members = groups[(name, label_key)]
            labels = dict(label_key)
            if len(members) == 1:
                s = members[0]
                out.add_sample(name, labels, s.value, s.timestamp, s.exemplar)
                continue
            if gauge_like:
                rule = self._gauge_rules.get(metric.name)
                if rule is None:
                    # No declared rule: values must not be silently merged,
                    # even when every source reports the same value.
                    rejected[REASON_UNDECLARED_GAUGE] += len(members)
                    continue
                value = _apply_rule(rule, [s.value for s in members])
            elif name.endswith('_created'):
                value = min(s.value for s in members)
            else:
                value = sum(s.value for s in members)
            out.add_sample(name, labels, value)
            merged += len(members) - 1
        return [out] if out.samples else [], merged, rejected

    def _project_other(self, metric: Metric) -> Tuple[List[Metric], int, Counter]:
        groups: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], List[Sample]] = {}
        order: List[Tuple[str, Tuple[Tuple[str, str], ...]]] = []
        for s in metric.samples:
            key = (s.name, _label_key(_project_labels(s.labels, self._drop_labels)))
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(s)

        rejected: Counter = Counter()
        out = Metric(metric.name, metric.documentation, metric.type, metric.unit)
        for name, label_key in order:
            members = groups[(name, label_key)]
            if len(members) == 1:
                s = members[0]
                out.add_sample(name, dict(label_key), s.value, s.timestamp, s.exemplar)
            else:
                rejected[REASON_UNSUPPORTED_TYPE] += len(members)
        return [out] if out.samples else [], 0, rejected

    def _digest(self, metrics: List[Metric]) -> str:
        lines = []
        for m in metrics:
            for s in m.samples:
                label = ','.join('{}={}'.format(k, v) for k, v in sorted(s.labels.items()))
                lines.append('{}{{{}}}={}'.format(s.name, label, floatToGoString(s.value)))
        lines.sort()
        return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()[:16]

    def _integrity_metrics(self, source: int, emitted: int, merged: int,
                           rejected: Counter, digest: str) -> List[Metric]:
        def counter_family(name: str, documentation: str, value: float) -> GaugeMetricFamily:
            family = GaugeMetricFamily(name, documentation, labels=['view'])
            family.add_metric([self._view], value)
            return family

        families = [
            counter_family('regional_gateway_scrape_source_series',
                           'Sample lines read from the shared registry in this scrape.', source),
            counter_family('regional_gateway_scrape_emitted_series',
                           'Sample lines emitted in this scrape, excluding integrity metrics.', emitted),
            counter_family('regional_gateway_scrape_merged_series',
                           'Source sample lines absorbed by aggregation in this scrape.', merged),
        ]
        rejected_family = GaugeMetricFamily(
            'regional_gateway_scrape_rejected_series',
            'Source sample lines rejected in this scrape, by reason.',
            labels=['view', 'reason'])
        for reason in sorted(rejected):
            rejected_family.add_metric([self._view, reason], rejected[reason])
        families.append(rejected_family)
        info = GaugeMetricFamily(
            'regional_gateway_scrape_info',
            'Digest of the emitted series, for scrape integrity verification.',
            labels=['view', 'sha256'])
        info.add_metric([self._view, digest], 1.0)
        families.append(info)
        return families


class SiteLatencyCollector:
    """In-memory source: per-site request latency with uniform buckets."""

    def collect(self) -> Iterable[Metric]:
        histogram = HistogramMetricFamily(
            'http_request_duration_seconds',
            'Per-site request latency.',
            labels=['region', 'site'])
        histogram.add_metric(['eu-west', 'site-a'],
                             buckets=[('0.1', 3.0), ('0.5', 7.0), ('+Inf', 9.0)], sum_value=2.4)
        histogram.add_metric(['eu-west', 'site-b'],
                             buckets=[('0.1', 1.0), ('0.5', 5.0), ('+Inf', 8.0)], sum_value=3.1)
        # A region with a single enabled site: passes through untouched.
        histogram.add_metric(['ap-south', 'site-c'],
                             buckets=[('0.1', 2.0), ('0.5', 4.0), ('+Inf', 4.0)], sum_value=1.0)
        return [histogram]


class SiteShapeCollector:
    """In-memory source: incompatible histograms and colliding gauges."""

    def collect(self) -> Iterable[Metric]:
        sizes = HistogramMetricFamily(
            'http_response_size_bytes',
            'Per-site response sizes.',
            labels=['region', 'site'])
        # site-a has a 256-byte boundary that site-b never enabled.
        sizes.add_metric(['eu-west', 'site-a'],
                         buckets=[('256', 1.0), ('1024', 4.0), ('+Inf', 6.0)], sum_value=3000.0)
        sizes.add_metric(['eu-west', 'site-b'],
                         buckets=[('1024', 2.0), ('+Inf', 5.0)], sum_value=4500.0)
        firmware = GaugeMetricFamily(
            'site_firmware_version',
            'Firmware build reported by each site.',
            labels=['region', 'site'])
        # Same value from different sources, no declared aggregation rule.
        firmware.add_metric(['eu-west', 'site-a'], 7.0)
        firmware.add_metric(['eu-west', 'site-b'], 7.0)
        power = GaugeMetricFamily(
            'site_power_draw_watts',
            'Per-site power draw.',
            labels=['region', 'site'])
        power.add_metric(['eu-west', 'site-a'], 120.0)
        power.add_metric(['eu-west', 'site-b'], 80.0)
        return [sizes, firmware, power]


DEFAULT_GAUGE_RULES = {'site_power_draw_watts': 'sum'}


def build_demo_registry() -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(SiteLatencyCollector())
    registry.register(SiteShapeCollector())
    return registry


def make_internal_app(registry: CollectorRegistry):
    """Internal scrape: full series, site identity preserved."""
    return make_wsgi_app(RegionalGatewayView(registry, view='internal'))


def make_public_app(registry: CollectorRegistry, gauge_rules: Optional[Dict[str, str]] = None):
    """Public scrape: site label projected away, collisions resolved or rejected."""
    return make_wsgi_app(RegionalGatewayView(
        registry, view='public', drop_labels=('site',),
        gauge_rules=DEFAULT_GAUGE_RULES if gauge_rules is None else gauge_rules))
