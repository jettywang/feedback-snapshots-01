# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Bandwidth limiting primitives shared by S3 uploads and downloads.

Metering model
--------------
A ``LeakyBucket`` admits a read only when the projected rate for that
bucket stays at or below its ``max_rate``.  Every admitted read is
recorded exactly once against the bucket, so ``LeakyBucket.bytes_consumed``
is the amount of payload actually billed to that bucket.

When affiliations are configured, a transfer that declares an
``affiliation`` is checked against two buckets for every read:

* the host bucket (``max_bandwidth``), shared by every affiliation, and
* the affiliation bucket (``max_bandwidth_affiliations[affiliation]``),
  shared only by transfers from that affiliation.

A read is admitted only when both buckets admit it.  Both buckets are
then charged the same bytes under the same lock, and neither is charged
when either one rejects the read.  This gives two useful invariants:

* every read that goes through an affiliation is billed exactly once to
  that affiliation and exactly once to the host, so
  ``host.bytes_consumed >= sum(affiliation.bytes_consumed)`` (equality
  holds when every read is affiliated), and
* a tenant that saturates its own bucket cannot stop another tenant
  from using capacity that the host bucket still has available.

A rejected read is queued in the bucket's ``ConsumptionScheduler`` and
the caller waits for the returned retry time; queued reads are not
billed.  Cancelling a transfer removes its queued reservation from both
buckets without charging them, so a cancelled request cannot hold
capacity that other requests could use.
"""

import threading
import time


class RequestExceededException(Exception):
    def __init__(self, requested_amt, retry_time):
        """Error when requested amount exceeds what is allowed

        The request that raised this error should be retried after waiting
        the time specified by ``retry_time``.

        :type requested_amt: int
        :param requested_amt: The originally requested byte amount

        :type retry_time: float
        :param retry_time: The length in time to wait to retry for the
            requested amount
        """
        self.requested_amt = requested_amt
        self.retry_time = retry_time
        msg = f'Request amount {requested_amt} exceeded the amount available. Retry in {retry_time}'
        super().__init__(msg)


class RequestToken:
    """A token to pass as an identifier when consuming from the LeakyBucket"""

    pass


class TimeUtils:
    def time(self):
        """Get the current time back

        :rtype: float
        :returns: The current time in seconds
        """
        return time.time()

    def sleep(self, value):
        """Sleep for a designated time

        :type value: float
        :param value: The time to sleep for in seconds
        """
        return time.sleep(value)


class BandwidthLimiter:
    def __init__(
        self,
        leaky_bucket,
        time_utils=None,
        affiliation_leaky_buckets=None,
    ):
        """Limits bandwidth for shared S3 transfers

        :type leaky_bucket: LeakyBucket
        :param leaky_bucket: The host leaky bucket. Every limited read,
            including reads made on behalf of an affiliation, is checked
            against this bucket so the host-wide limit is never exceeded.

        :type time_utils: TimeUtils
        :param time_utils: Time utility to use for interacting with time.

        :type affiliation_leaky_buckets: dict
        :param affiliation_leaky_buckets: A mapping of affiliation name to
            the ``LeakyBucket`` that is shared by every transfer belonging
            to that affiliation.
        """
        self._leaky_bucket = leaky_bucket
        self._time_utils = time_utils
        if time_utils is None:
            self._time_utils = TimeUtils()
        self._affiliation_leaky_buckets = dict(affiliation_leaky_buckets or {})

    @property
    def affiliations(self):
        """The names of the configured bandwidth affiliations"""
        return frozenset(self._affiliation_leaky_buckets)

    @property
    def bytes_consumed(self):
        """The number of bytes billed to the host bucket"""
        return self._leaky_bucket.bytes_consumed

    def get_affiliation_bytes_consumed(self, affiliation):
        """Get the number of bytes billed to an affiliation bucket

        :type affiliation: str
        :param affiliation: The affiliation to look up

        :rtype: int
        """
        if affiliation not in self._affiliation_leaky_buckets:
            raise ValueError(
                f'Unknown bandwidth affiliation {affiliation!r}. '
                f'Configured affiliations: '
                f'{sorted(self._affiliation_leaky_buckets)!r}'
            )
        return self._affiliation_leaky_buckets[affiliation].bytes_consumed

    def get_bandwith_limited_stream(
        self, fileobj, transfer_coordinator, enabled=True, affiliation=None
    ):
        """Wraps a fileobj in a bandwidth limited stream wrapper

        :type fileobj: file-like obj
        :param fileobj: The file-like obj to wrap

        :type transfer_coordinator: s3transfer.futures.TransferCoordinator
        param transfer_coordinator: The coordinator for the general transfer
            that the wrapped stream is a part of

        :type enabled: boolean
        :param enabled: Whether bandwidth limiting should be enabled to start

        :type affiliation: str
        :param affiliation: The affiliation whose quota should also be
            charged for reads on this stream. The host bucket is always
            charged as well. If not supplied, only the host bucket applies.
        """
        bucket = self._leaky_bucket
        if affiliation is not None:
            try:
                affiliation_bucket = self._affiliation_leaky_buckets[
                    affiliation
                ]
            except KeyError:
                raise ValueError(
                    f'Unknown bandwidth affiliation {affiliation!r}. '
                    f'Configured affiliations: '
                    f'{sorted(self._affiliation_leaky_buckets)!r}'
                )
            bucket = AffiliationBandwidthBucket(
                self._leaky_bucket,
                affiliation_bucket,
                affiliation,
                self._time_utils,
            )
        stream = BandwidthLimitedStream(
            fileobj, bucket, transfer_coordinator, self._time_utils
        )
        if not enabled:
            stream.disable_bandwidth_limiting()
        return stream


class BandwidthLimitedStream:
    def __init__(
        self,
        fileobj,
        leaky_bucket,
        transfer_coordinator,
        time_utils=None,
        bytes_threshold=256 * 1024,
    ):
        """Limits bandwidth for reads on a wrapped stream

        :type fileobj: file-like object
        :param fileobj: The file like object to wrap

        :type leaky_bucket: LeakyBucket
        :param leaky_bucket: The leaky bucket to use to throttle reads on
            the stream. This may also be an
            ``AffiliationBandwidthBucket``, which enforces both the host
            and affiliation quotas for each read.

        :type transfer_coordinator: s3transfer.futures.TransferCoordinator
        param transfer_coordinator: The coordinator for the general transfer
            that the wrapped stream is a part of

        :type time_utils: TimeUtils
        :param time_utils: The time utility to use for interacting with time
        """
        self._fileobj = fileobj
        self._leaky_bucket = leaky_bucket
        self._transfer_coordinator = transfer_coordinator
        self._time_utils = time_utils
        if time_utils is None:
            self._time_utils = TimeUtils()
        self._bandwidth_limiting_enabled = True
        self._request_token = RequestToken()
        self._bytes_seen = 0
        self._bytes_threshold = bytes_threshold

    def enable_bandwidth_limiting(self):
        """Enable bandwidth limiting on reads to the stream"""
        self._bandwidth_limiting_enabled = True

    def disable_bandwidth_limiting(self):
        """Disable bandwidth limiting on reads to the stream"""
        self._bandwidth_limiting_enabled = False

    def read(self, amount):
        """Read a specified amount

        Reads will only be throttled if bandwidth limiting is enabled. Only
        bytes actually returned by the underlying stream are billed, so a
        read that hits EOF or returns a short read does not over-count the
        transfer.
        """
        if not self._bandwidth_limiting_enabled:
            return self._fileobj.read(amount)

        data = self._fileobj.read(amount)
        # We do not want to be calling consume on every read as the read
        # amounts can be small causing the lock of the leaky bucket to
        # introduce noticeable overhead. So instead we keep track of
        # how many bytes we have seen and only call consume once we pass a
        # certain threshold.
        self._bytes_seen += len(data)
        if self._bytes_seen < self._bytes_threshold:
            return data

        self._consume_through_leaky_bucket()
        return data

    def _consume_through_leaky_bucket(self):
        # NOTE: If the read amount on the stream are high, it will result
        # in large bursty behavior as there is not an interface for partial
        # reads. However given the read's on this abstraction are at most 256KB
        # (via downloads), it reduces the burstiness to be small KB bursts at
        # worst.
        while True:
            if self._transfer_coordinator.exception:
                # Do not leave a queued reservation behind when a transfer
                # is cancelled or fails while it is waiting for capacity.
                # Otherwise the cancelled request would keep billing time
                # against the bucket queues of later requests.
                self._cancel_pending_consumption()
                raise self._transfer_coordinator.exception
            try:
                self._leaky_bucket.consume(
                    self._bytes_seen, self._request_token
                )
            except RequestExceededException as e:
                try:
                    self._time_utils.sleep(e.retry_time)
                except BaseException:
                    self._cancel_pending_consumption()
                    raise
            else:
                self._bytes_seen = 0
                return

    def _cancel_pending_consumption(self):
        self._leaky_bucket.cancel(self._request_token)

    def signal_transferring(self):
        """Signal that data being read is being transferred to S3"""
        self.enable_bandwidth_limiting()

    def signal_not_transferring(self):
        """Signal that data being read is not being transferred to S3"""
        self.disable_bandwidth_limiting()

    def seek(self, where, whence=0):
        self._fileobj.seek(where, whence)

    def tell(self):
        return self._fileobj.tell()

    def close(self):
        self.finalize()
        self._fileobj.close()

    def finalize(self):
        """Bill any bytes buffered below the threshold, without closing

        Reads smaller than ``bytes_threshold`` are batched so the leaky
        bucket lock is not taken for every tiny read. A stream that is never
        closed (for example a download response body) still needs those
        bytes billed once the transfer is done.
        """
        if not self._bytes_seen:
            return
        if self._transfer_coordinator.exception:
            # A cancelled transfer should not be billed for bytes that
            # were buffered but never sent, nor keep a reservation.
            self._cancel_pending_consumption()
            self._bytes_seen = 0
        elif self._bandwidth_limiting_enabled:
            # This handles the case where the file is small enough to
            # never trigger the threshold and thus is never subjugated to
            # the leaky bucket on read(). This specifically happens for
            # small uploads. So instead to account for those bytes, have
            # it go through the leaky bucket when the file gets closed.
            self._consume_through_leaky_bucket()

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.close()


class AffiliationBandwidthBucket:
    """A bucket that enforces a host quota and an affiliation quota together

    Reads are admitted only when both the host bucket and the affiliation
    bucket admit them, and an admitted read is billed exactly once to each
    bucket. A rejected read is queued in whichever bucket rejected it and
    is not billed to either bucket.
    """

    def __init__(
        self, host_bucket, affiliation_bucket, affiliation, time_utils=None
    ):
        """
        :type host_bucket: LeakyBucket
        :param host_bucket: The bucket shared by the whole host

        :type affiliation_bucket: LeakyBucket
        :param affiliation_bucket: The bucket shared by one affiliation

        :type affiliation: str
        :param affiliation: The name of the affiliation

        :type time_utils: TimeUtils
        :param time_utils: The clock used to evaluate both buckets. It
            should be the same clock the buckets were created with.
        """
        self._host_bucket = host_bucket
        self._affiliation_bucket = affiliation_bucket
        self._affiliation = affiliation
        self._time_utils = time_utils
        if time_utils is None:
            self._time_utils = host_bucket._time_utils
        self._lock = threading.Lock()

    def consume(self, amt, request_token):
        """Consume an amount from both the host and affiliation buckets

        Both buckets are evaluated under one lock so a request can never
        be billed to one bucket without being billed to the other. If
        either bucket rejects the read, no bucket is billed and any
        reservation that a bucket already holds for this token is kept so
        the request does not lose its place in the queue.

        :raises RequestExceededException: If either bucket rejects the read
        """
        with (
            self._lock,
            self._host_bucket._lock,
            self._affiliation_bucket._lock,
        ):
            time_now = self._time_utils.time()
            host_admitted, host_retry_time = (
                self._host_bucket._check_consumption(
                    amt, request_token, time_now
                )
            )
            affiliation_admitted, affiliation_retry_time = (
                self._affiliation_bucket._check_consumption(
                    amt, request_token, time_now
                )
            )
            if not (host_admitted and affiliation_admitted):
                retry_times = [
                    retry_time
                    for retry_time in (host_retry_time, affiliation_retry_time)
                    if retry_time is not None
                ]
                raise RequestExceededException(amt, max(retry_times))
            self._host_bucket._commit_consumption(amt, time_now, request_token)
            self._affiliation_bucket._commit_consumption(
                amt, time_now, request_token
            )
            return amt

    def is_scheduled(self, request_token):
        """Whether the token holds a queued reservation in either bucket"""
        with (
            self._lock,
            self._host_bucket._lock,
            self._affiliation_bucket._lock,
        ):
            return self._host_bucket._has_reservation(
                request_token
            ) or self._affiliation_bucket._has_reservation(request_token)

    def cancel(self, request_token):
        """Drop any queued reservation for the token in both buckets"""
        with (
            self._lock,
            self._host_bucket._lock,
            self._affiliation_bucket._lock,
        ):
            self._host_bucket._cancel_scheduled_consumption(request_token)
            self._affiliation_bucket._cancel_scheduled_consumption(
                request_token
            )


class LeakyBucket:
    def __init__(
        self,
        max_rate,
        time_utils=None,
        rate_tracker=None,
        consumption_scheduler=None,
    ):
        """A leaky bucket abstraction to limit bandwidth consumption

        :type rate: int
        :type rate: The maximum rate to allow. This rate is in terms of
            bytes per second.

        :type time_utils: TimeUtils
        :param time_utils: The time utility to use for interacting with time

        :type rate_tracker: BandwidthRateTracker
        :param rate_tracker: Tracks bandwidth consumption

        :type consumption_scheduler: ConsumptionScheduler
        :param consumption_scheduler: Schedules consumption retries when
            necessary
        """
        self._max_rate = float(max_rate)
        self._time_utils = time_utils
        if time_utils is None:
            self._time_utils = TimeUtils()
        self._lock = threading.Lock()
        self._rate_tracker = rate_tracker
        if rate_tracker is None:
            self._rate_tracker = BandwidthRateTracker()
        self._consumption_scheduler = consumption_scheduler
        if consumption_scheduler is None:
            self._consumption_scheduler = ConsumptionScheduler()
        self._bytes_consumed = 0

    @property
    def max_rate(self):
        """The maximum number of bytes per second this bucket allows"""
        return self._max_rate

    @property
    def bytes_consumed(self):
        """The total number of bytes this bucket has billed"""
        with self._lock:
            return self._bytes_consumed

    def consume(self, amt, request_token):
        """Consume an a requested amount

        :type amt: int
        :param amt: The amount of bytes to request to consume

        :type request_token: RequestToken
        :param request_token: The token associated to the consumption
            request that is used to identify the request. So if a
            RequestExceededException is raised the token should be used
            in subsequent retry consume() request.

        :raises RequestExceededException: If the consumption amount would
            exceed the maximum allocated bandwidth

        :rtype: int
        :returns: The amount consumed
        """
        with self._lock:
            time_now = self._time_utils.time()
            admitted, retry_time = self._check_consumption(
                amt, request_token, time_now
            )
            if not admitted:
                raise RequestExceededException(
                    requested_amt=amt, retry_time=retry_time
                )
            return self._commit_consumption(amt, time_now, request_token)

    def cancel(self, request_token):
        """Cancel any queued consumption for the provided token

        This is used when a transfer is cancelled while it is waiting for
        capacity. The queued reservation is removed without billing the
        bucket, so the capacity can be offered to other requests.

        :type request_token: RequestToken
        :param request_token: The token used in the queued consume() request
        """
        with self._lock:
            self._cancel_scheduled_consumption(request_token)

    def is_scheduled(self, request_token):
        """Whether the token currently holds a queued reservation

        :type request_token: RequestToken
        :param request_token: The token to inspect
        """
        with self._lock:
            return self._has_reservation(request_token)

    def _has_reservation(self, request_token):
        # Caller must already hold self._lock.
        return self._consumption_scheduler.is_scheduled(request_token)

    def _check_consumption(self, amt, request_token, time_now):
        """Decide whether amt can be admitted without billing the bucket

        A request that already holds a reservation is admitted once it is
        retried; the reservation is released later, but only if every
        bucket involved also admits the read. A new request is admitted if
        its projected rate stays within the bucket's maximum rate;
        otherwise it is queued and the retry time is returned.

        :rtype: tuple
        :returns: ``(admitted, retry_time)`` where ``retry_time`` is None
            when the request is admitted.
        """
        if self._consumption_scheduler.is_scheduled(request_token):
            return True, None
        if self._projected_to_exceed_max_rate(amt, time_now):
            retry_time = self._schedule_consumption(amt, request_token)
            return False, retry_time
        return True, None

    def _commit_consumption(self, amt, time_now, request_token):
        """Bill an admitted read, releasing any queued reservation"""
        if self._consumption_scheduler.is_scheduled(request_token):
            self._consumption_scheduler.process_scheduled_consumption(
                request_token
            )
        self._rate_tracker.record_consumption_rate(amt, time_now)
        self._bytes_consumed += amt
        return amt

    def _schedule_consumption(self, amt, request_token):
        allocated_time = amt / float(self._max_rate)
        return self._consumption_scheduler.schedule_consumption(
            amt, request_token, allocated_time
        )

    def _cancel_scheduled_consumption(self, request_token):
        if self._consumption_scheduler.is_scheduled(request_token):
            self._consumption_scheduler.process_scheduled_consumption(
                request_token
            )

    def _projected_to_exceed_max_rate(self, amt, time_now):
        projected_rate = self._rate_tracker.get_projected_rate(amt, time_now)
        return projected_rate > self._max_rate


class ConsumptionScheduler:
    def __init__(self):
        """Schedules when to consume a desired amount"""
        self._tokens_to_scheduled_consumption = {}
        self._total_wait = 0

    def is_scheduled(self, token):
        """Indicates if a consumption request has been scheduled

        :type token: RequestToken
        :param token: The token associated to the consumption
            request that is used to identify the request.
        """
        return token in self._tokens_to_scheduled_consumption

    def schedule_consumption(self, amt, token, time_to_consume):
        """Schedules a wait time to be able to consume an amount

        :type amt: int
        :param amt: The amount of bytes scheduled to be consumed

        :type token: RequestToken
        :param token: The token associated to the consumption
            request that is used to identify the request.

        :type time_to_consume: float
        :param time_to_consume: The desired time it should take for that
            specific request amount to be consumed in regardless of previously
            scheduled consumption requests

        :rtype: float
        :returns: The amount of time to wait for the specific request before
            actually consuming the specified amount.
        """
        self._total_wait += time_to_consume
        self._tokens_to_scheduled_consumption[token] = {
            'wait_duration': self._total_wait,
            'time_to_consume': time_to_consume,
        }
        return self._total_wait

    def process_scheduled_consumption(self, token):
        """Processes a scheduled consumption request that has completed

        :type token: RequestToken
        :param token: The token associated to the consumption
            request that is used to identify the request.
        """
        scheduled_retry = self._tokens_to_scheduled_consumption.pop(token)
        self._total_wait = max(
            self._total_wait - scheduled_retry['time_to_consume'], 0
        )


class BandwidthRateTracker:
    def __init__(self, alpha=0.8):
        """Tracks the rate of bandwidth consumption

        :type a: float
        :param a: The constant to use in calculating the exponentional moving
            average of the bandwidth rate. Specifically it is used in the
            following calculation:

            current_rate = alpha * new_rate + (1 - alpha) * current_rate

            This value of this constant should be between 0 and 1.
        """
        self._alpha = alpha
        self._last_time = None
        self._current_rate = None

    @property
    def current_rate(self):
        """The current transfer rate

        :rtype: float
        :returns: The current tracked transfer rate
        """
        if self._last_time is None:
            return 0.0
        return self._current_rate

    def get_projected_rate(self, amt, time_at_consumption):
        """Get the projected rate using a provided amount and time

        :type amt: int
        :param amt: The proposed amount to consume

        :type time_at_consumption: float
        :param time_at_consumption: The proposed time to consume at

        :rtype: float
        :returns: The consumption rate if that amt and time were consumed
        """
        if self._last_time is None:
            return 0.0
        return self._calculate_exponential_moving_average_rate(
            amt, time_at_consumption
        )

    def record_consumption_rate(self, amt, time_at_consumption):
        """Record the consumption rate based off amount and time point

        :type amt: int
        :param amt: The amount that got consumed

        :type time_at_consumption: float
        :param time_at_consumption: The time at which the amount was consumed
        """
        if self._last_time is None:
            self._last_time = time_at_consumption
            self._current_rate = 0.0
            return
        self._current_rate = self._calculate_exponential_moving_average_rate(
            amt, time_at_consumption
        )
        self._last_time = time_at_consumption

    def _calculate_rate(self, amt, time_at_consumption):
        time_delta = time_at_consumption - self._last_time
        if time_delta <= 0:
            # While it is really unlikely to see this in an actual transfer,
            # we do not want to be returning back a negative rate or try to
            # divide the amount by zero. So instead return back an infinite
            # rate as the time delta is infinitesimally small.
            return float('inf')
        return amt / (time_delta)

    def _calculate_exponential_moving_average_rate(
        self, amt, time_at_consumption
    ):
        new_rate = self._calculate_rate(amt, time_at_consumption)
        return self._alpha * new_rate + (1 - self._alpha) * self._current_rate
