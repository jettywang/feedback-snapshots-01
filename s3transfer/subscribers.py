# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import logging
from functools import lru_cache

from s3transfer.compat import accepts_kwargs
from s3transfer.exceptions import (
    CancelledError,
    InvalidSubscriberMethodError,
    RestrictedTransferError,
)

logger = logging.getLogger(__name__)

# The only TransferMeta fields that are safe to expose to a restricted
# subscriber. Everything else on the real TransferMeta (call_args, etag,
# user_context, ...) can carry tenant specific bucket names, keys, or request
# parameters and must never reach a restricted recipient.
_RESTRICTED_META_FIELDS = ('transfer_id', 'size')


class BaseSubscriber:
    """The base subscriber class

    It is recommended that all subscriber implementations subclass and then
    override the subscription methods (i.e. on_{subscribe_type}() methods).
    """

    VALID_SUBSCRIBER_TYPES = ['queued', 'progress', 'done']

    def __new__(cls, *args, **kwargs):
        cls._validate_subscriber_methods()
        return super().__new__(cls)

    @classmethod
    @lru_cache
    def _validate_subscriber_methods(cls):
        for subscriber_type in cls.VALID_SUBSCRIBER_TYPES:
            subscriber_method = getattr(cls, 'on_' + subscriber_type)
            if not callable(subscriber_method):
                raise InvalidSubscriberMethodError(
                    f'Subscriber method {subscriber_method} must be callable.'
                )

            if not accepts_kwargs(subscriber_method):
                raise InvalidSubscriberMethodError(
                    f'Subscriber method {subscriber_method} must accept keyword '
                    'arguments (**kwargs)'
                )

    def on_queued(self, future, **kwargs):
        """Callback to be invoked when transfer request gets queued

        This callback can be useful for:

            * Keeping track of how many transfers have been requested
            * Providing the expected transfer size through
              future.meta.provide_transfer_size() so a HeadObject would not
              need to be made for copies and downloads.

        :type future: s3transfer.futures.TransferFuture
        :param future: The TransferFuture representing the requested transfer.
        """
        pass

    def on_progress(self, future, bytes_transferred, **kwargs):
        """Callback to be invoked when progress is made on transfer

        This callback can be useful for:

            * Recording and displaying progress

        :type future: s3transfer.futures.TransferFuture
        :param future: The TransferFuture representing the requested transfer.

        :type bytes_transferred: int
        :param bytes_transferred: The number of bytes transferred for that
            invocation of the callback. Note that a negative amount can be
            provided, which usually indicates that an in-progress request
            needed to be retried and thus progress was rewound.
        """
        pass

    def on_done(self, future, **kwargs):
        """Callback to be invoked once a transfer is done

        This callback can be useful for:

            * Recording and displaying whether the transfer succeeded or
              failed using future.result()
            * Running some task after the transfer completed like changing
              the last modified time of a downloaded file.

        :type future: s3transfer.futures.TransferFuture
        :param future: The TransferFuture representing the requested transfer.
        """
        pass


class RestrictedTransferMeta:
    """A sanitized view of ``TransferMeta`` for restricted subscribers

    Only an explicit allow list of non sensitive fields is exposed. The
    original ``TransferMeta`` (which carries ``call_args`` with the bucket,
    key, extra request parameters, and file object) is never retained, so no
    tenant specific data is reachable through this object, including via its
    private attributes.
    """

    def __init__(self, transfer_meta, allowed_fields=_RESTRICTED_META_FIELDS):
        # Eagerly copy only the allow listed scalar values rather than keeping
        # a reference to the original meta so sensitive data cannot be reached
        # by introspecting private attributes.
        self._transfer_id = transfer_meta.transfer_id
        self._size = transfer_meta.size
        self._allowed_fields = tuple(allowed_fields)

    @property
    def transfer_id(self):
        """The unique id of the transfer used to correlate events"""
        return self._transfer_id

    @property
    def size(self):
        """The size of the transfer request if known"""
        return self._size

    @property
    def allowed_fields(self):
        """The names of the metadata fields exposed to restricted recipients"""
        return self._allowed_fields


class RestrictedTransferFuture:
    """A sanitized view of a ``TransferFuture`` for restricted subscribers

    It provides just enough information for a monitoring recipient to track
    progress and the final state of a transfer by its ``transfer_id`` without
    exposing the underlying request. In particular:

        * ``meta`` only exposes the allow listed
          :class:`RestrictedTransferMeta` fields and never the bucket, key, or
          request parameters.
        * ``result()`` never raises the original exception. Failures are
          reported as :class:`RestrictedTransferError` and cancellations as
          :class:`s3transfer.exceptions.CancelledError`, neither of which
          carries tenant specific details.

    The business process keeps using the original ``TransferFuture`` to obtain
    the full, unsanitized diagnostic information.
    """

    def __init__(self, transfer_future):
        self._coordinator = transfer_future._coordinator
        self._meta = RestrictedTransferMeta(transfer_future.meta)

    @property
    def meta(self):
        return self._meta

    @property
    def status(self):
        """The transfer coordinator's current status

        The supported values mirror the coordinator: ``not-started``,
        ``queued``, ``running``, ``cancelled``, ``failed``, and ``success``.
        """
        return self._coordinator.status

    def done(self):
        """Determines if the restricted transfer has completed"""
        return self._coordinator.done()

    def result(self):
        """Waits until completion and returns the sanitized outcome

        :returns: ``None`` when the transfer succeeded. The real result
            (which may carry response metadata) is withheld.

        :raises s3transfer.exceptions.CancelledError: if the transfer was
            cancelled.
        :raises RestrictedTransferError: if the transfer failed. The original
            exception details are withheld from this restricted view.
        """
        try:
            self._coordinator.result()
        except CancelledError:
            raise
        except Exception as exception:
            logger.debug(
                'Sanitizing failure for restricted subscriber of transfer %s.',
                self._meta.transfer_id,
                exc_info=exception,
            )
            raise RestrictedTransferError(
                f'Transfer {self._meta.transfer_id} failed.'
            )
        return None

    def cancel(self):
        """Restricted views cannot cancel the underlying transfer"""
        raise NotImplementedError(
            'A restricted transfer future cannot cancel the transfer.'
        )


class RestrictedSubscriber(BaseSubscriber):
    """A subscriber that only forwards an allow listed view of a transfer

    This is intended for recipients such as a shared monitoring pipeline that
    are authorized to observe progress and final status but not tenant
    specific request data. It wraps another subscriber and invokes its
    callbacks with a :class:`RestrictedTransferFuture` instead of the real
    ``TransferFuture``.

    Exceptions raised by the wrapped subscriber are caught and logged so a
    misbehaving monitoring recipient can never disrupt or alter the business
    transfer itself.
    """

    def __init__(self, subscriber):
        self._subscriber = subscriber

    def _restricted_future(self, future):
        if isinstance(future, RestrictedTransferFuture):
            return future
        return RestrictedTransferFuture(future)

    def _invoke(self, callback_name, **kwargs):
        future = kwargs.pop('future')
        callback = getattr(self._subscriber, callback_name, None)
        if not callable(callback):
            return
        restricted_future = self._restricted_future(future)
        try:
            callback(future=restricted_future, **kwargs)
        except Exception:
            logger.debug(
                'Exception raised in restricted subscriber callback %s '
                'for transfer %s.',
                callback_name,
                restricted_future.meta.transfer_id,
                exc_info=True,
            )

    def on_queued(self, future, **kwargs):
        self._invoke('on_queued', future=future, **kwargs)

    def on_progress(self, future, bytes_transferred, **kwargs):
        self._invoke(
            'on_progress',
            future=future,
            bytes_transferred=bytes_transferred,
            **kwargs,
        )

    def on_done(self, future, **kwargs):
        self._invoke('on_done', future=future, **kwargs)
