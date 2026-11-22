=====================================================
s3transfer - An Amazon S3 Transfer Manager for Python
=====================================================

S3transfer is a Python library for managing Amazon S3 transfers.
This project is maintained and published by Amazon Web Services.

.. note::

  This project is not currently GA. If you are planning to use this code in
  production, make sure to lock to a minor version as interfaces may break
  from minor version to minor version. For a basic, stable interface of
  s3transfer, try the interfaces exposed in `boto3 <https://docs.aws.amazon.com/boto3/latest/guide/s3.html>`__

Bandwidth affiliations
-----------------------

``TransferConfig.max_bandwidth`` caps the aggregate upload/download rate for
a ``TransferManager``. A manager can additionally carve that host-wide cap
into per-tenant quotas with ``max_bandwidth_affiliations``. Pass the
``affiliation`` argument on ``upload``/``download`` to charge a request to one
of those quotas::

    config = TransferConfig(
        max_bandwidth=100 * 1024 * 1024,          # host cap, bytes/second
        max_bandwidth_affiliations={
            'team-a': 20 * 1024 * 1024,           # team-a cap
            'team-b': 50 * 1024 * 1024,           # team-b cap
            'team-c': None,                       # host cap only
        },
    )
    manager = TransferManager(client, config)
    manager.download(bucket, key, filename, affiliation='team-a')

Every read for an affiliated request is admitted only when both the host
bucket and the affiliation bucket admit it, and an admitted read is billed
exactly once to each. The host cap is therefore always enforced, while a
tenant that exhausts its own quota cannot stop another tenant from using the
capacity the host still has. ``manager.bandwidth_limiter.bytes_consumed`` and
``manager.bandwidth_limiter.get_affiliation_bytes_consumed(name)`` expose the
billed totals, and cancellation removes any queued reservation without billing
it.
