=====================
Certificate issuance
=====================

.. automodule:: paramiko.cert

.. note::
   Issuance is separate from authentication and authorisation. A certificate
   that parses correctly, or that loads successfully via
   `PKey.load_certificate <paramiko.pkey.PKey.load_certificate>`, has not been
   accepted for login by any server.

.. autoclass:: paramiko.cert.CertificatePolicy
   :members:
   :member-order: bysource

.. autoclass:: paramiko.cert.CertificateRequest
   :members:
   :member-order: bysource

.. autoclass:: paramiko.cert.CertificateAuthority
   :members:
   :member-order: bysource

.. autoclass:: paramiko.cert.SignedCertificate
   :members:
   :member-order: bysource

.. autoclass:: paramiko.cert.CertificateAudit
   :members:

.. autofunction:: paramiko.cert.issue_user_certificate
