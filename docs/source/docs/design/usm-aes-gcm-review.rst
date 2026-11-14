USM AES-GCM Design Review
=========================

Status: review draft, no default change
Scope: PySNMP USM (securityModel 3), SNMPv3 ``authPriv``
Prototype: ``tests/proto/secmod/test_usm_gcm_prototype.py``

Executive summary
-----------------

Adding an AES-GCM class to ``PRIV_SERVICES`` is necessary but not
sufficient. The current privacy interface receives only the localized
key, ``(snmpEngineBoots, snmpEngineTime, msgPrivacyParameters)`` and the
BER-encoded scopedPDU. It cannot see the authoritative engine ID, user
name, ``msgID``, ``msgFlags``, security level or context, so it cannot
put those fields into GCM AAD. USM authentication (HMAC over the whole
message) still covers them in the stock call chain; a GCM tag in
``msgPrivacyParameters`` does not.

A private privacy service can therefore be shipped as an explicitly
non-interoperable, PySNMP-to-PySNMP profile. It must not reuse
``usmAesCfb128Protocol`` or any other ``snmpPrivProtocols`` OID, and it
must not be described as compatible with third-party AES-GCM agents.
Full GCM binding of engine identity, user and message header requires a
security model change, not a privacy plugin.

This review recommends, for the current cycle:

1. Do not change defaults.
2. If GCM is pursued, implement it as a **private USM extension** under
   the PySNMP enterprise arc, advertised as such and disabled by
   default.
3. Keep the existing HMAC security level. Do not claim that GCM replaces
   USM authentication; describe it as adding ciphertext integrity on top
   of HMAC.
4. Defer a standalone security model until there is a standards-track
   profile to target and a wire-compatibility test peer.

Current USM message layout and order
------------------------------------

The on-wire SNMPv3 message is defined in
:py:mod:`pysnmp.proto.mpmod.rfc3412`:

.. code-block:: text

   SNMPv3Message ::= SEQUENCE {
       msgVersion             INTEGER,          -- 3
       msgGlobalData          HeaderData,
       msgSecurityParameters  OCTET STRING,     -- BER of UsmSecurityParameters
       msgData                ScopedPduData }   -- plaintext | encryptedPDU

   HeaderData ::= SEQUENCE {
       msgID           INTEGER,
       msgMaxSize      INTEGER,
       msgFlags        OCTET STRING (SIZE(1)),   -- authFlag|privFlag|reportableFlag
       msgSecurityModel INTEGER }                -- 3 for USM

   UsmSecurityParameters ::= SEQUENCE {
       msgAuthoritativeEngineID     OCTET STRING,
       msgAuthoritativeEngineBoots  INTEGER (0..2147483647),
       msgAuthoritativeEngineTime   INTEGER (0..2147483647),
       msgUserName                  OCTET STRING (SIZE(0..32)),
       msgAuthenticationParameters  OCTET STRING,
       msgPrivacyParameters         OCTET STRING }

``msgFlags`` bit meanings are fixed by RFC 3412 §6.4: bit 0 auth,
bit 1 priv, bit 2 reportable. ``securityLevel`` is derived by the MP
model as 1 (noAuthNoPriv), 2 (authNoPriv) or 3 (authPriv); values with
both auth and priv clear are rejected.

Outgoing ``authPriv`` order in :py:meth:`SnmpUSMSecurityModel.generate_response_message`
(``service.py``, ``__generate_request_or_response_message``):

1. Resolve user and localized auth/priv keys from LCD or the
   security-state cache (``3.1.1``).
2. Apply security-level checks. ``authPriv`` requires both an auth and a
   privacy protocol (``3.1.2``, ``3.1.3``).
3. Serialize the scopedPDU (contextEngineID, contextName, PDU) to BER.
4. Call ``privHandler.encrypt_data(privKey, (boots, time, None), data)``.
   The plugin returns ``(encryptedPDU, msgPrivacyParameters)``
   (``3.1.4a``).
5. Write ``msgPrivacyParameters`` into field 5 of
   ``UsmSecurityParameters`` and the ciphertext into the
   ``encryptedPDU`` choice (``3.1.4a``).
6. Write engine ID, boots, time and user name into fields 0-3
   (``3.1.5``, ``3.1.7``). Boots/time come from the local LCD for a
   response/report, from the timeline for a request to a known peer, and
   are zero for discovery (``3.1.6``).
7. Write a zero digest of ``authHandler.digest_length`` into field 4,
   BER-encode ``msgSecurityParameters`` into the message, BER-encode the
   whole message, then let the auth handler replace the placeholder with
   the real HMAC (``3.1.8a``). For authNoPriv the zero-length fields and
   whole message are encoded directly (``3.1.8b``).

The resulting ``wholeMsg`` is what HMAC covers. HMAC therefore covers
``msgVersion``, ``msgGlobalData`` (including ``msgID``, ``msgMaxSize``,
``msgFlags`` and ``msgSecurityModel``), all six USM fields including
``msgPrivacyParameters``, and the ciphertext. That is why every outer
mutation in the prototype fails at HMAC before decryption.

Incoming ``authPriv`` order in :py:meth:`SnmpUSMSecurityModel.process_incoming_message`:

1. Decode ``msgSecurityParameters``; parse errors produce a Report
   candidate without a counter OID (``3.2.1``).
2. Cache ``msgUserName``; read engine ID and user name (``3.2.2``,
   ``3.2.4``).
3. Check security level against the user's configured protocols
   (``3.2.5``).
4. Verify HMAC over ``wholeMsg`` before any decryption (``3.2.6``).
   Failures increment ``usmStatsWrongDigests`` and return
   ``authenticationFailure``.
5. Update the peer timeline when HMAC succeeds (``3.2.6``).
6. For authoritative engines check boots/time against the local notion;
   for non-authoritative engines check against the timeline (``3.2.7``).
   A 150-second window is used in both directions.
7. Only then call ``privHandler.decrypt_data`` with the received
   ``msgPrivacyParameters`` and ciphertext (``3.2.8a``). Profile failures
   increment ``usmStatsDecryptionErrors`` and return
   ``decryptionError``.
8. Ber-decode the decrypted scopedPDU. A BER failure is also reported as
   ``decryptionError`` (``3.2.8a``).

Security-level and report behavior
----------------------------------

Relevant current behavior, confirmed by code and prototype:

* An authoritative engine rejects a message whose security level is
  lower than the user's configured capability. ``authNoPriv`` for a user
  configured with privacy is ``unsupportedSecurityLevel``; so is
  ``noAuthNoPriv`` (``service.py`` ``3.2.5``).
* ``notInTimeWindow`` is reported with ``securityLevel=2``
  (authNoPriv); the ``unknownEngineID`` discovery Report is generated at
  the received security level and the current code sends it with an
  empty user name.
* A Report generated because of ``authenticationFailure``,
  ``unknownSecurityName`` or ``decryptionError`` is downgraded to
  ``noAuthNoPriv`` in ``service.py`` ``3.1.2`` (the ``ctx`` branch sets
  ``securityLevel = 1`` and clears the auth/priv flags). RFC 3414
  §11.4 explicitly warns that unsecure Reports expose the receiver to
  denial-of-service risk; this is the existing trade-off, not something
  GCM introduces.
* The MP layer chooses the Report security level from
  ``statusInformation["securityLevel"]`` when present, otherwise
  ``noAuthNoPriv`` (``mpmod/rfc3412.py`` ``7.1.3d.1``).

What GCM would place where
--------------------------

For a private profile in the current plugin API, the only defensible
layout is:

.. code-block:: text

   msgPrivacyParameters = nonce (12 bytes) || tag (16 bytes)
   encryptedPDU         = AES-GCM ciphertext, same length as plaintext
   AAD                  = profile label || msgAuthoritativeEngineBoots
                          || msgAuthoritativeEngineTime

   Key: localized privKey, truncated / expanded to the GCM key size
        using the same auth-protocol hash as the other AES services.

The privacy plugin verifies the tag in ``decrypt_data``. USM has already
verified HMAC at step 4, so a GCM failure here is reported as
``decryptionError`` and increments ``usmStatsDecryptionErrors``. It is
*not* an authentication failure at the USM layer, even though GCM
provides its own integrity check.

Why the AAD is limited: ``encrypt_data`` and ``decrypt_data`` only
receive the localized key, a three-tuple of boots, time and privacy
parameters, and the data. There is no engine ID, user name, ``msgID``,
``msgFlags``, security level or context argument. Putting
``msgAuthoritativeEngineID`` or ``msgUserName`` into AAD would require
threading new parameters through ``generate_request_message``,
``generate_response_message`` and ``process_incoming_message``, which is
a security-model change.

What still covers engine identity, user and header in the recommended
profile:

* HMAC over ``wholeMsg`` covers engine ID, boots, time, user name,
  privacy parameters, ciphertext, ``msgID``, ``msgMaxSize``, flags and
  security model. That is the same coverage the current AES-CFB mode
  has.
* GCM adds a second, independent integrity check over the ciphertext,
  nonce and the boot/time AAD. It catches corruption that might
  otherwise be attributed only to HMAC, and it fails closed before BER
  decoding.
* Neither mechanism binds the **context** separately from the
  ciphertext: the context is inside the encrypted scopedPDU, so changing
  it changes the ciphertext and fails HMAC, and would also fail the GCM
  tag. In the current profile, context integrity is inherited from
  ciphertext integrity, not from explicit AAD. The prototype demonstrates
  both paths: a same-length splice of another context's encrypted
  scopedPDU is rejected by HMAC, and with a test-only fixed nonce a
  different context produces a different ciphertext whose old tag no
  longer verifies.

Offline prototype and failure sequence
--------------------------------------

The prototype at ``tests/proto/secmod/test_usm_gcm_prototype.py``
registers ``PrivateGcm`` under a private PySNMP arc,
``1.3.6.1.4.1.20408.3.1.1.1.1.9.1``. It is not under
``snmpPrivProtocols`` (``1.3.6.1.6.3.10.1.2``) and is not
``usmAesCfb128Protocol``. It uses the real USM security model and a real
SNMPv3 message, then mutates bytes while preserving lengths.

Failure matrix (actual observed outcomes):

.. list-table::
   :header-rows: 1

   * - Mutation
     - Layer that rejects
     - Error from the current stack
   * - Engine ID changed, user under new engine ID exists
     - USM HMAC, step 4
     - ``authenticationFailure``; ``usmStatsWrongDigests``
   * - Engine ID changed, no user under new engine ID
     - USM user lookup, step 2
     - ``unknownSecurityName``; before HMAC
   * - Encrypted scopedPDU spliced from a different context
     - USM HMAC, step 4
     - ``authenticationFailure``; GCM is never called
   * - Ciphertext changed at first, middle or last octet
     - USM HMAC, step 4
     - ``authenticationFailure``; GCM is never called
   * - Nonce / privacy parameters changed
     - USM HMAC, step 4
     - ``authenticationFailure``; GCM is never called
   * - Ciphertext changed, plugin called directly
     - GCM tag, ``decrypt_data``
     - ``decryptionError``; ``usmStatsDecryptionErrors``
   * - Nonce changed, plugin called directly
     - GCM tag, ``decrypt_data``
     - ``decryptionError``
   * - Tag changed, plugin called directly
     - GCM tag, ``decrypt_data``
     - ``decryptionError``
   * - Same nonce, different context, plugin called directly
     - GCM tag, ``decrypt_data``
     - ``decryptionError``; ciphertext differs
   * - Intact message replayed within the 150-second window
     - Nothing in USM or GCM
     - Accepted again; replay protection is not provided
   * - ``authPriv`` downgraded to ``authNoPriv``
     - USM security-level check, step 3
     - ``unsupportedSecurityLevel``
   * - ``authPriv`` downgraded to ``noAuthNoPriv``
     - USM security-level check, step 3
     - ``unsupportedSecurityLevel``
   * - Report for ``decryptionError``
     - USM generates Report at noAuthNoPriv
     - Empty auth/privacy parameters; flags ``0x04``

Two failures are worth calling out in review:

* Engine identity is checked by HMAC only after a matching user entry is
  found. If the engine ID points to an unknown user, the message fails
  earlier with ``unknownSecurityName``. The failure reason is therefore
  observable and differs depending on local LCD contents. That is
  existing USM behavior.
* Replaying a complete, intact message inside the time window succeeds.
  GCM does not add replay protection; the USM timeline is coarse (±150 s)
  and does not track message uniqueness. ``msgID`` is covered by HMAC
  but is not a replay cache key at the security-model layer.

Report, retransmission and downgrade constraints
------------------------------------------------

**Reports.** Reports are generated by the MP model from
``statusInformation`` and then passed through ``generate_response_message``.
If the Report is triggered by HMAC failure, unknown user or decryption
failure, USM forces ``noAuthNoPriv``. A GCM profile cannot change that
from inside a privacy plugin. If the product requirement is
"authenticated Reports even on decryption failures," that is a security
model change or a change to the `ctx` branch in
``service.py``, and it changes behavior for every existing privacy
protocol.

**Retransmission.** Retries are implemented in
``CommandGenerator.process_response_pdu``. On timeout or a retriable
Report, the original PDU and target parameters are reused and
``send_pdu`` rebuilds the message. For the private GCM profile, each
rebuild generates a fresh nonce and ciphertext, so retries are not
byte-identical. That is required for GCM nonce safety. It also means:

* A receiver cannot use ciphertext equality to detect a retransmission.
* A retry storm consumes nonce space; the plugin must use a robust
  random 96-bit nonce or a strictly increasing counter. The prototype
  uses ``secrets.token_bytes(12)`` by default; its ``nonce_factory``
  hook exists only so the context-integrity test can pin a nonce. That
  hook must not be used in production.
* The security-state cache popped on the first send is not reused for a
  response. Retries re-enter generation with the same cached request
  parameters, which is the right place to generate a new nonce.

**Downgrade.** A private GCM privacy protocol does not define a new
security level, so a peer that strips the privacy flag produces
``authNoPriv`` and is rejected by the authoritative engine if the user
row says privacy is mandatory. A peer that strips both flags produces
``noAuthNoPriv`` and is also rejected. This is stronger than the current
Report downgrade path: the data path is protected, but the Report path
can still be unauthenticated. If GCM is marketed as "prevents downgrade
attacks," that claim is too broad; it prevents data-plane downgrade
under the configured user row, not unauthenticated Report injection.

Compatibility boundary
----------------------

The private-extension profile is compatible only with itself. It may be
used when both ends are PySNMP or an explicitly updated peer that
implements the same private arc, key derivation, nonce layout and AAD
label. It is not compatible with:

* Any standards-track USM privacy protocol, including AES-CFB128
  (``usmAesCfb128Protocol``);
* Vendor AES-CFB192/256 implementations under Cisco or other enterprise
  arcs;
* Any agent that only implements ``snmpPrivProtocols`` OIDs;
* Any expectation that an existing device will accept a new private
  OID without configuration and code changes.

Because the private OID is outside ``snmpPrivProtocols``, it is not a
standards-track registration. It must be documented as such, and it
should be rejected by any conformance tooling that validates
``usmUserPrivProtocol`` against ``snmpPrivProtocols``. Nothing in this
review claims that the prototype is an Internet standard or that it has
been tested against a third-party AES-GCM implementation.

Two implementation options
--------------------------

Option A: controlled private USM extension (recommended for a prototype)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Change surface:

* Add ``PrivateGcm`` under ``pysnmp.proto.secmod.eso.priv`` (or a
  dedicated private module) and register it in ``PRIV_SERVICES``.
* Add a private MIB ``ObjectIdentity`` under the PySNMP arc. Do not
  modify ``SNMP-USER-BASED-SM-MIB`` or ``SNMP-USM-AES-MIB``.
* Add HLAPI aliases only if they are clearly marked private.
* Add docs and tests that state the wire format and the lack of
  third-party interoperability.

Cost: one privacy class, one MIB identity, one HLAPI constant, docs and
tests. The existing HMAC, security levels, Report logic, retransmission
and timeline remain unchanged.

Guarantees: ciphertext integrity and confidentiality under the existing
USM HMAC envelope. No new binding of engine identity, user or header
beyond what HMAC already gives. No authenticated Report on decryption
failure. No replay protection.

Option B: standalone enterprise security model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A real security model would need:

* A new ``SECURITY_MODEL_ID`` greater than 255, allocated as
  ``enterpriseID * 256 + model``. PySNMP's enterprise number is 20408,
  so values in ``20408 * 256 + n`` are available to this project, but
  they are not IANA registrations.
* Registration in ``SnmpEngine.security_models`` and
  ``SnmpEngine.message_processing_subsystems``, because the current
  ``HeaderData`` constrains ``msgSecurityModel`` to ``>= 3`` and the MP
  dispatcher selects by model.
* A new message format or a new ``msgSecurityParameters`` syntax. GCM
  needs a nonce and tag somewhere; a private security model can define
  its own layout and put the whole header into AAD.
* New LCD/MIB objects for users, protocols and keys, because the
  existing ``usmUserTable`` is keyed by USM semantics and
  ``usmUserPrivProtocol`` is validated against ``PRIV_SERVICES``.
* VACM integration: ``vacmSecurityToGroup`` and
  ``vacmAccessTable`` are keyed by ``securityModel`` and
  ``securityLevel``. A new model needs configuration and reporting
  support or it will be silent.
* New Report/error mapping, new counters, new discovery, new key
  localization rules and new tests.

Cost: substantially larger than a privacy class: new security model,
message processing model or security-parameters syntax, engine
registration, MIB, config API, HLAPI, docs and a lab peer. It is the only
way to bind engine identity, user, ``msgID``, flags and context directly
into GCM AAD and to define an authenticated Report policy.

Guarantees: exactly the properties the new profile defines, but only for
peers that implement it. It does not make existing devices
interoperable, and it must not be described as an IANA-registered
security model.

What a single privacy plugin cannot provide
-------------------------------------------

The following are not implementable inside ``encrypt_data`` /
``decrypt_data`` without changing their callers:

* AAD over engine ID, user name, ``msgID``, flags or security level.
* A new message layout or a place to put a tag outside
  ``msgPrivacyParameters``.
* An authenticated Report on HMAC or decryption failure.
* A security-level change, a new ``securityModel`` value or a new MP
  model.
* Replay suppression. The plugin sees no message identity and no
  cross-message state; the USM timeline is the only state, and it is
  coarse.
* Key agreement or a change to key localization semantics. The plugin
  receives an already-localized key and must use the existing
  auth-protocol hash for key expansion.
* A claim of third-party interoperability. A private OID is not a
  standards registration.

Decision requested
------------------

1. Confirm that GCM is a **private, non-interoperable profile** for this
   cycle and will not replace AES-CFB as the default.
2. Confirm whether the product requirement is "ciphertext integrity on
   top of HMAC" (Option A) or "GCM binds the full USM header" (Option B).
   Option B cannot be delivered by a privacy class.
3. Confirm the private OID arc and documentation wording before any MIB
   or HLAPI alias is added.
