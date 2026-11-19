# Offline NTLM MIC and channel-binding diagnostics

## Scope

This tool performs **offline, passive** analysis of captured NTLMSSP tokens.
It does not authenticate, relay, contact a server, recover passwords, or emit
attack payloads. Its only cryptographic operation is recomputing a MIC with a
defender-supplied exported session key, which is the same local check an NTLM
SSP performs when accepting a context.

The core problem it addresses is the false positive "a MIC field is present,
therefore the handshake has integrity protection". Presence of a field is a
wire fact; protection only exists once the value is actually verified against
the negotiated key material.

## The three-way distinction

Every context reports three independent answers for the MIC and for channel
binding.

- **presence** — `present`, `absent`, or `unknown`. Read only from observable
  bytes: the 16-byte MIC slot at offset 72 of a recent AUTHENTICATE, the
  client `MsvAvFlags` bit `0x2`, and the `MsvAvChannelBindings` AV pair
  (`0x000A`).
- **verifiability** — `verifiable` or `not_verifiable`. MIC verification needs
  all three legs of one conversation **and** the exported session key. Channel
  binding matching additionally needs the outer-channel binding hash (for
  example the TLS server end-point value). Missing material keeps the result
  non-verifiable; it is never converted into a pass or a fail.
- **verdict / match** — `pass`, `fail`, or `unknown` for the MIC; `match`,
  `mismatch`, or `unknown` for channel binding. Only an explicit recomputation
  or an SSP audit record can produce `pass`/`fail`.

## Where each fact comes from

- Negotiate flags (`NegotiateFlags`) are reported on every message. The
  AUTHENTICATE flags must echo the CHALLENGE flags; dropped or added flags are
  raised as anomalies, not silently accepted.
- CHALLENGE target info AV pairs are read from `TargetInfo`. The server
  `MsvAvFlags` bit `0x2` signals that a MIC is expected; `MsvAvTimestamp`
  supports EPA but does not by itself prove channel binding is enforced.
- AUTHENTICATE facts come from the NTLMv2 client challenge AV pairs and the
  MIC slot. An all-zero MIC slot means the slot is reserved but not populated.
- The SSP context is separate evidence. A capture cannot show whether the
  acceptor returned `GSS_S_COMPLETE`, `GSS_S_BAD_MIC`, or
  `GSS_S_BAD_BINDINGS`; the tool accepts an optional SSP audit sidecar and
  labels it as SSP-sourced rather than wire-derived.

## MIC computation

Per MS-NLMP, the MIC is `HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE ||
AUTHENTICATE)` with the 16 MIC bytes in the AUTHENTICATE zeroed during hashing.
The tool hashes the exact captured bytes, so re-serialisation cannot mask a
modification.

## Context grouping rules

- Tokens are grouped by the explicit `context_id` in the capture.
- User names and server challenges are never used to merge contexts. Two
  handshakes sharing a challenge produce a `reused_server_challenge` warning
  but stay separate.
- A capture annotation `origin_context` surfaces a deliberate splice as a
  `mixed_origin_context` anomaly. Lineage is only read from that explicit
  field, never inferred from payload similarity.
- A context missing any leg is marked incomplete; its MIC can be present but
  stays not-verifiable and the verdict remains `unknown`. A rear-only capture
  is therefore never reported as verified.

## Channel binding semantics

- `MsvAvChannelBindings` present means the client *claims* a binding. Without
  the outer-channel hash the match stays `unknown`.
- With the outer hash, equality is `match`; inequality is `mismatch`.
- A required outer binding with no client AV pair is a `mismatch`, matching the
  SSP `GSS_S_BAD_BINDINGS` behaviour when missing bindings are not allowed.
- MIC and channel binding are independent: the dataset includes a case where
  the MIC verifies but channel binding mismatches, to prevent collapsing the
  two into one result.

## Synthetic validation dataset

`generate` builds credential-free NTLMv2 handshakes. All accounts use
`example.invalid` names and random local passwords; nothing corresponds to a
real identity. The contexts are:

- `ctx_alpha`, `ctx_beta`: complete handshakes with MIC and matching channel
  binding, interleaved in one stream and deliberately sharing an 8-byte server
  challenge.
- `ctx_mic_flip`: one MIC byte corrupted; MIC verdict `fail`.
- `ctx_user_tamper`: a user-name byte changed after MIC generation; `fail`.
- `ctx_chal_tamper`: a CHALLENGE byte changed with the AUTHENTICATE held;
  `fail`.
- `ctx_cbt_tamper`: CBT hash corrupted and the MIC recomputed with an alternate
  key; MIC `pass` under that key, channel binding `mismatch`.
- `ctx_no_mic`: handshake without a MIC; presence `absent`, verdict `unknown`.
- `ctx_half`: only CHALLENGE and AUTHENTICATE captured; not verifiable, never a
  pass.
- `ctx_spliced`: three legs from two conversations; MIC recomputation `fail`
  plus a lineage anomaly.

## Usage

```sh
# Build the synthetic dataset under a directory.
python -m scapy.tools.ntlmmic.diagnose generate ./ntlmmic_data

# Offline analysis. Omitting the key / binding files preserves unknown states.
python -m scapy.tools.ntlmmic.diagnose analyze ./ntlmmic_data/capture.jsonl \
    --session-keys ./ntlmmic_data/session_keys.json \
    --outer-bindings ./ntlmmic_data/outer_bindings.json \
    --ssp-audit ./ntlmmic_data/ssp_audit.json
```
